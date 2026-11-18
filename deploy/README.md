# Install on your own tenant (one machine, one Microsoft 365 tenant)

This runs Cloud Locksmith Core on `localhost` against a single Microsoft 365 tenant. A
setup script registers the Entra app for you and writes the configuration; you do not
copy any secret by hand. Read [`docs/trust.md`](../docs/trust.md) first: a full connect
requests write scopes.

For several tenants (an MSP), or to register the app yourself, use the manual path in
[`docs/connect-a-real-tenant.md`](../docs/connect-a-real-tenant.md).

## Requirements

* Docker with Compose 2.24 or later (`docker compose version`).
* A work account that is allowed to register applications in the tenant. It should be a
  member account (not a guest). Personal Microsoft accounts are refused.
* A Global Administrator for the first full connect, because that sign-in asks for admin
  consent. Setup itself grants no consent and assigns no roles.
* Chrome, Edge or Firefox. Sign-in cookies are `Secure`; these browsers accept them on
  `http://localhost`, Safari may not.

## Install

Stop the demo first if it is running (`docker compose down` at the repository root):
the demo and this install both use ports 3000 and 8000.

```
cd deploy
docker compose run --rm setup
docker compose up -d
```

`setup` prints a device code and a URL; sign in there with a work account. Before it
creates anything it prints the tenant it signed in to (name, default domain and tenant
ID); check it is the tenant you mean to scan. If your account is in more than one tenant,
choose one with `--tenant`, which takes a tenant ID or a domain:

```
docker compose run --rm setup --tenant contoso.onmicrosoft.com
```

A tenant ID given with `--tenant` must match the tenant you sign in to. Setup then:

* creates a single-tenant app registration named **Cloud Locksmith (local)** with one
  redirect URI, `http://localhost:8000/api/v1/auth/microsoft/callback`, and a client
  secret that expires after 24 months;
* writes `deploy/cloud-locksmith.env` and `deploy/cloud-locksmith-db.env` (the second
  holds only the Postgres and Redis passwords). Both are gitignored. Setup never prints a
  secret.

It refuses to run if an app named **Cloud Locksmith (local)** already exists in the
tenant, and it never replaces an existing config. Run it again on a finished install and
it prints the tenant ID, client ID and secret expiry instead. If the config file is
incomplete, it says which keys are missing and changes nothing (exit code 2).

The config sets `ENVIRONMENT=production` and `LOCAL_LOOPBACK_ONLY=true`, so the API
accepts only `http://localhost` or `http://127.0.0.1` URLs and does not redirect to
HTTPS. It sets `MICROSOFT_TENANT` to your tenant ID, so sign-in is limited to that
tenant, and it leaves the scheduler and auto-remediation off. Use `localhost` in the
browser; `http://[::1]` is not accepted.

Until the `0.2.0` images are published, `docker compose up -d` builds the images from
source. The first build takes several minutes. Every published port binds `127.0.0.1`;
Postgres and Redis are on an internal network only.

## First sign-in

1. Open http://localhost:3000/preview-login and sign in with a Global Administrator of the
   tenant. Preview is read-only: it requests no write scopes and does not store the
   token. The scan runs during sign-in, so the page can take a minute or more.
2. Then sign in from http://localhost:3000/login for the full connect. This stores the
   delegated token (encrypted) and makes that account the tenant owner. It asks for the
   scopes in [`docs/permissions.md`](../docs/permissions.md), including write scopes.

Executing a fix changes the tenant: read
[`docs/remediation-lifecycle.md`](../docs/remediation-lifecycle.md) first.

## Using it on a VM

The ports are bound to the VM's loopback address only. From your own machine:

```
ssh -L 3000:localhost:3000 -L 8000:localhost:8000 <vm>
```

Then open http://localhost:3000 on your own machine.

## Upgrade

```
git pull
cd deploy
docker compose pull
docker compose up -d
```

Database migrations run when the API starts. Until `0.2.0` images are published, use
`docker compose up -d --build` to rebuild from the updated checkout.

## Rotate the client secret

```
cd deploy
docker compose run --rm setup --rotate-secret
docker compose up -d --force-recreate
```

Rotation signs in again (it must be the same tenant; `--tenant` works here too), adds a new 24-month secret, saves
it, then deletes the old one. Restart afterwards so the API reads the new secret; the
second command is the one the script prints. The app-secret-expiry finding for this app
names the rotate command.

## Back up

```
cd deploy
docker compose exec -T postgres pg_dump -U cloudlocksmith -Fc -f /tmp/cl.dump cloudlocksmith
docker compose cp postgres:/tmp/cl.dump <a path outside the repository>
```

The dump contains your tenant data and the encrypted delegated tokens; the key that
decrypts them is in `cloud-locksmith.env`. Store the dump safely, outside the repository,
and keep both private.

To restore a dump into the running database:

```
docker compose cp <dump file> postgres:/tmp/cl.dump
docker compose exec -T postgres pg_restore -U cloudlocksmith -d cloudlocksmith --clean --if-exists /tmp/cl.dump
```

A dump restored to another install needs the same `cloud-locksmith.env`, or its tokens
cannot be decrypted.

## Troubleshooting

* **`env file ... cloud-locksmith.env not found`** (or `cloud-locksmith-db.env`): setup
  has not run yet. Run `docker compose run --rm setup` in `deploy/`.
* **Setup cannot write its files on an SELinux host (Fedora, RHEL)**: the setup container
  is not allowed to write to the bind-mounted `deploy/` directory. Create
  `deploy/compose.override.yml` locally (do not commit it) with the `:z` option, which
  relabels `deploy/` for container access, then run setup again:

  ```
  services:
    setup:
      volumes:
        - ./:/out:z
  ```

* **Ports bound to `127.0.0.1` reachable from the local network (Linux)**: on Docker
  Engine before 28.0, hosts on the same network segment could reach ports published on
  a loopback address ([moby/moby#45610](https://github.com/moby/moby/issues/45610), fixed
  in 28.0.0). Use Docker Engine 28 or later (`docker version`), or block the ports with a
  host firewall.

## Uninstall

```
cd deploy
docker compose --profile setup down -v
```

`--profile setup` also removes the network created by the setup run; `-v` deletes the
database volume and all local data. Then delete `deploy/cloud-locksmith.env` and
`deploy/cloud-locksmith-db.env`, and delete the app registration **Cloud Locksmith
(local)** in the Entra admin centre (App registrations). To stop without deleting data,
run `docker compose --profile setup down` without `-v`.
