# Connect a real tenant

This runs Cloud Locksmith Core locally against your own Microsoft 365 tenant. Start with
a test or developer tenant.

**What has been verified.** On 2026-11-12 this flow was run against a licensed developer
tenant with the predecessor of this codebase (the same scan, scoring and simulation code,
before the open-source clean-up). It covered the Preview sign-in and scan, a full
connect, and the Settings fix simulation, with no fix executed. This exported codebase
has not yet been run against a real tenant. The known issues at the end were found in
that run.

## 1. Register an app in Entra

1. In the Entra admin centre, go to **App registrations → New registration**.
2. Set *Supported account types* to **Accounts in any organizational directory**
   (multi-tenant).
3. Set the *Redirect URI* (Web) to `http://localhost:8000/api/v1/auth/microsoft/callback`.
4. Under **Certificates & secrets**, create a client secret and copy its **Value**.
5. You do not need to pre-add API permissions. The sign-in requests the scopes in
   `permissions.md`, and the admin consents to them on the consent screen.

## 2. Configure the backend

```
cd backend
cp .env.example .env
```

Fill in `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `SESSION_SECRET`,
`APP_JWT_SECRET` and `ENCRYPTION_KEY`; `.env.example` shows how to generate each value.
Keep these two lines as they are:

```
ENABLE_SCHEDULER=false
ENABLE_AUTO_REMEDIATION=false
```

The scheduler defaults to on in the code. With both off, nothing runs in the
background; scans still run when you sign in.

## 3. Start the backend

```
docker compose up --build
```

This uses `backend/docker-compose.yml` (API, Postgres and Redis, on 127.0.0.1 only). The
entrypoint waits for Postgres, runs `alembic upgrade head`, then starts the API. Check
that http://localhost:8000/docs opens.

## 4. Start the dashboard

```
cd dashboard
cp .env.example .env.local
npm ci
npm run dev
```

Open http://localhost:3000.

## 5. Read-only first: Preview sign-in

1. Go to http://localhost:3000/preview-login and sign in with a **Global Administrator**
   of the tenant, then accept the consent screen. Preview requests read-only scopes, gives
   READ_ONLY access, and does not store the token.
2. The scan runs during the sign-in callback, so the page can take 1–3 minutes. Don't
   refresh it. You then land on the dashboard with a posture score and findings.

## 6. Full connect

Sign in from http://localhost:3000/login. This stores the delegated token (encrypted)
and makes your account the tenant **owner**, bound to your Entra object ID (`oid`).

## 7. Preview a fix (no changes)

* **Risk Feed → Simulate Fix:** offered only when `CA_MFA_ALL_USERS` or `CA_MFA_ADMINS`
  is failing. If your tenant already enforces MFA through Conditional Access, it won't
  appear.
* **Settings → Simulation → Simulate Fix:** simulates `CA_MFA_ALL_USERS` against your
  directory. This needs the full connect (step 6); it does not work after Preview only
  (see known issues).

Simulation is a calculation and changes nothing. Executing a fix changes the tenant: see
`remediation-lifecycle.md` before you approve or execute anything.

## Owner binding

Once a tenant has an owner, a Preview or full-connect sign-in by a different Microsoft
account is refused (403). Today the dashboard then shows the plain login page with no
message (see known issues). To start over on a local install, drop the database volume
(`docker compose down -v` in `backend/`), which deletes all local data.

## Known issues (seen in the 2026-11-12 run)

* `IDENTITY_STALE_SERVICE_PRINCIPAL` findings fail to save
  (`unsupported resource_type for finding: SERVICE_PRINCIPAL`).
* `IDENTITY_PERMANENT_ROLE_ASSIGNMENT`: Graph rejects the role-assignment filter
  (`Multiple roleDefinitionId in filter not supported`).
* After a Preview sign-in only, `/api/v1/users` returns 500 (no stored token), so the
  Settings simulation is unavailable until a full connect.
* The owner-binding 403 lands on a bare `/login` page without an explanation.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `AADSTS50011` redirect URI mismatch | The redirect URI in Entra must equal `MICROSOFT_REDIRECT_URI` exactly. |
| `AADSTS7000215` invalid client secret | Create a new secret and copy its **Value**, not its ID. |
| `AADSTS65001` consent required | Sign in as a Global Administrator. |
| `port is already allocated` | Something else uses 8000, 5432 or 6379; stop it. |
| Dashboard loads but API calls fail | Check the backend terminal and that http://localhost:8000/docs opens. |
