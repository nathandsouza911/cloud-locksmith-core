# Connect a real tenant

This runs Cloud Locksmith Core locally against your own Microsoft 365 tenant. Start with
a test or developer tenant.

**What has been verified.** On 2026-11-13 this codebase (with the fixes listed under
*Unreleased* in `CHANGELOG.md`) was run against a licensed developer tenant with the
owner present:

* Full connect and the sign-in scan.
* One Conditional Access fix, *Block legacy authentication*, applied as a **report-only**
  policy: approved, executed, verified as report-only, rolled back, and applied and rolled
  back again. The tenant ended with the same Conditional Access policies it started with.
* Refusals that change nothing: a fix with no registered break-glass account, an expired
  approval (older than 48 h), a rollback without a Microsoft sign-in in the last 24 h,
  and two simultaneous executes of the same fix (one runs, the other is refused).
* A read-only check of stale service principals, service-account interactive login and
  the two risk-based Conditional Access controls.

Not run against a real tenant: any **enforced** Conditional Access fix, any fix other than
*Block legacy authentication*, and the fixes that change users, roles or app consents.
Earlier, on 2026-11-12, the predecessor of this codebase ran the Preview sign-in, scan and
fix simulation; the issues found then are fixed.

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

Both are off by default. With both off, nothing runs in the background; scans still run
when you sign in.

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
2. The scan runs during the sign-in callback, so the page can take a minute or more on a
   larger tenant (about 50 seconds for 14 users and 337 service principals). Don't refresh
   it. You then land on the dashboard with a posture score and findings.

## 6. Full connect

Sign in from http://localhost:3000/login. This stores the delegated token (encrypted)
and makes your account the tenant **owner**, bound to your Entra object ID (`oid`).

## 7. Preview a fix (no changes)

* **Risk Feed → Simulate Fix:** offered only when `CA_MFA_ALL_USERS` or `CA_MFA_ADMINS`
  is failing. If your tenant already enforces MFA through Conditional Access, it won't
  appear.
* **Settings → Simulation → Simulate Fix:** simulates `CA_MFA_ALL_USERS` against your
  directory. This needs the full connect (step 6); after a Preview sign-in only, it says
  that a full connect is required.

Simulation is a calculation and changes nothing. Executing a fix changes the tenant: see
`remediation-lifecycle.md` before you approve or execute anything.

## 8. Apply a Conditional Access fix (changes the tenant)

Before the first Conditional Access fix:

* **Security defaults must be off.** Entra does not allow Conditional Access policies
  while they are on, so every Conditional Access fix fails. Turn them back on afterwards
  if you rely on them.
* **Register at least one break-glass account.** The pre-flight check refuses any
  Conditional Access fix until the product knows at least one break-glass account, and
  every policy it creates excludes those accounts. See the known issue below for
  registering an account that already exists.

Then use **Risk Feed** (or **Security Controls**) → **Review & Fix**. This approves and
executes in one step, after the pre-flight checks. The policy is created in
**report-only** mode (the finding's default mode): it logs what it would block and enforces
nothing, so the finding stays open in the score. Roll it back from **Remediation History**.

## Owner binding

Once a tenant has an owner, a Preview or full-connect sign-in by a different Microsoft
account is refused, and the login page says the tenant is already connected to another
account. To start over on a local install, drop the database volume
(`docker compose down -v` in `backend/`), which deletes all local data.

## Known issues (seen in the 2026-11-13 run)

* **No way to register an existing break-glass account.** The pre-flight check reads the
  product's own list of break-glass accounts, and only the *create break-glass accounts*
  fix adds to it (by creating new accounts). For a local install you can add an existing
  account directly; use its Entra object ID and your tenant ID:

  ```
  docker compose exec postgres psql -U postgres -d cloudlocksmith -c \
    "insert into break_glass_accounts (tenant_id, user_external_id, created_at)
     values ('<tenant-id>', '<break-glass-object-id>', now());"
  ```

  The pre-flight check still confirms with Microsoft that the account is an active
  Global Administrator.
* **Enforcing a Conditional Access fix is not available in the dashboard.** Fixes run in
  the finding's mode, which defaults to report-only.
* **Stale service principals** use Microsoft's service-principal sign-in report, a beta
  Graph endpoint that lags by about a day: an app first used today can appear as never
  signed in until the report catches up.
* **Mail-forwarding rules** cannot be read for users without an Exchange Online licence;
  those users are skipped and logged, not reported.
* The "found something" paths of the service-account and risk-based Conditional Access
  controls were not seen on a real tenant (the test tenant had no such accounts or
  policies); they are covered by unit tests.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `AADSTS50011` redirect URI mismatch | The redirect URI in Entra must equal `MICROSOFT_REDIRECT_URI` exactly. |
| `AADSTS7000215` invalid client secret | Create a new secret and copy its **Value**, not its ID. |
| `AADSTS65001` consent required | Sign in as a Global Administrator. |
| `port is already allocated` | Something else uses 8000, 5432 or 6379; stop it. |
| Dashboard loads but API calls fail | Check the backend terminal and that http://localhost:8000/docs opens. |
