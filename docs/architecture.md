# Architecture

```
browser ──> dashboard (Next.js 14, :3000) ──HTTPS/JSON + cookie──> api (FastAPI, :8000)
                                                                    │
                                     ┌──────────────────────────────┼─────────────────────┐
                                     │                              │                     │
                              Postgres 15                      Redis 7            Microsoft Graph
                        (tenants, findings, audit,     (token denylist, rate      (delegated + app-only
                         snapshots, campaigns)          limits, lockout)            tokens; never in demo)
```

## Components

| Path | What it is |
|---|---|
| `backend/app/main.py` | FastAPI app, middleware, router registration, startup checks. |
| `backend/app/api/` | HTTP routes (`routes/` and `v1/`). |
| `backend/app/services/` | Scanning, scoring, remediation, rollback, verification, reports, MSP fleet. |
| `backend/app/services/remediation/control_registry.py` | The control catalogue: detector, executor, verifier, rollback per control (see `controls.md`). |
| `backend/app/jobs/`, `backend/app/scheduler.py` | Background jobs (scans, reports, campaigns, auto-remediation). |
| `backend/app/demo/` | Demo mode (recorded scan, guards). |
| `backend/alembic/` | Schema: one baseline (`20261110_baseline`) plus later revisions. |
| `dashboard/` | Next.js dashboard (App Router). |

## Request path

Middleware, outermost first (registration order in `main.py`):

1. CORS (origins from `CORS_ALLOWED_ORIGINS`, falling back to `FRONTEND_URL`).
2. Proxy headers (client IP only from `TRUSTED_PROXY_HOSTS`).
3. Rate limiting (Redis, in-memory fallback outside production).
4. Demo-mode guard (reserved demo tenant both ways; in demo mode, writes refused).
5. Tenant context: every non-public route needs a valid app JWT and an `X-Tenant-ID` the
   user has a `UserTenantAccess` row for; otherwise 401/400/403.
6. Then, in order: decoding of the auth cookie, the CSRF check (state-changing requests
   must carry an allowed `Origin`), and in production the HTTPS redirect and HSTS header.

Routes then resolve the tenant again server-side (`app/api/dependencies/current_user.py`);
the `X-Tenant-ID` header is only a selector, never trusted on its own.

## Identity

* Users sign in with Microsoft (OAuth authorization code). The Entra object ID (`oid`) is
  the identity; the tenant ID (`tid`) comes from the verified token.
* The app issues its own JWT in an HttpOnly, Secure, SameSite=None cookie
  (`clx_access_token`). Revoked tokens are kept in a Redis denylist.
* Delegated Microsoft tokens are stored encrypted (Fernet, `ENCRYPTION_KEY`) in
  `tenant_oauth`. Preview sign-ins do not store a token.

## Background work

`ENABLE_SCHEDULER` defaults to **true**: when the API starts it also runs the scheduler
loop (scheduled scans, reports, campaign jobs and the auto-remediation job). The
auto-remediation job does nothing unless `ENABLE_AUTO_REMEDIATION=true` (default false).
See `remediation-lifecycle.md`.

## Database

Fresh installs only: `alembic upgrade head` builds the schema from the baseline in one
step. The baseline was generated from a database migrated through the 77 revisions of the
earlier private codebase and verified to produce an identical schema. Upgrading a
database from that earlier codebase is not supported.
