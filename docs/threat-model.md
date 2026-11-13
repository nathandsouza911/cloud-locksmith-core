# Threat model

Cloud Locksmith Core holds delegated admin tokens for Microsoft 365 tenants and can change
their security settings. The design assumes the client is hostile: every request can be
forged, and headers prove nothing on their own.

## Assets

* Delegated Microsoft tokens per tenant (`tenant_oauth`, encrypted with `ENCRYPTION_KEY`).
* App session JWTs (`APP_JWT_SECRET`).
* Findings, snapshots and audit logs per tenant (Postgres).
* The ability to change a tenant (fix and rollback endpoints, scheduler).

## Tenant isolation

| Threat | Control | Evidence |
|---|---|---|
| User A reads tenant B by sending `X-Tenant-ID: B` | `TenantContextMiddleware` requires a `UserTenantAccess` row for (user, tenant) on every non-public route; routes resolve the tenant again from the database. | `tests/integration/test_evidence_reports.py`, `test_report_retrieval.py`, `test_remediation_decisions_api.py` (cross-tenant cases) |
| User approves or downloads another tenant's object by ID | Queries filter by the resolved tenant as well as the ID. | `test_remediation_approval_api.py::test_cannot_approve_another_tenants_decision`, `test_report_retrieval.py` (403) |
| Unauthenticated request reaches a route that forgot its auth dependency | The middleware rejects any non-public route without a valid JWT (fail closed). | `test_evidence_reports.py::test_evidence_reports_requires_authentication` |
| Tenant resolver falls back to a session value | The session-based resolver was removed; the tenant guard fails closed. | `test_tenant_service_no_unsafe_resolver.py`, `test_tenant_guard_fails_closed.py` |

Public routes (exempt from the tenant middleware) are listed in `PUBLIC_ROUTES` in
`app/middleware/tenant_context.py`. `/api/v1/msp/fleet-overview` and
`/api/v1/realtime/stream` are exempt from tenant selection but still require a signed-in
user and are scoped to that user's tenants or organization.

## Sign-in (OAuth)

* The OAuth `state` is signed and checked on the callback.
* The tenant ID (`tid`) comes from the token, and the ID token is verified against
  Microsoft's keys for that tenant.
* The user is identified by `oid`, never by email or UPN.
* **Owner binding:** the first owner of a tenant must hold a tenant-admin role. A later
  Preview or SMB-connect sign-in to an already-owned tenant by a different `oid` is
  refused with 403. MSP connect has its own confirmation step.
* Preview sign-ins get READ_ONLY access, and their token is not stored.

Tests: `test_onboarding_admin_verification.py`, `test_auth_microsoft_msp_connect.py`,
`test_onboarding_callback_error_handling.py`.

## Tokens and sessions

* Delegated tokens are encrypted at rest (Fernet). A leaked database without
  `ENCRYPTION_KEY` does not expose them.
* The app cookie is HttpOnly, Secure and SameSite=None. State-changing requests must
  carry an allowed `Origin` (CSRF check).
* Logout revokes the JWT in a Redis denylist. In production, Redis must be reachable,
  otherwise token checks fail closed; outside production an in-memory fallback is used.
* Fix routes also require a Microsoft sign-in within the last 24 hours.

## Changing a tenant

See `remediation-lifecycle.md`: approval with a 48-hour expiry, typed confirmation in
the UI, preflight checks, protected break-glass accounts, a per-tenant lock, a cooldown,
verification after the change, and rollback from a stored snapshot. Automatic remediation
is off by default (`ENABLE_AUTO_REMEDIATION=false`).

## Demo mode

Demo mode must never become a way into a real tenant. Each of these is covered by
`backend/tests/test_demo_mode.py`:

* **Startup refusal.** The app refuses to start with `DEMO_MODE=true` if
  `ENVIRONMENT=production`, the Microsoft client ID or secret are not the demo
  placeholders, or the scheduler or auto-remediation is enabled.
* **No outbound HTTP.** In demo mode every outbound request through httpx or requests is
  refused. Graph reads for the demo tenant are answered from recorded fictional data,
  and anything else fails.
* **Reserved tenant, both ways.** The demo tenant ID is refused everywhere outside demo
  mode, including the OAuth callback. Demo mode refuses every other tenant.
* **Read-only.** Every write is refused except demo sign-in, sign-out and the fix
  simulation, and the Microsoft sign-in routes are disabled.
* **Demo sign-in.** The route exists only in demo mode and returns 404 otherwise. The
  identity comes from the server, and the normal JWT and tenant checks apply afterwards.
* **Public demo key.** The demo encryption key is public, so production refuses to start
  with it.

## Out of scope / known limits

* Hosting hardening (TLS termination, secrets storage, backups) is the operator's job.
* When enabled (`ENABLE_SCHEDULER=true`; off by default), the scheduler runs inside the
  API process; see `architecture.md`.
* Model and database differ in 21 places (the database is the stricter side, for
  example a unique owner index and a foreign key the models do not declare). Tests that
  use SQLite `create_all` therefore do not exercise those database constraints; the
  Postgres integration suite does.
