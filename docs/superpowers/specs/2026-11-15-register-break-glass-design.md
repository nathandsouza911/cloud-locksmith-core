# Register an existing break-glass account (ROADMAP 2.7)

Approved by the owner 2026-11-15.

## Why
Conditional Access fixes are refused unless the tenant has a registered break-glass
account (pre-flight `BreakGlassPresenceCheck`). Today a row only appears when the
product creates the account itself, or by hand-written SQL (live-run gap G1). Admins
who already have emergency accounts need a supported way to register them.

## Goals
- Owner-only API to list, register and remove break-glass accounts for the current tenant.
- Registration verifies with Graph: the user exists, `accountEnabled` is true,
  `userType` is Member, and the user is a current Global Administrator (same check
  as the pre-flight). Synced (on-premises) accounts are accepted with a warning.
- Every register/remove is written to the hash-chained audit log.
- One account can be registered only once per tenant (DB unique constraint).
- Settings screen card: list, add (object ID or UPN), remove. Read-only for non-owners.

## Non-goals
- Creating accounts (the existing remediation executor does that).
- Changing CA policies when an account is removed; existing policies keep their exclusions.
- New Graph scopes.

## Anti-goals
- Trusting a client-supplied tenant. The tenant always comes from the session.
- Registering an account that cannot provide emergency access.

## Approaches
1. **Dedicated owner-only API + Settings card (chosen).** Small, explicit, auditable.
2. Reuse the remediation workflow (approve/execute). Rejected: registration changes no
   tenant state, and the workflow's finding/attempt machinery does not fit.
3. Document the SQL workaround only. Rejected: not usable by non-developers, unaudited.

## Design
- `GET/POST /api/v1/break-glass/accounts`, `DELETE /api/v1/break-glass/accounts/{id}`.
  Dependency: tenant from `get_explicit_current_tenant`; role must be `OWNER`
  (`request.state.user_tenant_role`), fail closed otherwise (403).
- POST body `{ "user": "<object id or UPN>" }`. Graph `GET /users/{user}?$select=id,
  userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled`, then
  Global Administrator membership via `fetch_directory_roles` + `fetch_role_members`.
  Stored value is the Graph object ID. Errors: 404 not found, 400 with a code for
  disabled / guest / not GA, 409 already registered.
- Audit actions `BREAK_GLASS_REGISTERED`, `BREAK_GLASS_REMOVED`.
- Alembic migration: unique (tenant_id, user_external_id); revision id <= 32 chars.
- Dashboard: card on Settings using existing UI components.

## Tests
Unit + PG integration: owner-only (ADMIN, READ_ONLY rejected), each Graph refusal,
duplicate, audit rows, cross-tenant (tenant A cannot list/delete tenant B's rows; a GA
of tenant B is checked against tenant A's Graph and refused). Dashboard card tests.

## Left to the builder
Exact UI copy and layout; error code names.
