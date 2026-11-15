# Register an Existing Break-Glass Account Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a tenant owner list, register (after Graph verification) and remove break-glass accounts, audited, from the API and the Settings screen.

**Architecture:** A small service (`break_glass_registration.py`) holds verification and DB logic; a thin router in `app/api/v1/break_glass_accounts.py` adds the owner gate and maps service errors to HTTP. Dashboard gets a `BreakGlassAccountsCard` on Settings.

**Tech Stack:** FastAPI, sync SQLAlchemy, Alembic, Microsoft Graph via `graph_get`; Next.js 14 + Jest.

**Spec:** `docs/superpowers/specs/2026-11-15-register-break-glass-design.md`

## Global Constraints
- Tenant comes only from `get_explicit_current_tenant`; every query filters `tenant_id == current_tenant.id`.
- Owner gate: `request.state.user_tenant_role == "OWNER"`, anything else 403 (fail closed).
- Alembic revision id <= 32 chars.
- No new Graph scope (uses `/users/{id}`, `/directoryRoles`, role members — already used by pre-flight).
- Audit actions `BREAK_GLASS_REGISTERED`, `BREAK_GLASS_REMOVED` via `app.services.audit.audit_logger.log_audit_event`.
- Tests run on PG: `docker start cl-oss-test-pg`, `source dummy_env.sh`, `export DATABASE_URL=postgresql://cl:cl@127.0.0.1:55435/cl_test`.

## Review Focus
- UPN with different case or surrounding whitespace → trimmed; stored value is the Graph object id, so duplicates by UPN vs id are still caught (Task 1 test `test_upn_and_object_id_are_the_same_account`).
- Graph 404 for the user → 404 `USER_NOT_FOUND`, not 500 (Task 1).
- Graph failure other than 404 → 502 `GRAPH_UNAVAILABLE`, nothing stored (Task 1).
- Deleting an id that belongs to another tenant → 404, the row survives (Task 2 cross-tenant test).
- Empty / over-long input → 422 before Graph is called (Task 2).

---

### Task 1: Registration service + unique constraint

**Files:**
- Create: `backend/app/services/break_glass_registration.py`
- Create: `backend/alembic/versions/20261115_bg_unique.py` (revision `20261115_break_glass_unique`, down `20261112_drop_terms_flag`; unique `uq_break_glass_tenant_user` on (tenant_id, user_external_id), dedupe existing rows first keeping min id)
- Modify: `backend/app/db/models/break_glass_account.py` (add `UniqueConstraint`)
- Test: `backend/tests/integration/test_break_glass_registration.py`

**Interfaces — Produces:**
- `class BreakGlassRegistrationError(Exception)` with `.code: str`, `.status_code: int`, `.message: str`
- codes: `USER_NOT_FOUND` 404, `ACCOUNT_DISABLED` 400, `GUEST_ACCOUNT` 400, `NOT_GLOBAL_ADMIN` 400, `ALREADY_REGISTERED` 409, `GRAPH_UNAVAILABLE` 502, `NOT_FOUND` 404
- `list_registered(db, tenant) -> list[dict]` (id, user_external_id, created_at)
- `async register_existing(db, tenant, user_ref: str, actor: str) -> dict` returns `{id, user_external_id, user_principal_name, display_name, warnings: list[str]}`; warning `"synced_from_on_premises"` when `onPremisesSyncEnabled` is true.
- `remove_registered(db, tenant, account_id: int, actor: str) -> None`

- [ ] Step 1: tests (Graph patched at `break_glass_registration.graph_get`, `fetch_directory_roles`, `fetch_role_members`):
  `test_registers_active_global_admin_and_audits` (row stored with Graph id, one AuditLog action `BREAK_GLASS_REGISTERED`),
  `test_refuses_disabled` / `test_refuses_guest` / `test_refuses_non_global_admin` (code, no row, no audit success row),
  `test_user_not_found_maps_404`, `test_graph_error_maps_502`,
  `test_duplicate_is_409`, `test_upn_and_object_id_are_the_same_account`,
  `test_synced_account_registers_with_warning`,
  `test_remove_deletes_and_audits`, `test_remove_other_tenants_row_is_not_found`,
  `test_global_admin_of_other_tenant_is_checked_against_this_tenant` (Graph called with tenant A; role members from A don't include the id → NOT_GLOBAL_ADMIN).
- [ ] Step 2: run, expect import failure.
- [ ] Step 3: implement service + model constraint + migration; `IntegrityError` on insert → rollback, `ALREADY_REGISTERED`.
- [ ] Step 4: run tests + `alembic upgrade head` on test DB; pass.
- [ ] Step 5: commit.

### Task 2: Owner-only API

**Files:**
- Modify: `backend/app/api/v1/break_glass_events.py` → add routes on the same router (`/accounts`)
- Test: `backend/tests/integration/test_break_glass_accounts_api.py`

**Interfaces — Consumes:** Task 1. **Produces:** `GET /api/v1/break-glass/accounts`, `POST` body `{"user": str}` (1–256 chars, stripped), `DELETE /api/v1/break-glass/accounts/{id}` → 204. Errors as `{"code","message"}` in `detail`.

- [ ] Step 1: tests via TestClient with dependency overrides: ADMIN and READ_ONLY get 403 on POST/DELETE; GET allowed for any tenant member (so non-owners can see the read-only list); POST maps service errors; cross-tenant: tenant A session cannot list or delete tenant B's row; empty `user` → 422.
- [ ] Step 2–4: fail, implement `require_owner(request)` next to `require_write_access` in `current_user.py`, pass.
- [ ] Step 5: commit.

### Task 3: Settings card

**Files:**
- Create: `dashboard/components/settings/BreakGlassAccountsCard.tsx`
- Modify: `dashboard/lib/api/endpoints.ts` (`getBreakGlassAccounts`, `registerBreakGlassAccount(user)`, `removeBreakGlassAccount(id)`), types file, `dashboard/app/(app)/settings/page.tsx`
- Test: `dashboard/components/settings/__tests__/BreakGlassAccountsCard.test.tsx`

- [ ] Step 1: tests: lists accounts; owner can add (calls register, shows warning text for synced accounts, shows server message on error); owner can remove after confirm; non-owner sees list with no add/remove controls; empty state explains CA fixes are blocked until one is registered.
- [ ] Step 2–4: fail, implement (owner flag from existing session/me data), pass; lint, tsc, prettier.
- [ ] Step 5: commit.

### Task 4: Docs + full verification
- Update `docs/connect-a-real-tenant.md` (replace G1 SQL workaround with the Settings card), README known issues, CHANGELOG Unreleased, notes LIVE_REMEDIATION_SCRIPT G1 status.
- Run full backend suite on PG, dashboard jest/lint/tsc, ruff. Commit. Push branch and open PR only with owner OK.
