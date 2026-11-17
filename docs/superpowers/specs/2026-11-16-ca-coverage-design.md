# Conditional Access coverage across all users (ROADMAP 3.1) — design

Status: approved by the owner 2026-11-16 (design note in the private notes, three decisions:
extend `app/simulation` incl. the empty-scope fix; recorded demo policies; server-built
Simulate Fix snapshot).

## Problem

1. There is no per-user view of Conditional Access (CA) coverage. Tenant-wide findings
   (`CA_MFA_ALL_USERS`, `CA_LEGACY_AUTH_BLOCK`) say *whether* a policy exists, not *who*
   is left out (exclusions by user, group, role; report-only policies; narrowing
   conditions).
2. `policy_evaluator._has_empty_include_scope` treats a policy with no included users,
   groups or roles as applying to **everyone**. In Graph such a policy applies to no one.
   Any coverage report built on it would hide gaps.
3. Simulate Fix trusts a `tenant_snapshot` sent by the browser. The dashboard sends users
   and roles only: no existing policies, `groups: {}`, roles keyed by display name (Graph
   `includeRoles` uses role template IDs), and a proposed policy that is not the policy
   Apply sends. For tenant-wide findings it sends empty include lists and only bug (2)
   turns that into "everyone".

## Decisions

### A. Evaluator (`app/simulation/policy_parser.py`, `policy_evaluator.py`)

Parser additions: `include_applications`, `exclude_applications`, `include_user_actions`,
`client_app_types`, `grant_operator`, `has_authentication_strength`,
`includes_guests` / `excludes_guests` (from `includeGuestsOrExternalUsers` /
`excludeGuestsOrExternalUsers` or the legacy `GuestsOrExternalUsers` value),
`narrowing_conditions` (names of conditions that limit when the policy applies:
locations other than All with no exclusions, platforms, sign-in/user/service-principal
risk, device filter, authentication flows, insider risk).

Evaluator rules (one shared include/exclude matcher used by both Simulate Fix and the
coverage report — no second evaluator):

- Empty include scope → applies to no one. `None` in `includeUsers` → no one.
- `All` in `includeUsers` → everyone. Users, groups (transitive members), roles (by role
  template ID) as today.
- Guests (conservative both ways): a guest-targeting *include* is not counted as covering
  anyone (guest type/tenant scoping is not modelled); a guest-targeting *exclude* excludes
  every user with `userType == "Guest"`.
- Exclusion wins over inclusion (unchanged).

`get_applicable_policies` keeps its signature for the engine; it now gets an optional
`guest_ids` set.

### B. Tenant reader (`app/simulation/tenant_reader.py`)

`read_tenant_identity(db, tenant, *, extra_group_ids=()) -> TenantIdentity` reads, for the
session tenant only, via `graph_get` / `graph_get_all` (all pages):

| Data | Path | Permission |
|---|---|---|
| CA policies | `/identity/conditionalAccess/policies` | Policy.Read.All |
| Security defaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | Policy.Read.All |
| Users | `/users?$select=id,displayName,userPrincipalName,accountEnabled,userType` | Directory.Read.All |
| Activated roles | `/directoryRoles` | Directory.Read.All |
| Role members | `/directoryRoles/{id}/members?$select=id` | Directory.Read.All |
| Group members | `/groups/{id}/transitiveMembers?$select=id` | Directory.Read.All |

No new permission. Groups read: every group a policy includes or excludes, plus groups
that hold a role. Users are filtered from member lists by `@odata.type`.

Fail closed: any Graph error raises; the report is never built from partial data. One
exception: a referenced group that returns 404 has been deleted and has no members — that
is a fact, not a read failure (tested).

Limits stated in the output: role assignments through PIM eligibility and administrative
unit scopes are not modelled; users who hold a role through a role-assignable group are
counted as holding it.

### C. Coverage (`app/simulation/coverage.py`)

Pure function `build_coverage(identity) -> dict`. Per user, three questions, each with a
status `covered | report_only | gap | not_applicable`, the covering policy names, and
reasons:

1. **MFA**: a policy that applies to the user, targets `All` applications with no
   excluded applications, no user actions, all client app types (`[]` or `["all"]`), no
   narrowing conditions, and *requires* MFA (`mfa` or an authentication strength, and not
   satisfiable by another control under `OR`).
2. **Legacy authentication**: a policy that applies to the user, targets `All`
   applications, `clientAppTypes` contains both `exchangeActiveSync` and `other`, and
   grants `block`. (Stricter than the CA-09 finding, which accepts either type; the report
   says which type is left open.)
3. **Admin protection** (only for users holding a role in
   `PRIVILEGED_ROLE_TEMPLATE_IDS`): question 1 for that user.

`report_only`: no enforced policy covers the user but a report-only one would.
Gap reasons name the policy and why: excluded (directly / by group *name* / by role *name*
/ as a guest), excludes some applications, applies only to some apps or user actions,
applies only under conditions (list), allows another control instead of MFA, only blocks
one legacy client type, or "no policy requires MFA / blocks legacy authentication".

Security defaults on → MFA and legacy authentication `covered` by "Security defaults" for
every user (CA policies cannot be enforced while security defaults are on).

Output always carries the disclaimer: "Models policy assignment; it is not Microsoft's
evaluation engine. Conditions other than users, applications, client app types and the
conditions listed are not evaluated." plus the limits from B.

### D. API (`app/api/v1/ca_coverage.py`)

`GET /api/v1/ca-coverage` — tenant from the session (`get_explicit_current_tenant`), any
role with access to the tenant, read-only. `?format=csv` returns a CSV download; cells
that start with `= + - @` (tab/CR too) are prefixed with `'` (display names are
tenant-controlled). Graph failure → 502 with the Graph category, no partial report.

### E. Simulate Fix (`POST /api/v1/simulations/run`)

Request becomes `{"control_id": "CA_MFA_ALL_USERS" | "CA_MFA_ADMINS"}`. The server:
reads the tenant with the reader (B); builds the proposed policy with the same builder
Apply uses (`ca_policy_engine.build_policy_document`, split out of `build_policy` without
its break-glass gate; `build_policy` keeps the gate and calls it), mode ENFORCED, the
control's default rollout phase, exclusions = the tenant's registered break-glass
accounts; runs the engine with the tenant's real policies, groups and roles. Old body keys
(`tenant_snapshot`, `role_mapping`, `proposed_change`) are rejected (400) so a stale client
cannot send data the server would ignore silently.

Response adds `newly_affected_users` (users whose access becomes stricter than the tenant
without the fix; under security defaults every user is already MFA_REQUIRED) and
`security_defaults_enabled` (the dashboard warns that CA policies are not enforced while
they are on). Added after the 2026-11-17 live run reported 12 of 14 users newly affected on
a security-defaults tenant. Admin counts use role template IDs.

Dashboard: Risk Feed and Settings send `{control_id}`; `lib/simulation.ts` snapshot
builder and the unused `PolicyEditor` (it never sent `control_id`, so the backend always
rejected it) are removed.

### F. Demo

Recorded fictional data, consistent with the seeded findings (`CA_MFA_ADMINS` pass,
`CA_MFA_ALL_USERS` and `CA_LEGACY_AUTH_BLOCK` fail):
- enabled "Require MFA for administrators" (Global Administrator, User Administrator
  roles; all apps);
- report-only "Require MFA for all users" (`All`, excludes group "CA exclusions");
- group "CA exclusions" with one fictional member;
- no legacy-authentication block; security defaults off; role members recorded.
Demo still never calls Microsoft; unknown paths still raise.

### G. Dashboard page

New page "CA Coverage" (own nav entry): summary counts per question, filter (gaps only /
all), per-user table (name, UPN, enabled, admin, three status cells with reasons on
expand), CSV export button, disclaimer and limits shown on the page.

## Security

- Tenant only from the session; reader takes the resolved `Tenant`; `graph_get` already
  validates the token's tenant. Cross-tenant test on both endpoints (403 for a tenant the
  user cannot access, Graph never called).
- No client-supplied identity data is trusted anymore (E).
- No writes, no new scopes, no audit events needed (read-only).
- CSV formula-injection guard.

## Tests (test-first)

Parser/evaluator: empty scope → no one; `None`; guests both ways; group/role exclusion;
narrowing conditions; OR-grant; auth strength. Coverage: each reason; report-only; security
defaults; admin question. Reader: paging, transitive groups, role-held-by-group, 404 group,
any other error raises, fail closed. API: auth, cross-tenant 403, CSV escaping, 502 on
Graph error. Simulation: server builds policy (same as Apply minus gate), existing
policies counted, `newly_affected_users`, old body rejected, cross-tenant. Demo: coverage
and Simulate Fix answer from recordings with the expected gaps.
