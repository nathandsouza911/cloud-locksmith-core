# Changelog

## Unreleased

* **Tenant-level Conditional Access checks now use the same rules as CA Coverage, so the
  two can no longer disagree.** The MFA (all users, admins), legacy authentication, device
  code flow, authentication transfer, high-risk sign-in and risk-based MFA checks passed
  on a policy that excluded some apps or applied only under conditions (locations,
  device platforms, risk levels, a device filter). They now require a policy that applies
  to every app with none excluded and to every sign-in, except for the condition the
  check is about (authentication flows for device code and transfer, sign-in risk for
  the two risk checks). The MFA checks also require all client app types and MFA as a
  required control, not one option among others. Legacy authentication now accepts a
  block on client app type `all`, which includes both legacy types. On the CA Coverage
  page, two policies that each block one legacy type now cover the user, as the check
  already allowed. User exclusions such as break-glass accounts are still allowed.
  Policies created by Apply still pass. Tenants that passed before may now fail: that
  failure is real.
* **CA Coverage** (new page under Clients, `GET /api/v1/ca-coverage`, CSV export): for
  every user, whether an enforced Conditional Access policy requires MFA on every
  sign-in, blocks legacy authentication (both `exchangeActiveSync` and `other`), and,
  for privileged-role holders, requires admin MFA. Each gap names the policy and the
  reason: excluded directly, by group or by role, as a guest; report-only; turned off;
  only some applications; only under conditions (locations, platforms, risk, device
  filter); another control allowed instead of MFA. It reads policies, users, transitive
  group members and role holders with the existing `Policy.Read.All` and
  `Directory.Read.All` permissions, stops with an error on any failed read rather than
  report from partial data, and lists what it does not evaluate. The demo shows it on
  recorded fictional policies.
* Fixed: a Conditional Access policy that includes no users, groups or roles was treated
  as covering everyone; in Microsoft Graph it covers no one.
* **Simulate Fix** is now computed on the server for the signed-in tenant. It took the
  tenant's users and roles from the browser, without the tenant's existing policies or
  group members, with roles matched by name rather than role template ID, and with a
  proposed policy that differed from the one Apply sends. The request is now
  `{"control_id": ...}` only (other fields are refused); the result adds
  `newly_affected_users` (users whose access the fix makes stricter; with security defaults
  on, every user already counts as required to use MFA) and `security_defaults_enabled`,
  with a warning that Conditional Access policies are not enforced while security
  defaults stay on.
* **Legacy authentication check (`CA_LEGACY_AUTH_BLOCK`) no longer passes falsely.** It
  passed when only one of the two legacy client types (Exchange ActiveSync, other clients)
  was blocked, when the blocking policy targeted only some users, and when a policy had no
  grant controls. Now both types must be blocked for all users and all cloud apps (by one
  policy or two); break-glass exclusions are allowed. The finding lists any type still
  unblocked. A tenant with security defaults enabled passes, since security defaults
  block legacy authentication (as the MFA checks already allowed). Tenants that passed before may now fail: that failure is real.
* **A policy with no grant controls is no longer counted as a block.** Graph returns no
  grant controls for policies that set only session controls, and those allow sign-in.
  This affected the device code flow, authentication transfer and high-risk sign-in
  checks as well. Policies created by Apply always send an explicit block and still pass.
* **The HTTP access log no longer records sign-in secrets.** uvicorn logged every request
  path with its query string, so each Microsoft sign-in callback wrote its authorization
  code, `state` and `session_state` to the log, in development and in the production
  image. Those values, and `id_token`, `access_token`, `refresh_token`, `client_secret`
  and `code_verifier`, are now replaced with `[REDACTED]`; other parameters are kept.
  Authorization codes are single-use and short-lived, but logs from earlier versions
  still contain them: delete or restrict those logs if others can read them.
* **Scans no longer copy directory data into the logs.** For every user without an admin
  role, the overprivileged-admin check logged the user's full Graph `/memberOf` response:
  group names and descriptions, mail and proxy addresses, and security identifiers. It
  now logs the user ID and how many objects of each type were returned. Logs from earlier
  versions still contain that data: delete or restrict them if others can read them.
* **A rolled-back fix no longer leaves its state on the finding.** Scans merge new
  evidence into the stored evidence so that an approval in progress survives a rescan,
  but rollback and approval expiry did not remove the fix's own fields. After a
  rollback the finding kept "report-only policy applied", the last failure label
  ("Execution failed") and the approved scope indefinitely. Rollback now removes the
  approval, failure and report-only fields; approval expiry removes the approved scope
  (and still records when it expired). Findings rolled back before this release keep
  the old fields until their next fix or rollback.

* **Per-user MFA findings no longer report uncovered users as covered.** "User without
  MFA" and "Admin without MFA" passed every user as soon as any enabled MFA policy
  included all users, even users that policy excluded (directly, by group or by role) and
  policies limited to some apps or conditions. Without such a policy, group and role
  exclusions were ignored, nested groups were not read, and a group that could not be
  read was treated as empty. Both findings now use the CA Coverage engine, so the scan
  and the page give the same answer, and each finding lists the reasons (for example
  "Excluded from 'MFA all' by group 'CA exclusions'"). If any read fails, the result is
  Unknown, never a pass. The break-glass check uses the same matcher, so an account
  excluded by group or role is no longer reported as covered by MFA, and a failed read
  records no break-glass result instead of stopping the tenant scan. Expect new failures
  on tenants with exclusions or app-limited policies: they are real.

* **Device code flow, authentication transfer, high-risk sign-in and risk-based MFA
  checks require a policy for all users.** A blocking (or MFA) policy that targeted only
  some users or groups passed the tenant-level check, leaving everyone else uncovered.
  Exclusions such as break-glass accounts are still allowed. Policies created by Apply
  include all users and still pass.

## 0.1.2 (2026-11-15)

* The API (`GET /` and the OpenAPI page) and the dashboard package now report the release
  version; they still said 0.1.0 in 0.1.1. A test keeps the README, the compose image
  tags, the dashboard package and the API version the same.
* **Delete Account** now removes every row of the tenant. It missed six tables: rows in
  assets, drift notifications, remediation actions or remediation verifications made the
  deletion fail, and campaign tasks and report payloads were left behind. A test now
  fails if a new tenant table is not handled. Only the deletion record (tenant ID, name,
  who deleted it) is kept.
* Register an existing break-glass account from **Settings** → **Break-glass accounts**
  (tenant owner only), instead of inserting a database row by hand. The account must be
  enabled, a member and a current Global Administrator of the connected tenant
  (checked with Microsoft Graph; no new permission). Owners can also remove accounts;
  both changes are written to the audit log, and they are refused if the audit record
  cannot be saved. API: `GET/POST /api/v1/break-glass/accounts`,
  `DELETE /api/v1/break-glass/accounts/{id}`.
* The hash-chained audit log failed on every write on a database built from the
  migrations: `audit_logs.created_at` had no default and the immutability trigger
  compared `json` values, which Postgres cannot do. Sign-in audit events were dropped,
  and user offboarding applied its changes in the tenant, then reported an error and
  kept no audit record. Migration `20261115_audit_log_fixes` repairs both; rows remain
  immutable, except that deleting a tenant (**Settings** → **Delete Account**) removes
  that tenant's audit rows with the rest of its data.
* The audit trail records who approved, executed and rolled back a fix from the signed-in
  session. The approve and rollback endpoints took `approved_by` / `requested_by` from
  the request body (defaulting to `"ui"`), so records said "ui" and a signed-in admin
  could name someone else. Those body fields are now ignored; execution records
  `executed_by`.
* A repeated Microsoft sign-in callback (a browser retry or a replayed link) could freeze
  the whole API: the callback locks its sign-in record and then waits on Microsoft, and
  the duplicate waited for that lock inside the event loop. The duplicate now gets 409
  at once. Any other database lock wait now fails after `DB_LOCK_TIMEOUT_MS` (default 5
  seconds) instead of hanging.
* The demo starts from prebuilt images. A release tag now publishes
  `cloud-locksmith-core-backend` and `cloud-locksmith-core-dashboard-demo` (amd64 and
  arm64) to `ghcr.io`, and `docker compose up` pulls the images for the release it
  names, building from source only when they cannot be pulled. The tag workflow fails if
  `docker-compose.yml` does not pin the tag's version.
* Change records: export every executed fix as JSON (who executed and approved it, the
  before and after state, each changed setting's before and after value, verification
  and rollback), and view one from **Remediation History** → **View change**. Suggested
  by the first public feedback. See `docs/remediation-lifecycle.md`.
* Framework mapping corrected. Several CISA SCuBA references in the evidence report were
  wrong (MS.AAD.3.3v1, 7.3v1 and 7.4v1 cited with statement text that is not in the
  baseline). Every SCuBA reference now quotes cisagov/ScubaGear verbatim and is checked
  at startup; 17 of 27 controls map to a SCuBA statement, graded direct, partial or
  evidence, and shown in `docs/controls.md`. CIS benchmark numbers were inferred rather
  than taken from the licensed benchmark, so they are no longer shown until verified.
  The report says "maps to", never "compliant". The evidence PDF is now rendered for
  real in CI.

## 0.1.1 (2026-11-13)

Fixes from the roadmap's first phase and from a supervised live run against a developer
tenant (`docs/connect-a-real-tenant.md` lists what was run).

* The scheduler is now off by default (`ENABLE_SCHEDULER=false`). The demo and the
  documented `.env.example` already turned it off, so they behave as before; any other
  install that relied on the old default must now set `ENABLE_SCHEDULER=true`.
* Stale service principal findings are saved (they failed with "unsupported
  resource_type").
* The permanent role assignment control queries Graph once per privileged role; Graph
  rejected the previous multi-value filter.
* After a Preview-only sign-in, routes that need live directory data return 409
  `FULL_CONNECT_REQUIRED` instead of 500, and Simulate Fix shows that reason.
* A Microsoft sign-in refused because the tenant already has an owner now says so on the
  login page (without naming the owner) instead of showing a bare login page.
* In the demo, a refused fix shows a plain message where you clicked.
* Conditional Access report-only policies use Graph's real state value,
  `enabledForReportingButNotEnforced`. The code sent `reportOnly`, which Graph rejects, so
  the licence check that runs before every Conditional Access fix failed and no
  Conditional Access fix could run; scans also missed existing report-only MFA policies.
* The Conditional Access licence check (it creates and immediately deletes a temporary
  report-only policy) now sends `clientAppTypes: ["all"]`; Graph rejected the empty list,
  and every Conditional Access fix was refused as "no licence". The check now runs only
  after the break-glass checks, and no longer runs before approval and preflight checks,
  so a fix that would be refused never writes to the tenant. Found in a live run.
* **Security fix.** "Review & Fix" on a Conditional Access card in Security Controls
  applied the policy in enforced mode directly, with no approval, approval expiry or
  preflight check. It now goes through the same approve, preflight and execute workflow
  as the Risk Feed, and `POST /api/v1/control/apply` refuses `mode: "enforced"`.
* Conditional Access fixes through the approval workflow failed with "Another
  Conditional Access mutation is already running", and could leave the tenant lock held.
  The lock is now held on its own database connection and is re-entrant within a request.
* Conditional Access verification now compares with the policy as Graph returns it
  (Graph adds empty fields), so correct policies are no longer reported as failed.
  Report-only fixes are verified as "report-only" and leave the finding open.
* A Conditional Access fix whose verification failed can now be rolled back, and rolling
  back a Conditional Access fix from the dashboard works (it always failed before).
* Two simultaneous fix or rollback requests for the same finding froze the whole API.
  The second request is now refused at once ("already executing", or 409 for rollback).
* The device code flow and authentication transfer fixes were always applied as
  enforced, without the break-glass check. They now follow the finding's mode
  (report-only by default) and run the break-glass check first, like the other
  Conditional Access fixes.
* A rolled-back Conditional Access fix can be applied again (it was reported as drift).
* If a Conditional Access rollback fails partway, the dashboard now says so and asks you
  to retry (it showed a generic error), the failure is recorded in the audit trail, and
  a retry restores the previous state. A rollback refused before any change explains why.
* The Users page shows each user's last sign-in (it showed "No recent activity" for
  everyone).
* The sidebar and the page content scroll independently.
* Refused fixes say why (expired approval, re-approval required, licence) instead of
  "Invalid remediation request", and a refusal by a pre-flight check is recorded with its
  reason in the finding and the audit trail.
* After three attempts a finding could never be fixed again, even after re-approval. A
  person's approval now starts a fresh set of attempts (automated approvals do not).
* A fixed finding no longer keeps an "Execution failed" label from earlier attempts.
* Remediation History lists Conditional Access fixes (with rollback), once per finding.
* Security Controls shows a report-only Conditional Access policy as "Report only".
* The sign-in scan no longer takes minutes on tenants with users who have no mailbox:
  inbox rules are read in parallel with a short limit per user.
* Risk Feed shows the risk distribution above the findings, so the findings use the full
  width.
* Stale service principals: every service principal was reported as stale, because the
  scan asked for a sign-in field that service principals do not have. Last sign-ins now
  come from Microsoft's service-principal sign-in report (a beta Graph endpoint, covered
  by the existing `AuditLog.Read.All` permission), Microsoft's own built-in apps are no
  longer judged, and nothing is flagged when the report cannot be read. Earlier false
  findings are resolved on the next scan.
* Service-account interactive login now records "no service-account-named accounts
  found" instead of nothing, so the dashboard shows the check ran.

## 0.1.0 (2026-11-12)

First open-source release of Cloud Locksmith Core, extracted from a private codebase.

* 27 identity and Conditional Access controls, posture score and history, risk feed,
  attack paths, approval-gated remediation with preflight checks, verification and
  rollback, MSP fleet view, baselines, campaigns, evidence reports, and an OAuth app
  consent review workflow.
* Read-only demo mode (`docker compose up --build`), with a recorded scan of a fictional
  tenant and guards that keep it away from Microsoft and real tenants.
* A single database baseline (`20261110_baseline`) for fresh installs. Databases from the
  private predecessor are not supported.
* Removed from the predecessor: paid plans, quotas and billing, the Marketplace
  (AppSource) sign-up, the marketing and legal pages, the terms-of-service gate, and
  unused modules.
* Fixed while extracting: dependencies pinned (and `greenlet` added); the two risk-based
  Conditional Access controls now require an Entra ID P2 licence; four controls that the
  capability map always blocked are now available behind approval.
