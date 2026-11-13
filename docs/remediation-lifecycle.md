# Remediation lifecycle

Which controls can be fixed, rolled back or verified is listed in `controls.md`.
The behaviour below is what the code implements and what its tests cover. On a real
developer tenant (2026-11-13) one Conditional Access fix, *Block legacy authentication*
in report-only mode, was run through approve, execute, verify and roll back, together with
the refusals described here (`connect-a-real-tenant.md` lists exactly what was run).

## 1. Detect

A scan evaluates every control for the tenant and stores one finding per control and
resource (`compliance_results`). Conditional Access controls that need an Entra ID P1/P2
licence the tenant does not have are marked NOT_EVALUATED rather than failing.

## 2. Preview (no changes)

For `CA_MFA_ALL_USERS` and `CA_MFA_ADMINS` the dashboard offers **Simulate Fix**
(`POST /api/v1/simulations/run`): a pure calculation over a snapshot of the tenant's
users and roles that reports how many users would be required to use MFA, blocked, or
unaffected, and how many admins are affected. It calls no Graph write endpoint.

## 3. Approve

A fix only runs for a finding in the APPROVED state. Approval writes an audit record,
and **approvals expire after 48 hours**: an older approval sends the finding back to
PENDING. The dashboard asks for typed confirmation before executing.

## 4. Execute

`execute_approved_remediation` (`backend/app/services/remediation_execution_service.py`)
refuses to run unless all of these hold:

* the finding belongs to the requesting tenant and is still failing;
* the approval exists and is fresh (48 h);
* the user signed in with Microsoft within the last 24 hours (fix routes require it);
* the tenant has the licence the control needs (P1, or P2 for the risk-based CA policies);
* break-glass and other protected accounts are not the target;
* for the CA controls, the preflight checks pass (`services/remediation/preflight/`);
* no other remediation is running for the tenant (Postgres advisory lock) and the finding
  was not remediated in the last 30 minutes;
* the finding has not used up its three execution attempts. A person's approval starts a
  fresh set of attempts; automated approvals do not.

A second request for a finding that is already executing is refused at once ("already
executing"). A refusal is recorded on the finding and in the audit trail with its reason,
and the API returns that reason (for example an expired approval).

Conditional Access fixes run in the finding's mode, which defaults to **report-only**: the
policy logs what it would block and enforces nothing. Every policy excludes the registered
break-glass accounts. The licence check for Conditional Access creates and immediately
deletes a temporary report-only policy; it runs only after the pre-flight and break-glass
checks pass.

A snapshot of the state before the change is stored for rollback.

## 5. Verify

Where the control has a verifier, the result is read back from Graph after the change.
A fix only counts as successful when the executor reports success **and** verification
passes; otherwise the finding is marked failed.

For Conditional Access, verification checks that the managed policy exists exactly as
intended (empty fields Graph adds are ignored). An **enforced** policy must also make the
control pass. A **report-only** policy is recorded as verified *report-only* and the
finding stays open, because a report-only policy protects no one.

## 6. Roll back

Controls with rollback restore the stored snapshot (for example the previous Conditional
Access policy or the removed role assignments). Rollback is also audited, and needs the
same fresh Microsoft sign-in (24 h) as executing.

A Conditional Access fix can also be rolled back when its verification failed, since the
change was made and its snapshot exists. The server finds the change to undo itself,
within the requesting tenant. If Graph fails partway through a rollback, the API returns
502 `rollback_incomplete`, the failure is audited, and retrying the rollback restores the
snapshot.

## Automatic remediation (off by default)

The scheduler's auto-remediation job runs only when **both** `ENABLE_SCHEDULER=true`
(default false) **and** `ENABLE_AUTO_REMEDIATION=true` (default false). Even then it only
considers the controls in `AUTO_REMEDIATION_CONTROLS`
(`IDENTITY_OVERPRIVILEGED_USER`, `IDENTITY_UNUSED_ACCOUNT`, `IDENTITY_USER_CONSENT_POLICY`),
and skips a finding when:

* the control is not in the tenant's active baseline, or is rated DANGEROUS or manual;
* drift was detected less than 24 hours ago (grace period);
* five fixes already ran in this cycle;
* the tenant has no delegated token or lacks the required licence.

Auto-executed fixes can act on findings that nobody approved. Leave
`ENABLE_AUTO_REMEDIATION=false` unless you have reviewed that list for your tenants.

## Settings that are not safety switches

`REMEDIATION_DRY_RUN` (default true) is only read by a startup warning. It does **not**
stop remediations. Do not rely on it.

## Audit

Remediation decisions, approvals and executions are recorded in
`remediation_audit_logs`; the general `audit_logs` table is protected by a database
trigger that rejects UPDATE and DELETE.
