# Change record export (ROADMAP 3.3)

Written 2026-11-15 while the owner was away (owner asked to continue through the roadmap);
these are Claude's calls, open to correction.

## Why
An auditor, or the admin answering one, needs a durable record of each change the tool
made: who asked, who approved, what each setting was before and after, whether the
change was verified, and whether it was rolled back. First public feedback asked for the
before and after values. The data is already stored; this is a report over it.

## Decisions
- One record per execution (`RemediationAuditLog` row with decision `EXECUTED`), tenant
  from the session only.
- Requested/executed by: `executed_by` on the preceding `EXECUTE_STARTED` row (recorded
  from PR #7 on; older records show `null`, never a guess).
- Approval: the latest `APPROVED` row for the finding before the execution
  (`approved_by`, `approved_at`, `approval_mode`).
- Before/after:
  - generic executors: `RemediationSnapshot.state` / `.state_after` (`snapshot_id` on the
    EXECUTED row);
  - Conditional Access engine: `state_after.ca_snapshot_id` -> `ControlSnapshot.policies`
    (before) and the `ControlExecution` that used that snapshot (`policies_created`,
    `policies_updated`, mode, status, verified). Every lookup is filtered by tenant.
- `changes`: flat list of `{setting, before, after}` for every leaf that differs
  (dotted paths; lists compared whole). For a created CA policy, `before` is `null`.
- Verification: CA -> `ControlExecution.verified`; others -> the audit row's `verified`.
- Rollback: the first `ROLLED_BACK` row for the finding after the execution (and before
  the next execution): when, who, reason.
- Output: JSON download (`GET /api/v1/remediation/change-records`, optional
  `compliance_result_id`, `since`); PDF is left for later. The Remediation History page
  gets a "View change" panel with before/after side by side.

## Tests
Postgres integration: record contents for a generic and a CA execution; rollback linked
to the right execution; tenant A's export never contains tenant B's records, including
when a tenant A row points at a tenant B CA snapshot id. Dashboard: panel renders the
diff.
