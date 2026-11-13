# Changelog

## Unreleased

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
