# Changelog

## 0.1.0 (unreleased)

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
