# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**, not in public issues:

* Use GitHub's **Report a vulnerability** button on this repository's *Security* tab
  (private vulnerability reporting).

Include what you found, how to reproduce it, and the impact you expect. You should get
an acknowledgement within 7 days. Please give us a reasonable time to fix the issue
before disclosing it.

## Scope

In scope: this repository's backend, dashboard, demo mode and deployment files.
Especially welcome are reports of:

* access to another tenant's data or actions (tenant isolation);
* OAuth or session flaws (state, `tid`/`oid` handling, token storage or revocation);
* ways for demo mode to reach a real tenant or Microsoft;
* remediation running without the approval and safety checks described in
  `docs/remediation-lifecycle.md`.

Out of scope: vulnerabilities in your own hosting, and findings that need an
already-compromised admin account or server.

## Supported versions

Only the latest release receives security fixes.
