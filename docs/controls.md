# Controls

Generated from `backend/app/services/remediation/control_registry.py` by
`python -m tools.gen_controls_doc`. Do not edit by hand.

27 controls. *Fix* means the product has an executor for the
control; every fix needs an explicit approval in the UI unless noted under
*Auto-fix list*. *Auto-fix list* controls can also be executed by the background
scheduler, but only when `ENABLE_AUTO_REMEDIATION=true` (default `false`).

The columns describe what the code implements and what its unit tests cover. What has
been run against a real tenant is listed in `connect-a-real-tenant.md`: the read-only
scan, and one fix (`CA_LEGACY_AUTH_BLOCK`, report-only) applied, verified and rolled back.

*CISA SCuBA* lists the baseline statements a control **maps to** (data:
`backend/app/services/control_catalog/`, statements quoted verbatim from
cisagov/ScubaGear). *partial* means the control covers part of the statement; *evidence*
means it supplies evidence for it without testing the setting itself. A mapping is not a
claim of compliance. `IDENTITY_PASSWORD_NEVER_EXPIRES` is deliberately unmapped: SCuBA
MS.AAD.6.1v1 says passwords SHALL NOT expire, the opposite of what that control flags.
CIS Microsoft 365 benchmark references are not shown until they are checked against the
licensed benchmark.

| Control | Title | Severity | Weight | Fix | Rollback | Verify after fix | Licence | Auto-fix list | CISA SCuBA |
|---|---|---|---|---|---|---|---|---|---|
| `CA_AUTHENTICATION_TRANSFER_BLOCK` | Authentication transfer blocked via CA policy | HIGH | 8 | yes | yes | yes | P1 | no | none |
| `CA_BREAK_GLASS_EXCLUSION` | Break-glass accounts excluded from all Conditional Access policies | CRITICAL | 10 (always monitored) | no | no | yes | none | no | none |
| `CA_DEVICE_CODE_FLOW_BLOCK` | Device code flow blocked via CA policy | HIGH | 8 | yes | yes | yes | P1 | no | MS.AAD.3.9v1 |
| `CA_GUEST_MFA` | MFA enforced for guest and external users via CA policy | HIGH | 8 | no | no | yes | P1 | no | MS.AAD.3.2v2 (partial) |
| `CA_HIGH_RISK_SIGN_IN_BLOCK` | High-risk sign-ins blocked via Identity Protection CA policy | HIGH | 8 | yes | yes | yes | P2 | no | MS.AAD.2.3v1 |
| `CA_LEGACY_AUTH_BLOCK` | Legacy authentication blocked via CA policy | HIGH | 8 | yes | yes | yes | P1 | no | MS.AAD.1.1v1 |
| `CA_MFA_ADMINS` | MFA enforced for all privileged roles via CA policy | CRITICAL | 10 | yes | yes | yes | P1 | no | MS.AAD.3.6v1 (partial) |
| `CA_MFA_ALL_USERS` | MFA enforced for all users via CA policy | CRITICAL | 10 | yes | yes | yes | P1 | no | MS.AAD.3.2v2 |
| `CA_RISK_BASED_STEP_UP_MFA` | Medium and high-risk sign-ins require step-up MFA via CA policy | HIGH | 6 | yes | yes | yes | P2 | no | MS.AAD.2.3v1 (partial) |
| `IDENTITY_ADMIN_COUNT_EXCESS` | Global administrator count within policy | HIGH | 10 | no | no | no | none | no | MS.AAD.7.1v1 (partial) |
| `IDENTITY_ADMIN_NO_MFA` | No admin without MFA | CRITICAL | 25 | no | no | no | none | no | MS.AAD.3.6v1 (partial) |
| `IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA` | Privileged admins use phishing-resistant MFA | CRITICAL | 12 | no | no | no | none | no | MS.AAD.3.6v1 |
| `IDENTITY_APP_SECRET_EXPIRING_SOON` | App registration credentials not expiring within 90 days | HIGH | 8 | no | no | no | none | no | none |
| `IDENTITY_BREAK_GLASS_ACCOUNT` | Two valid break-glass accounts configured | HIGH | 15 | yes | no | no | none | no | none |
| `IDENTITY_BREAK_GLASS_USAGE` | Break-glass account usage reviewed | CRITICAL | 0 (always monitored) | no | no | no | none | no | none |
| `IDENTITY_GUEST_INVITES_OPEN` | Guest invites restricted | MEDIUM | 8 | yes | yes | yes | none | no | MS.AAD.8.2v1 |
| `IDENTITY_ILLICIT_CONSENT_GRANTS` | No illicit user-consented OAuth grants | CRITICAL | 20 | yes | yes | yes | none | no | MS.AAD.5.2v1 (evidence) |
| `IDENTITY_MAIL_FORWARDING_RULE` | No inbox rules auto-forwarding mail outside the tenant | CRITICAL | 15 | no | no | no | none | no | MS.EXO.1.1v2 (partial) |
| `IDENTITY_OAUTH_APP_CONSENT_DISCOVERY` | Delegated OAuth app consent inventory | INFO | 0 (always monitored) | no | no | no | none | no | none |
| `IDENTITY_OVERPRIVILEGED_USER` | Users have minimal admin role assignments | HIGH | 15 | yes | yes | yes | none | yes | MS.AAD.7.2v1 (partial) |
| `IDENTITY_PASSWORD_NEVER_EXPIRES` | No user accounts with password set to never expire | MEDIUM | 6 | yes | yes | yes | none | no | none |
| `IDENTITY_PERMANENT_ROLE_ASSIGNMENT` | No permanent privileged role assignments without PIM | HIGH | 8 | no | no | no | none | no | MS.AAD.7.4v1 |
| `IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN` | Service accounts not performing interactive sign-ins | HIGH | 7 | yes | yes | yes | none | no | none |
| `IDENTITY_STALE_SERVICE_PRINCIPAL` | No enabled service principals inactive for more than 90 days | MEDIUM | 6 | yes | yes | yes | none | no | none |
| `IDENTITY_UNUSED_ACCOUNT` | No unused accounts | MEDIUM | 8 | yes | yes | yes | none | yes | none |
| `IDENTITY_USER_CONSENT_POLICY` | User consent locked down to owned resources | HIGH | 15 | yes | yes | yes | none | yes | MS.AAD.5.2v1 |
| `IDENTITY_USER_NO_MFA` | Users require MFA | HIGH | 15 | no | no | no | none | no | MS.AAD.3.2v2 (evidence) |
