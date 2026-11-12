# Controls

Generated from `backend/app/services/remediation/control_registry.py` by
`python -m tools.gen_controls_doc`. Do not edit by hand.

27 controls. *Fix* means the product has an executor for the
control; every fix needs an explicit approval in the UI unless noted under
*Auto-fix list*. *Auto-fix list* controls can also be executed by the background
scheduler, but only when `ENABLE_AUTO_REMEDIATION=true` (default `false`).

The columns describe what the code implements and what its unit tests cover. Against a
real tenant, only the read-only scan, the scoring and the `CA_MFA_ALL_USERS` fix
simulation have been exercised so far; no fix in this table has been executed against
a real tenant from this codebase.

| Control | Title | Severity | Weight | Fix | Rollback | Verify after fix | Licence | Auto-fix list |
|---|---|---|---|---|---|---|---|---|
| `CA_AUTHENTICATION_TRANSFER_BLOCK` | Authentication transfer blocked via CA policy | HIGH | 8 | yes | yes | yes | P1 | no |
| `CA_BREAK_GLASS_EXCLUSION` | Break-glass accounts excluded from all Conditional Access policies | CRITICAL | 10 (always monitored) | no | no | yes | none | no |
| `CA_DEVICE_CODE_FLOW_BLOCK` | Device code flow blocked via CA policy | HIGH | 8 | yes | yes | yes | P1 | no |
| `CA_GUEST_MFA` | MFA enforced for guest and external users via CA policy | HIGH | 8 | no | no | yes | P1 | no |
| `CA_HIGH_RISK_SIGN_IN_BLOCK` | High-risk sign-ins blocked via Identity Protection CA policy | HIGH | 8 | yes | yes | yes | P2 | no |
| `CA_LEGACY_AUTH_BLOCK` | Legacy authentication blocked via CA policy | HIGH | 8 | yes | yes | yes | P1 | no |
| `CA_MFA_ADMINS` | MFA enforced for all privileged roles via CA policy | CRITICAL | 10 | yes | yes | yes | P1 | no |
| `CA_MFA_ALL_USERS` | MFA enforced for all users via CA policy | CRITICAL | 10 | yes | yes | yes | P1 | no |
| `CA_RISK_BASED_STEP_UP_MFA` | Medium and high-risk sign-ins require step-up MFA via CA policy | HIGH | 6 | yes | yes | yes | P2 | no |
| `IDENTITY_ADMIN_COUNT_EXCESS` | Global administrator count within policy | HIGH | 10 | no | no | no | none | no |
| `IDENTITY_ADMIN_NO_MFA` | No admin without MFA | CRITICAL | 25 | no | no | no | none | no |
| `IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA` | Privileged admins use phishing-resistant MFA | CRITICAL | 12 | no | no | no | none | no |
| `IDENTITY_APP_SECRET_EXPIRING_SOON` | App registration credentials not expiring within 90 days | HIGH | 8 | no | no | no | none | no |
| `IDENTITY_BREAK_GLASS_ACCOUNT` | Two valid break-glass accounts configured | HIGH | 15 | yes | no | no | none | no |
| `IDENTITY_BREAK_GLASS_USAGE` | Break-glass account usage reviewed | CRITICAL | 0 (always monitored) | no | no | no | none | no |
| `IDENTITY_GUEST_INVITES_OPEN` | Guest invites restricted | MEDIUM | 8 | yes | yes | yes | none | no |
| `IDENTITY_ILLICIT_CONSENT_GRANTS` | No illicit user-consented OAuth grants | CRITICAL | 20 | yes | yes | yes | none | no |
| `IDENTITY_MAIL_FORWARDING_RULE` | No inbox rules auto-forwarding mail outside the tenant | CRITICAL | 15 | no | no | no | none | no |
| `IDENTITY_OAUTH_APP_CONSENT_DISCOVERY` | Delegated OAuth app consent inventory | INFO | 0 (always monitored) | no | no | no | none | no |
| `IDENTITY_OVERPRIVILEGED_USER` | Users have minimal admin role assignments | HIGH | 15 | yes | yes | yes | none | yes |
| `IDENTITY_PASSWORD_NEVER_EXPIRES` | No user accounts with password set to never expire | MEDIUM | 6 | yes | yes | yes | none | no |
| `IDENTITY_PERMANENT_ROLE_ASSIGNMENT` | No permanent privileged role assignments without PIM | HIGH | 8 | no | no | no | none | no |
| `IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN` | Service accounts not performing interactive sign-ins | HIGH | 7 | yes | yes | yes | none | no |
| `IDENTITY_STALE_SERVICE_PRINCIPAL` | No enabled service principals inactive for more than 90 days | MEDIUM | 6 | yes | yes | yes | none | no |
| `IDENTITY_UNUSED_ACCOUNT` | No unused accounts | MEDIUM | 8 | yes | yes | yes | none | yes |
| `IDENTITY_USER_CONSENT_POLICY` | User consent locked down to owned resources | HIGH | 15 | yes | yes | yes | none | yes |
| `IDENTITY_USER_NO_MFA` | Users require MFA | HIGH | 15 | no | no | no | none | no |
