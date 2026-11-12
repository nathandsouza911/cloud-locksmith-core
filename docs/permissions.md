# Microsoft Graph permissions

Cloud Locksmith Core signs in with delegated OAuth (authorization code flow) against
your own multi-tenant Entra app registration. The scope set depends on how the user
signs in. All lists below are copied from the code; if they disagree, the code wins:
`backend/app/services/microsoft_oauth_scopes.py` and `backend/app/api/routes/auth_microsoft.py`.

The demo (`DEMO_MODE=true`) requests no permissions and makes no Microsoft calls.

## Full connect (`smb_onboarding`, `msp_connect`)

`DELEGATED_SCOPES`, used for the normal "connect a tenant" sign-in and MSP connect:

| Scope | Why it is requested |
|---|---|
| `openid`, `profile`, `email`, `offline_access` | Sign-in, the user's identity (`oid`, `tid`), and a refresh token. |
| `User.Read` | Read the signed-in user. |
| `User.Read.All` | Read users for the identity controls (unused accounts, MFA, service accounts). |
| `User.ReadWrite.All` | Fixes that change users (for example disabling an unused account, password-expiry flag). |
| `UserAuthenticationMethod.Read.All` | Read registered authentication methods for the MFA controls. |
| `Directory.Read.All` | Read directory objects: roles, groups, service principals, organization, domains. |
| `Policy.Read.All` | Read Conditional Access, authorization and security-defaults policies. |
| `Policy.ReadWrite.Authorization` | Fixes to the authorization policy (guest invites, user consent). Checked again at execution time. |
| `Policy.ReadWrite.ConditionalAccess` | Create and update the Conditional Access policies behind the `CA_*` fixes, and roll them back. |
| `RoleManagement.Read.Directory` | Read role assignments and PIM eligibility. |
| `RoleManagement.ReadWrite.Directory` | Remove excess admin role assignments (`IDENTITY_OVERPRIVILEGED_USER`) and restore them on rollback. |
| `AuditLog.Read.All` | Sign-in activity (last sign-in, break-glass usage). |
| `Reports.Read.All` | Usage and registration reports (MFA registration, licence cost checker). |
| `MailboxSettings.Read` | Inbox forwarding rules (`IDENTITY_MAIL_FORWARDING_RULE`). |

A unit test (`backend/tests/test_microsoft_oauth_scopes.py`) asserts the write scopes
above are requested and that `Directory.ReadWrite.All` and
`Policy.ReadWrite.AuthenticationMethod` are **not**.

## Preview sign-in (`preview`)

Read-only. The resulting access is `READ_ONLY`, and the access token is used for the scan
during sign-in and not stored.

`openid profile email offline_access User.Read User.Read.All UserAuthenticationMethod.Read.All Directory.Read.All Policy.Read.All RoleManagement.Read.Directory AuditLog.Read.All`

## Licence cost checker (`cost_checker`)

`User.Read.All Directory.Read.All Reports.Read.All`

## App-only (client credentials)

The backend can also request an app-only token
(`https://graph.microsoft.com/.default`) for the tenant set in `MICROSOFT_TENANT`. At
startup it checks that this app has the application permissions listed in
`REQUIRED_GRAPH_REMEDIATION_PERMISSIONS` (default `User.EnableDisableAccount.All`). In
production a missing permission stops startup; elsewhere it is logged as a warning. The
check is skipped in demo mode.

## Least privilege notes

* Admin consent is required for most of these scopes. Use a Global Administrator for the
  first connect; the tenant is then bound to that user's `oid` as owner (see
  `connect-a-real-tenant.md`).
* If you only want a posture scan, use the Preview sign-in: it requests no write scopes.
