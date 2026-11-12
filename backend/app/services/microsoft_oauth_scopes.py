DELEGATED_SCOPES = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "User.Read",
    "User.Read.All",
    "User.ReadWrite.All",
    "UserAuthenticationMethod.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "Policy.ReadWrite.Authorization",
    "Policy.ReadWrite.ConditionalAccess",
    "RoleManagement.Read.Directory",
    "RoleManagement.ReadWrite.Directory",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "MailboxSettings.Read",
]

DELEGATED_SCOPE_STRING = " ".join(DELEGATED_SCOPES)
REQUIRED_AUTHORIZATION_POLICY_SCOPE = "Policy.ReadWrite.Authorization"

PREVIEW_SCOPES = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "User.Read",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All",
]

PREVIEW_SCOPE_STRING = " ".join(PREVIEW_SCOPES)

LICENSE_COST_CHECKER_SCOPES = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "User.Read.All",
    "Directory.Read.All",
    "Reports.Read.All",
]

LICENSE_COST_CHECKER_SCOPE_STRING = " ".join(LICENSE_COST_CHECKER_SCOPES)

WRITE_SCOPES = {
    "Policy.ReadWrite.Authorization",
    "Policy.ReadWrite.ConditionalAccess",
    "RoleManagement.ReadWrite.Directory",
}
