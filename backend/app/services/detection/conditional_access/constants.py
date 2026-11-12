# Microsoft-defined privileged role template GUIDs.
# Used by CA-03 detection, CA_MFA_ADMINS remediation, and related safety checks.
# Source: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
PRIVILEGED_ROLE_TEMPLATE_IDS: frozenset[str] = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        "744ec460-397e-42ad-a462-8b3f9747a02c",  # Hybrid Identity Administrator
        "0526716b-113d-4c15-b2c8-68e3c22b9f80",  # Authentication Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
        "8ac3450a-2f88-4e3c-8d37-9be8e7a9f339",  # Security Operator
    }
)

# Backwards-compatible alias for existing imports.
PRIVILEGED_ROLE_IDS = PRIVILEGED_ROLE_TEMPLATE_IDS

# Legacy authentication client app types used by CA-09.
LEGACY_AUTH_CLIENT_APP_TYPES: frozenset[str] = frozenset(
    {
        "exchangeActiveSync",
        "other",
    }
)

DEVICE_CODE_FLOW_TRANSFER_METHOD = "deviceCodeFlow"
AUTHENTICATION_TRANSFER_METHOD = "authenticationTransfer"
ALL_GUEST_OR_EXTERNAL_USER_TYPES: frozenset[str] = frozenset(
    {
        "internalGuest",
        "b2bCollaborationGuest",
        "b2bCollaborationMember",
        "b2bDirectConnectUser",
        "otherExternalUser",
        "serviceProvider",
    }
)
