from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


CONTROL_CAPABILITY_FIELDS = (
    "detect",
    "remediate",
    "auto_remediate",
    "requires_approval",
    "notes",
)
CONTROL_CAPABILITY_IDS = (
    "IDENTITY_USER_NO_MFA",
    "IDENTITY_ADMIN_NO_MFA",
    "IDENTITY_UNUSED_ACCOUNT",
    "IDENTITY_OVERPRIVILEGED_ADMIN",
    "IDENTITY_RISKY_OAUTH_APP",
    "TENANT_CONDITIONAL_ACCESS_POLICY",
    # Added: controls that were executable in CONTROL_REGISTRY but absent here,
    # causing evaluate_action() to return capability_not_defined and permanently
    # block them as POLICY_RESTRICTION before any Graph call was attempted.
    "IDENTITY_BREAK_GLASS_ACCOUNT",
    "IDENTITY_GUEST_INVITES_OPEN",
    "IDENTITY_USER_CONSENT_POLICY",
    "CA_BREAK_GLASS_EXCLUSION",
    "IDENTITY_PASSWORD_NEVER_EXPIRES",
    "IDENTITY_STALE_SERVICE_PRINCIPAL",
    "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
)
CONTROL_CAPABILITY_ALIASES = {
    "IDENTITY_ADMIN_OVERPRIVILEGED": "IDENTITY_OVERPRIVILEGED_ADMIN",
    "IDENTITY_ILLICIT_CONSENT_GRANTS": "IDENTITY_RISKY_OAUTH_APP",
    "IDENTITY_OVERPRIVILEGED_USER": "IDENTITY_OVERPRIVILEGED_ADMIN",
    # CA engine uses provider-specific IDs; map them to the canonical capability key.
    "CA_MFA_ALL_USERS": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_MFA_ADMINS": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_LEGACY_AUTH_BLOCK": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_DEVICE_CODE_FLOW_BLOCK": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_AUTHENTICATION_TRANSFER_BLOCK": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_GUEST_MFA": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_HIGH_RISK_SIGN_IN_BLOCK": "TENANT_CONDITIONAL_ACCESS_POLICY",
    "CA_RISK_BASED_STEP_UP_MFA": "TENANT_CONDITIONAL_ACCESS_POLICY",
}


def build_control_capability(
    *,
    detect: bool,
    remediate: bool,
    auto_remediate: bool,
    requires_approval: bool,
    notes: str,
) -> dict[str, Any]:
    if auto_remediate:
        mode = "auto"
        allowed = True
        reason = "auto_remediate"
    elif remediate:
        mode = "manual"
        allowed = True
        reason = "requires_approval" if requires_approval else "manual_remediate"
    else:
        mode = "blocked"
        allowed = False
        reason = "capability_unavailable"

    return {
        "detect": bool(detect),
        "remediate": bool(remediate),
        "auto_remediate": bool(auto_remediate),
        "requires_approval": bool(requires_approval),
        "notes": str(notes or ""),
        "allowed": allowed,
        "mode": mode,
        "reason": reason,
    }


def default_control_capabilities() -> dict[str, dict[str, Any]]:
    return {
        control_id: build_control_capability(
            detect=False,
            remediate=False,
            auto_remediate=False,
            requires_approval=False,
            notes="TODO",
        )
        for control_id in CONTROL_CAPABILITY_IDS
    }


def normalize_control_capability_id(control_id: str) -> str:
    normalized = str(control_id or "").strip().upper()
    return CONTROL_CAPABILITY_ALIASES.get(normalized, normalized)


class UnsupportedIdentityProviderError(ValueError):
    """Raised when a tenant provider has no registered adapter."""


class IdentityProviderAdapter(ABC):
    def __init__(self, *, db, tenant):
        self.db = db
        self.tenant = tenant

    @abstractmethod
    def get_control_capabilities(self) -> dict[str, dict[str, Any]]:
        """Return remediation capabilities keyed by normalized control_id."""

    @abstractmethod
    async def ingest_tenant_data(self) -> None:
        """Run provider-specific ingestion for the tenant."""

    @abstractmethod
    async def get(self, path: str) -> dict[str, Any]:
        """Fetch provider state by path."""

    @abstractmethod
    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create provider state by path."""

    @abstractmethod
    async def patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Update provider state by path."""

    @abstractmethod
    async def delete(self, path: str) -> dict[str, Any]:
        """Delete provider state by path."""

    @abstractmethod
    async def ensure_permissions(
        self,
        *,
        required_permissions: set[str],
        missing_permission_message: str,
    ) -> dict[str, Any]:
        """Validate that the tenant has the provider permissions needed for a change."""

    @abstractmethod
    async def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        """Return provider policies used by remediation controls."""

    @abstractmethod
    async def create_conditional_access_policy(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a provider policy for remediation."""

    @abstractmethod
    async def update_conditional_access_policy(
        self,
        policy_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a provider policy for remediation."""

    @abstractmethod
    async def delete_conditional_access_policy(self, policy_id: str) -> dict[str, Any]:
        """Delete a provider policy created or managed by remediation."""

    @abstractmethod
    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a provider-backed user."""

    @abstractmethod
    async def delete_user(self, user_id: str) -> dict[str, Any]:
        """Delete a provider-backed user."""

    @abstractmethod
    async def set_user_account_enabled(self, user_id: str, enabled: bool) -> dict[str, Any]:
        """Enable or disable a provider-backed user."""

    @abstractmethod
    async def add_directory_role_member(self, role_id: str, user_id: str) -> dict[str, Any]:
        """Add a user to a privileged provider role."""

    @abstractmethod
    async def create_role_eligibility_request(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a provider role eligibility request."""

    @abstractmethod
    async def create_role_assignment(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a provider role assignment."""

    @abstractmethod
    async def fetch_user_memberof_directory_roles(self, user_id: str) -> list[dict[str, str]]:
        """Fetch the current privileged roles for a user."""

    @abstractmethod
    async def get_authorization_policy(self) -> dict[str, Any]:
        """Fetch the tenant-wide authorization policy for identity controls."""

    @abstractmethod
    async def get_oauth2_permission_grant(self, grant_id: str) -> dict[str, Any]:
        """Fetch a single OAuth2 permission grant targeted by remediation."""

    @abstractmethod
    async def list_oauth2_permission_grants(self) -> list[dict[str, Any]]:
        """List OAuth2 permission grants targeted by remediation."""

    @abstractmethod
    async def get_user_account_state(
        self,
        user_id: str,
        *,
        use_application_token: bool = False,
    ) -> dict[str, Any]:
        """Fetch the provider account state for a user."""

    @abstractmethod
    async def remove_directory_role_member(self, role_id: str, user_id: str) -> dict[str, Any]:
        """Remove a user from a privileged provider role."""

    @abstractmethod
    async def delete_oauth2_permission_grant(self, grant_id: str) -> dict[str, Any]:
        """Delete an OAuth2 permission grant."""

    @abstractmethod
    async def create_oauth2_permission_grant(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create an OAuth2 permission grant (used during rollback)."""

    @abstractmethod
    async def create_service_principal(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a service principal (used during app consent rollback)."""

    # TODO: Add Google Workspace-specific abstractions once the
    # GoogleWorkspaceAdapter is introduced. Some Microsoft-specific methods
    # above will need provider-neutral names or Google-specific equivalents.
    # Microsoft-specific assumptions to revisit for Google:
    # - Graph directory role model (no direct equivalent in Google Workspace)
    # - CA policies (Azure AD Conditional Access, not applicable to Google)
    # - authorizationPolicy (Microsoft tenant-wide setting, no Google equivalent)
    # - OAuth2 permission grants (delegated consent, Google uses different model)
    # - Security Defaults (Microsoft-specific)
    # - Report download endpoints (Microsoft 365 reports API)
