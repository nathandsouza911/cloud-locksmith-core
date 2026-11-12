from __future__ import annotations

import logging
from typing import Any

from app.db.models import User
from app.services.break_glass_safeguards import merge_break_glass_exclusions
from app.services.graph_client import (
    AUTHORIZATION_POLICY_WRITE_PERMISSIONS,
    fetch_user_memberof_directory_roles,
    get_tenant_graph_token_claims,
    graph_delete,
    graph_get,
    graph_get_all,
    graph_get_app,
    graph_patch,
    graph_post,
    set_user_account_enabled_with_app_token,
    validate_tenant_graph_permissions,
)
from app.services.identity_providers.base import (
    IdentityProviderAdapter,
    build_control_capability,
    default_control_capabilities,
)
from app.services.microsoft_oauth_scopes import REQUIRED_AUTHORIZATION_POLICY_SCOPE
from app.services.token_manager import get_valid_access_token, has_delegated_oauth_token

logger = logging.getLogger(__name__)


class MicrosoftIdentityProviderAdapter(IdentityProviderAdapter):
    def get_control_capabilities(self) -> dict[str, dict[str, Any]]:
        capabilities = default_control_capabilities()
        capabilities.update(
            {
                "IDENTITY_USER_NO_MFA": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Detects MFA methods and Conditional Access coverage; remediates via Conditional Access enforcement — requires approval.",
                ),
                "IDENTITY_ADMIN_NO_MFA": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Remediates by enforcing Conditional Access for privileged roles through the existing approval flow.",
                ),
                "IDENTITY_UNUSED_ACCOUNT": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=True,
                    requires_approval=False,
                    notes="Detects dormant accounts from lastSignIn and disables accounts directly.",
                ),
                "IDENTITY_OVERPRIVILEGED_ADMIN": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=True,
                    requires_approval=False,
                    notes="Detects privileged role assignments and removes selected directory roles.",
                ),
                "IDENTITY_RISKY_OAUTH_APP": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Supports OAuth grant detection and remediation, but destructive revocation stays on the manual approval path.",
                ),
                "TENANT_CONDITIONAL_ACCESS_POLICY": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Microsoft supports creating and modifying Conditional Access policies through existing guarded workflows.",
                ),
                # Previously missing: these controls are executable in CONTROL_REGISTRY
                # but had no capability entry, so evaluate_action() blocked them
                # permanently as POLICY_RESTRICTION before reaching Graph.
                "IDENTITY_BREAK_GLASS_ACCOUNT": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Creates two emergency-access accounts excluded from all CA policies — dangerous; always requires explicit approval.",
                ),
                "IDENTITY_GUEST_INVITES_OPEN": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Restricts guest invitation to administrators via authorizationPolicy — tenant-wide write; requires approval.",
                ),
                "IDENTITY_USER_CONSENT_POLICY": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Restricts end-user OAuth consent to admin-approved apps — requires approval.",
                ),
                "CA_BREAK_GLASS_EXCLUSION": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Adds break-glass account exclusions to CA policies via the guarded CA workflow — requires approval.",
                ),
                "IDENTITY_PASSWORD_NEVER_EXPIRES": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=True,
                    requires_approval=False,
                    notes="Detects users with DisablePasswordExpiration flag and removes it via passwordPolicies PATCH.",
                ),
                "IDENTITY_STALE_SERVICE_PRINCIPAL": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Disables one stale service principal per finding; workloads using it stop working — requires approval.",
                ),
                "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=False,
                    requires_approval=True,
                    notes="Disables one service account used for interactive sign-in per finding — requires approval.",
                ),
            }
        )
        return capabilities

    async def ingest_tenant_data(self) -> None:
        if not await has_delegated_oauth_token(self.tenant, db=self.db):
            raise Exception("Tenant has no OAuth token")

        access_token = await get_valid_access_token(self.tenant.id, db=self.db)
        if "." not in access_token:
            raise Exception("Invalid Graph access token format")

        # Token validated; no additional ingestion steps at this time.

    async def get(self, path: str) -> dict[str, Any]:
        return await graph_get(self.db, self.tenant, path)

    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await graph_post(self.db, self.tenant, path, payload)

    async def patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await graph_patch(self.db, self.tenant, path, payload)

    async def delete(self, path: str) -> dict[str, Any]:
        return await graph_delete(self.db, self.tenant, path)

    async def ensure_permissions(
        self,
        *,
        required_permissions: set[str] = AUTHORIZATION_POLICY_WRITE_PERMISSIONS,
        missing_permission_message: str = (
            f"Missing required permission: {REQUIRED_AUTHORIZATION_POLICY_SCOPE}. " "Please reconnect tenant."
        ),
    ) -> dict[str, Any]:
        return await validate_tenant_graph_permissions(
            db=self.db,
            tenant=self.tenant,
            required_permissions=required_permissions,
            missing_permission_message=missing_permission_message,
        )

    async def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        return await graph_get_all(
            self.db,
            self.tenant,
            "/identity/conditionalAccess/policies",
        )

    async def create_conditional_access_policy(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        from app.schemas.graph_payloads import (
            ConditionalAccessPolicySchema,
            validate_graph_payload,
        )

        payload = merge_break_glass_exclusions(
            db=self.db,
            tenant_id=self.tenant.id,
            policy_payload=payload,
        )
        validated = validate_graph_payload(
            ConditionalAccessPolicySchema,
            payload,
            context="conditional_access_create",
        )
        return await self.post(
            "/identity/conditionalAccess/policies",
            validated.model_dump(mode="json"),
        )

    async def update_conditional_access_policy(
        self,
        policy_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        from app.schemas.graph_payloads import (
            ConditionalAccessPolicySchema,
            validate_graph_payload,
        )

        payload = merge_break_glass_exclusions(
            db=self.db,
            tenant_id=self.tenant.id,
            policy_payload=payload,
        )
        validated = validate_graph_payload(
            ConditionalAccessPolicySchema,
            payload,
            context="conditional_access_patch",
        )
        return await self.patch(
            f"/identity/conditionalAccess/policies/{policy_id}",
            validated.model_dump(mode="json"),
        )

    async def delete_conditional_access_policy(self, policy_id: str) -> dict[str, Any]:
        return await self.delete(f"/identity/conditionalAccess/policies/{policy_id}")

    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        from app.schemas.graph_payloads import UserCreateSchema, validate_graph_payload

        validated = validate_graph_payload(
            UserCreateSchema,
            payload,
            context="user_create",
        )
        return await self.post(
            "/users",
            validated.model_dump(mode="json"),
        )

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        return await self.delete(f"/users/{user_id}")

    async def set_user_account_enabled(self, user_id: str, enabled: bool) -> dict[str, Any]:
        from app.schemas.graph_payloads import UserPatchSchema, validate_graph_payload

        validated = validate_graph_payload(
            UserPatchSchema,
            {"accountEnabled": enabled},
            context="user_patch",
        )
        user = (
            self.db.query(User)
            .filter(
                User.tenant_id == self.tenant.id,
                User.external_id == user_id,
            )
            .one_or_none()
        )
        return await set_user_account_enabled_with_app_token(
            user_id=user_id,
            enabled=validated.accountEnabled,
            tenant_id=self.tenant.id,
            db=self.db,
            user_email=getattr(user, "email", None),
            tenant=self.tenant,
        )

    async def add_directory_role_member(self, role_id: str, user_id: str) -> dict[str, Any]:
        from app.schemas.graph_payloads import (
            DirectoryObjectReferenceSchema,
            validate_graph_payload,
        )

        validated = validate_graph_payload(
            DirectoryObjectReferenceSchema,
            {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"},
            context="directory_role_member_post",
        )
        return await self.post(
            f"/directoryRoles/{role_id}/members/$ref",
            validated.model_dump(mode="json", by_alias=True),
        )

    async def create_role_eligibility_request(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        from app.schemas.graph_payloads import (
            RoleEligibilityScheduleRequestSchema,
            validate_graph_payload,
        )

        validated = validate_graph_payload(
            RoleEligibilityScheduleRequestSchema,
            payload,
            context="role_eligibility_post",
        )
        return await self.post(
            "/roleManagement/directory/roleEligibilityScheduleRequests",
            validated.model_dump(mode="json"),
        )

    async def create_role_assignment(self, payload: dict[str, Any]) -> dict[str, Any]:
        from app.schemas.graph_payloads import RoleAssignmentSchema, validate_graph_payload

        validated = validate_graph_payload(
            RoleAssignmentSchema,
            payload,
            context="role_assignment_post",
        )
        return await self.post(
            "/roleManagement/directory/roleAssignments",
            validated.model_dump(mode="json"),
        )

    async def fetch_user_memberof_directory_roles(self, user_id: str) -> list[dict[str, str]]:
        return await fetch_user_memberof_directory_roles(self.db, self.tenant, user_id)

    async def get_authorization_policy(self) -> dict[str, Any]:
        return await self.get("/policies/authorizationPolicy")

    async def get_oauth2_permission_grant(self, grant_id: str) -> dict[str, Any]:
        return await self.get(f"/oauth2PermissionGrants/{grant_id}")

    async def list_oauth2_permission_grants(self) -> list[dict[str, Any]]:
        return await graph_get_all(self.db, self.tenant, "/oauth2PermissionGrants")

    async def get_user_account_state(
        self,
        user_id: str,
        *,
        use_application_token: bool = False,
    ) -> dict[str, Any]:
        path = f"/users/{user_id}?$select=id,mail,userPrincipalName,accountEnabled"
        if use_application_token:
            return await graph_get_app(path)
        return await self.get(path)

    async def remove_directory_role_member(self, role_id: str, user_id: str) -> dict[str, Any]:
        return await self.delete(f"/directoryRoles/{role_id}/members/{user_id}/$ref")

    async def delete_oauth2_permission_grant(self, grant_id: str) -> dict[str, Any]:
        return await self.delete(f"/oauth2PermissionGrants/{grant_id}")

    async def create_oauth2_permission_grant(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/oauth2PermissionGrants", payload)

    async def create_service_principal(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/servicePrincipals", payload)

    async def log_offboarding_step_context(self, *, step: str, user_id: str) -> None:
        claims = await get_tenant_graph_token_claims(
            db=self.db,
            tenant=self.tenant,
        )
        logger.info(
            "OFFBOARDING_STEP_CONTEXT %s",
            {
                "step": step,
                "user_id": user_id,
                "tenant_id": self.tenant.id,
                "token_tid": claims.get("tid"),
            },
        )
        if claims.get("tid") and claims.get("tid") != self.tenant.id:
            raise ValueError("TENANT_CONTEXT_MISMATCH")
