from app.services.microsoft_oauth_scopes import REQUIRED_AUTHORIZATION_POLICY_SCOPE


AUTHORIZATION_POLICY_GUEST_ALLOW_INVITES = "adminsAndGuestInviters"
_MANAGE_FOR_SELF_PREFIX = "ManagePermissionGrantsForSelf"


async def _ensure_authorization_policy_permissions(graph_client) -> None:
    ensure_permissions = getattr(graph_client, "ensure_permissions", None)
    if ensure_permissions is None:
        return
    await ensure_permissions(
        missing_permission_message=(
            f"Missing required permission: {REQUIRED_AUTHORIZATION_POLICY_SCOPE}. " "Please reconnect tenant."
        ),
    )


async def _patch_authorization_policy(
    graph_client,
    *,
    current_policy: dict,
    snapshot: dict,
    desired_top_level_fields: dict | None = None,
    desired_default_user_role_permissions: dict | None = None,
) -> dict:
    desired_top_level_fields = desired_top_level_fields or {}
    current_permissions = current_policy.get("defaultUserRolePermissions") or {}
    merged_permissions = None

    if desired_default_user_role_permissions is not None:
        merged_permissions = {
            **current_permissions,
            **desired_default_user_role_permissions,
        }

    payload = {}
    for field, value in desired_top_level_fields.items():
        if current_policy.get(field) != value:
            payload[field] = value

    if merged_permissions is not None and current_permissions != merged_permissions:
        payload["defaultUserRolePermissions"] = merged_permissions

    desired_state = {**desired_top_level_fields}
    if merged_permissions is not None:
        desired_state["defaultUserRolePermissions"] = merged_permissions

    if not payload:
        return {
            "status": "ALREADY_CONFIGURED",
            "snapshot": snapshot,
            "desired_state": desired_state,
            "current_state": snapshot["authorization_policy"],
        }

    await _ensure_authorization_policy_permissions(graph_client)
    await graph_client.patch("/policies/authorizationPolicy", payload)
    verified_policy = await graph_client.get("/policies/authorizationPolicy")

    for field, value in desired_top_level_fields.items():
        if verified_policy.get(field) != value:
            raise RuntimeError(f"Authorization policy verification failed for field '{field}'")

    if merged_permissions is not None:
        verified_permissions = verified_policy.get("defaultUserRolePermissions") or {}
        for field, value in desired_default_user_role_permissions.items():
            if verified_permissions.get(field) != value:
                raise RuntimeError(
                    "Authorization policy verification failed for " f"defaultUserRolePermissions.{field}"
                )

    return {
        "status": "UPDATED",
        "snapshot": snapshot,
        "desired_state": desired_state,
        "current_state": snapshot["authorization_policy"],
    }


class GuestInvitesExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        current_policy = await graph_client.get("/policies/authorizationPolicy")
        return {
            "authorization_policy": {
                "allowInvitesFrom": current_policy.get("allowInvitesFrom"),
            },
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        current_policy = await graph_client.get("/policies/authorizationPolicy")
        snapshot = evidence.get("snapshot") or {
            "authorization_policy": {
                "allowInvitesFrom": current_policy.get("allowInvitesFrom"),
            },
        }
        return await _patch_authorization_policy(
            graph_client,
            current_policy=current_policy,
            snapshot=snapshot,
            desired_top_level_fields={
                "allowInvitesFrom": (evidence.get("allowInvitesFrom") or AUTHORIZATION_POLICY_GUEST_ALLOW_INVITES),
            },
        )

    async def preview(self, graph_client, evidence: dict) -> dict:
        current_policy = await graph_client.get("/policies/authorizationPolicy")
        current_value = current_policy.get("allowInvitesFrom")
        desired_value = evidence.get("allowInvitesFrom") or AUTHORIZATION_POLICY_GUEST_ALLOW_INVITES
        return {
            "changes": [
                {
                    "action": "PATCH_AUTHORIZATION_POLICY",
                    "field": "allowInvitesFrom",
                    "current": current_value,
                    "desired": desired_value,
                }
            ]
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        prior = (snapshot or {}).get("authorization_policy") or {}
        if "allowInvitesFrom" in prior:
            await graph_client.patch(
                "/policies/authorizationPolicy",
                {"allowInvitesFrom": prior["allowInvitesFrom"]},
            )


class UserConsentExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        current_policy = await graph_client.get("/policies/authorizationPolicy")
        return {
            "authorization_policy": {
                "defaultUserRolePermissions": current_policy.get("defaultUserRolePermissions") or {},
            },
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        current_policy = await graph_client.get("/policies/authorizationPolicy")
        snapshot = evidence.get("snapshot") or {
            "authorization_policy": {
                "defaultUserRolePermissions": current_policy.get("defaultUserRolePermissions") or {},
            },
        }
        current_permissions = current_policy.get("defaultUserRolePermissions") or {}
        current_assigned = current_permissions.get("permissionGrantPoliciesAssigned") or []
        # Remove all ManagePermissionGrantsForSelf.* entries; preserve read-only Teams RSC entries.
        locked_down_assigned = [
            entry
            for entry in current_assigned
            if not (isinstance(entry, str) and entry.startswith(_MANAGE_FOR_SELF_PREFIX))
        ]
        return await _patch_authorization_policy(
            graph_client,
            current_policy=current_policy,
            snapshot=snapshot,
            desired_default_user_role_permissions={
                "permissionGrantPoliciesAssigned": locked_down_assigned,
            },
        )

    async def preview(self, graph_client, evidence: dict) -> dict:
        current_policy = await graph_client.get("/policies/authorizationPolicy")
        current_permissions = current_policy.get("defaultUserRolePermissions") or {}
        current_assigned = current_permissions.get("permissionGrantPoliciesAssigned") or []
        locked_down_assigned = [
            entry
            for entry in current_assigned
            if not (isinstance(entry, str) and entry.startswith(_MANAGE_FOR_SELF_PREFIX))
        ]
        return {
            "changes": [
                {
                    "action": "PATCH_AUTHORIZATION_POLICY",
                    "field": "defaultUserRolePermissions.permissionGrantPoliciesAssigned",
                    "current": current_assigned,
                    "desired": locked_down_assigned,
                }
            ]
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        prior = (snapshot or {}).get("authorization_policy") or {}
        permissions = prior.get("defaultUserRolePermissions")
        if permissions is not None:
            await graph_client.patch(
                "/policies/authorizationPolicy",
                {"defaultUserRolePermissions": permissions},
            )
