import asyncio

from app.services.remediation.admin_roles.admin_role_execute import AdminRoleExecutor
from app.services.remediation.tenant_identity_execute import (
    GuestInvitesExecutor,
    UserConsentExecutor,
)


class FakeGraphClient:
    def __init__(self, responses: dict[str, dict]):
        self.responses = dict(responses)
        self.patch_calls: list[tuple[str, dict]] = []
        self.ensure_permissions_calls: list[dict] = []

    async def get(self, path: str):
        return dict(self.responses[path])

    async def patch(self, path: str, payload: dict):
        self.patch_calls.append((path, payload))
        current = self.responses.get(path, {})
        current.update(payload)
        self.responses[path] = current
        return current

    async def ensure_permissions(self, **kwargs):
        self.ensure_permissions_calls.append(kwargs)
        return {"scp": "Policy.ReadWrite.Authorization"}


class FakeAdminRoleGraphClient(FakeGraphClient):
    def __init__(self):
        super().__init__({})
        self.db = object()
        self.tenant = object()
        self.user_roles = {
            "user-1": {
                "/users/user-1/memberOf": {
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.directoryRole",
                            "id": "role-global-admin",
                            "displayName": "Global Administrator",
                        }
                    ]
                }
            }
        }
        self.removed_members: list[tuple[str, str]] = []
        self.added_members: list[tuple[str, str]] = []

    async def get(self, path: str):
        if path in self.user_roles.get("user-1", {}):
            return self.user_roles["user-1"][path]
        return await super().get(path)

    async def remove_directory_role_member(self, role_id: str, user_id: str):
        self.removed_members.append((role_id, user_id))
        return {}

    async def add_directory_role_member(self, role_id: str, user_id: str):
        self.added_members.append((role_id, user_id))
        return {}

    async def fetch_user_memberof_directory_roles(self, user_id: str):
        payload = await self.get(f"/users/{user_id}/memberOf")
        return payload.get("value", [])


def test_guest_invites_executor_updates_authorization_policy():
    executor = GuestInvitesExecutor()
    graph_client = FakeGraphClient(
        {
            "/policies/authorizationPolicy": {
                "allowInvitesFrom": "everyone",
            }
        }
    )

    result = asyncio.run(executor.execute(graph_client, {}))

    assert result["status"] == "UPDATED"
    assert graph_client.patch_calls == [
        (
            "/policies/authorizationPolicy",
            {"allowInvitesFrom": "adminsAndGuestInviters"},
        )
    ]
    assert graph_client.ensure_permissions_calls == [
        {
            "missing_permission_message": (
                "Missing required permission: Policy.ReadWrite.Authorization. " "Please reconnect tenant."
            )
        }
    ]


# Test 1: Remediation strips all ManagePermissionGrantsForSelf.* entries and preserves
# Teams RSC entries (ManagePermissionGrantsForOwnedResource.<specific-name>).
def test_user_consent_executor_removes_self_consent_preserves_teams_rsc():
    executor = UserConsentExecutor()
    graph_client = FakeGraphClient(
        {
            "/policies/authorizationPolicy": {
                "defaultUserRolePermissions": {
                    "allowedToCreateApps": True,
                    "permissionGrantPoliciesAssigned": [
                        "ManagePermissionGrantsForSelf.microsoft-user-default-low",
                        "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
                    ],
                }
            }
        }
    )

    result = asyncio.run(executor.execute(graph_client, {}))

    assert result["status"] == "UPDATED"
    assert graph_client.patch_calls == [
        (
            "/policies/authorizationPolicy",
            {
                "defaultUserRolePermissions": {
                    "allowedToCreateApps": True,
                    "permissionGrantPoliciesAssigned": [
                        "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
                    ],
                }
            },
        )
    ]


# Test 2: Returns ALREADY_CONFIGURED when tenant already has no ManagePermissionGrantsForSelf.*
# entries (only Teams RSC entries present — already locked down).
def test_user_consent_executor_already_configured_when_only_teams_rsc_present():
    executor = UserConsentExecutor()
    graph_client = FakeGraphClient(
        {
            "/policies/authorizationPolicy": {
                "defaultUserRolePermissions": {
                    "permissionGrantPoliciesAssigned": [
                        "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
                    ]
                }
            }
        }
    )

    result = asyncio.run(executor.execute(graph_client, {}))

    assert result["status"] == "ALREADY_CONFIGURED"
    assert graph_client.patch_calls == []


# Test 3: Returns ALREADY_CONFIGURED when permissionGrantPoliciesAssigned is empty — the
# fully-disabled state is valid and requires no remediation.
def test_user_consent_executor_already_configured_when_policies_empty():
    executor = UserConsentExecutor()
    graph_client = FakeGraphClient(
        {"/policies/authorizationPolicy": {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}}}
    )

    result = asyncio.run(executor.execute(graph_client, {}))

    assert result["status"] == "ALREADY_CONFIGURED"
    assert graph_client.patch_calls == []


# Test 4: Rollback restores the complete original defaultUserRolePermissions (including any
# ManagePermissionGrantsForSelf.* entries that were present before remediation).
def test_user_consent_executor_rollback_restores_original_permissions():
    executor = UserConsentExecutor()
    original_permissions = {
        "allowedToCreateApps": True,
        "permissionGrantPoliciesAssigned": [
            "ManagePermissionGrantsForSelf.microsoft-user-default-low",
            "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
        ],
    }
    graph_client = FakeGraphClient(
        {
            "/policies/authorizationPolicy": {
                "defaultUserRolePermissions": original_permissions,
            }
        }
    )

    result = asyncio.run(executor.execute(graph_client, {}))
    assert result["status"] == "UPDATED"

    asyncio.run(executor.rollback(graph_client, result["snapshot"]))

    rollback_patch = graph_client.patch_calls[1]
    assert rollback_patch == (
        "/policies/authorizationPolicy",
        {"defaultUserRolePermissions": original_permissions},
    )


def test_admin_role_executor_removes_role_and_can_rollback():
    executor = AdminRoleExecutor()
    graph_client = FakeAdminRoleGraphClient()

    result = asyncio.run(
        executor.execute(
            graph_client,
            {
                "user_id": "user-1",
                "selected_roles": ["role-global-admin"],
            },
        )
    )
    asyncio.run(executor.rollback(graph_client, result["snapshot"]))

    assert graph_client.removed_members == [
        ("role-global-admin", "user-1"),
    ]
    assert graph_client.added_members == [
        ("role-global-admin", "user-1"),
    ]
