import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.graph_client import GraphBlockedError
from app.services.identity_providers.google import GoogleAPIError
from app.services.identity_providers.google import GoogleWorkspaceAdapter


def _build_adapter():
    tenant = SimpleNamespace(
        id="tenant-google",
        provider="google",
        provider_credentials={
            "delegated_admin_email": "admin@example.com",
            "service_account": {
                "client_email": "svc@example.iam.gserviceaccount.com",
                "private_key": "test-placeholder-not-a-private-key",
                "token_uri": "https://oauth2.googleapis.com/token",
            },
        },
    )
    return GoogleWorkspaceAdapter(db=object(), tenant=tenant)


def test_google_service_account_validation_requires_required_keys():
    tenant = SimpleNamespace(
        id="tenant-google",
        provider="google",
        provider_credentials={
            "delegated_admin_email": "admin@example.com",
            "service_account": {"client_email": "svc@example.com"},
        },
    )
    adapter = GoogleWorkspaceAdapter(db=object(), tenant=tenant)

    with pytest.raises(RuntimeError, match="client_email, private_key"):
        adapter._service_account_info()


def test_google_delegated_admin_is_required():
    tenant = SimpleNamespace(
        id="tenant-google",
        provider="google",
        provider_credentials={
            "service_account": {
                "client_email": "svc@example.com",
                "private_key": "private-key",
            }
        },
    )
    adapter = GoogleWorkspaceAdapter(db=object(), tenant=tenant)

    with pytest.raises(ValueError, match="Delegated admin required"):
        adapter._delegated_admin_email()


def test_google_list_users_normalizes_paged_directory_results(monkeypatch):
    adapter = _build_adapter()
    call_count = {"value": 0}

    async def fake_request(method, path, *, payload=None, params=None):
        del method, payload
        call_count["value"] += 1
        assert path == "/users"
        if params and params.get("pageToken") == "page-2":
            return {
                "users": [
                    {
                        "id": "user-2",
                        "primaryEmail": "user2@example.com",
                        "name": {"fullName": "User Two"},
                        "isAdmin": False,
                        "suspended": True,
                        "lastLoginTime": "2026-04-20T00:00:00.000Z",
                    }
                ]
            }
        return {
            "users": [
                {
                    "id": "user-1",
                    "primaryEmail": "user1@example.com",
                    "name": {"fullName": "User One"},
                    "isAdmin": True,
                    "suspended": False,
                    "isEnrolledIn2Sv": True,
                    "lastLoginTime": "2026-04-21T00:00:00.000Z",
                }
            ],
            "nextPageToken": "page-2",
        }

    monkeypatch.setattr(adapter, "_request", fake_request)
    monkeypatch.setattr(
        adapter,
        "get_mfa_status",
        lambda user_id: (_ for _ in ()).throw(AssertionError(f"unexpected MFA call for {user_id}")),
    )

    users = asyncio.run(adapter.list_users())

    assert call_count["value"] == 2
    assert users == [
        {
            "id": "user-1",
            "email": "user1@example.com",
            "is_active": True,
            "is_admin": True,
            "mfa_enabled": True,
            "last_login": "2026-04-21T00:00:00.000Z",
            "display_name": "User One",
            "displayName": "User One",
            "mail": "user1@example.com",
            "userPrincipalName": "user1@example.com",
            "accountEnabled": True,
        },
        {
            "id": "user-2",
            "email": "user2@example.com",
            "is_active": False,
            "is_admin": False,
            "mfa_enabled": False,
            "last_login": "2026-04-20T00:00:00.000Z",
            "display_name": "User Two",
            "displayName": "User Two",
            "mail": "user2@example.com",
            "userPrincipalName": "user2@example.com",
            "accountEnabled": False,
        },
    ]


def test_google_fetch_user_roles_maps_role_assignments_to_normalized_roles(monkeypatch):
    adapter = _build_adapter()

    async def fake_list_directory_roles():
        return [
            {"id": "123", "displayName": "Super Admin"},
            {"id": "456", "displayName": "Groups Admin"},
        ]

    async def fake_list_role_assignments(*, user_key, role_id=None, include_indirect=False):
        assert user_key == "user-1"
        assert role_id is None
        assert include_indirect is True
        return [
            {"roleAssignmentId": "ra-1", "roleId": "123"},
            {"roleAssignmentId": "ra-2", "roleId": "456"},
            {"roleAssignmentId": "ra-3", "roleId": "123"},
        ]

    monkeypatch.setattr(adapter, "list_directory_roles", fake_list_directory_roles)
    monkeypatch.setattr(adapter, "_list_role_assignments", fake_list_role_assignments)

    roles = asyncio.run(adapter.fetch_user_memberof_directory_roles("user-1"))

    assert roles == [
        {"id": "123", "displayName": "Super Admin", "type": "directoryRole"},
        {"id": "456", "displayName": "Groups Admin", "type": "directoryRole"},
    ]


def test_google_fetch_user_roles_preserves_unknown_role_assignments(monkeypatch):
    adapter = _build_adapter()

    async def fake_list_directory_roles():
        return [
            {"id": "123", "displayName": "Super Admin", "type": "directoryRole"},
        ]

    async def fake_list_role_assignments(*, user_key, role_id=None, include_indirect=False):
        del role_id
        assert user_key == "user-1"
        assert include_indirect is True
        return [{"roleAssignmentId": "ra-1", "roleId": "999"}]

    monkeypatch.setattr(adapter, "list_directory_roles", fake_list_directory_roles)
    monkeypatch.setattr(adapter, "_list_role_assignments", fake_list_role_assignments)

    roles = asyncio.run(adapter.fetch_user_memberof_directory_roles("user-1"))

    assert roles == [
        {"id": "999", "displayName": "Unknown Role", "type": "unknown"},
    ]


def test_google_set_user_account_enabled_patches_and_verifies(monkeypatch):
    adapter = _build_adapter()

    patch_calls: list[tuple[str, dict]] = []

    async def fake_request(method, path, *, payload=None, params=None):
        del params
        if method == "PATCH":
            patch_calls.append((path, payload))
            assert path == "/users/user-1"
            assert payload == {"suspended": True}
            return {}
        assert method == "GET"
        return {
            "id": "user-1",
            "primaryEmail": "user1@example.com",
            "name": {"fullName": "User One"},
            "isAdmin": False,
            "suspended": True,
        }

    monkeypatch.setattr(adapter, "_request", fake_request)

    user = asyncio.run(adapter.set_user_account_enabled("user-1", False))

    assert patch_calls == [("/users/user-1", {"suspended": True})]
    assert user["id"] == "user-1"
    assert user["email"] == "user1@example.com"
    assert user["is_active"] is False
    assert user["accountEnabled"] is False


def test_google_set_user_account_enabled_returns_mismatched_state_after_retries(monkeypatch):
    """Directory API is eventually consistent: retry, then return the observed state (no raise).

    Callers must check is_active themselves.
    """
    adapter = _build_adapter()

    async def fake_patch(path, payload):
        assert path == "/users/user-1"
        assert payload == {"suspended": False}
        return {}

    async def fake_get_user_account_state(user_id, *, use_application_token=False):
        del use_application_token
        assert user_id == "user-1"
        return {
            "id": "user-1",
            "email": "user1@example.com",
            "is_active": False,
            "is_admin": False,
            "mfa_enabled": False,
            "last_login": None,
            "accountEnabled": False,
        }

    monkeypatch.setattr(adapter, "patch", fake_patch)
    monkeypatch.setattr(adapter, "get_user_account_state", fake_get_user_account_state)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr("app.services.identity_providers.google.asyncio.sleep", no_sleep)

    state = asyncio.run(adapter.set_user_account_enabled("user-1", True))
    assert state["is_active"] is False


def test_google_ensure_permissions_calls_required_probes(monkeypatch):
    adapter = _build_adapter()
    calls: list[str] = []

    async def fake_list_users():
        calls.append("users")
        return []

    async def fake_list_roles():
        calls.append("roles")
        return []

    monkeypatch.setattr(adapter, "list_users", fake_list_users)
    monkeypatch.setattr(adapter, "list_directory_roles", fake_list_roles)

    result = asyncio.run(
        adapter.ensure_permissions(
            required_permissions={"admin.directory.user", "admin.directory.rolemanagement"},
            missing_permission_message="missing permissions",
        )
    )

    assert calls == ["users", "roles"]
    assert result["status"] == "ok"


def test_google_ensure_permissions_maps_errors_to_permission_block(monkeypatch):
    adapter = _build_adapter()

    async def fake_list_users():
        raise GoogleAPIError(403, "permission denied", path="/users")

    monkeypatch.setattr(adapter, "list_users", fake_list_users)

    with pytest.raises(GraphBlockedError) as exc_info:
        asyncio.run(
            adapter.ensure_permissions(
                required_permissions=set(),
                missing_permission_message="missing permissions",
            )
        )

    assert exc_info.value.reason == "INSUFFICIENT_PERMISSIONS"
    assert exc_info.value.message == "missing permissions"


def test_google_list_users_detects_pagination_loop(monkeypatch):
    adapter = _build_adapter()

    async def fake_request(method, path, *, payload=None, params=None):
        del method, path, payload, params
        return {"users": [], "nextPageToken": "loop-token"}

    monkeypatch.setattr(adapter, "_request", fake_request)

    with pytest.raises(RuntimeError, match="pagination loop detected"):
        asyncio.run(adapter.list_users())


def test_google_revoke_user_sessions_posts_signout(monkeypatch):
    adapter = _build_adapter()

    async def fake_post(path, payload):
        assert path == "/users/user-1/signOut"
        assert payload == {}
        return {}

    monkeypatch.setattr(adapter, "post", fake_post)

    result = asyncio.run(adapter.revoke_user_sessions("user-1"))

    assert result == {"id": "user-1", "sessions_revoked": True}


def test_google_request_retries_rate_limit(monkeypatch):
    adapter = _build_adapter()
    responses: list[object] = []

    class _FakeResponse:
        def __init__(self, status_code, payload, *, headers=None, text=None, content=b"x"):
            self.status_code = status_code
            self._payload = payload
            self.headers = headers or {}
            self.text = text if text is not None else json.dumps(payload)
            self.content = content

        def json(self):
            return self._payload

    class _FakeClient:
        def __init__(self, **kwargs):
            del kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            del exc_type, exc, tb
            return False

        async def request(self, **kwargs):
            responses.append(kwargs)
            if len(responses) == 1:
                return _FakeResponse(
                    429,
                    {"error": {"message": "rate limit"}},
                    headers={"Retry-After": "0"},
                )
            return _FakeResponse(200, {"users": []})

    async def fake_sleep(delay):
        assert delay == 0.0

    monkeypatch.setattr(adapter, "_get_access_token", lambda: "token")
    monkeypatch.setattr("app.services.identity_providers.google.httpx.AsyncClient", _FakeClient)
    monkeypatch.setattr("app.services.identity_providers.google.asyncio.sleep", fake_sleep)

    result = asyncio.run(adapter._request("GET", "/users"))

    assert result == {"users": []}
    assert len(responses) == 2
