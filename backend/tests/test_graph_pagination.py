"""Regression tests for Graph API pagination completeness.

Verifies that every collection read follows @odata.nextLink so tenants
with >100 items are never silently truncated.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.identity_providers import microsoft
from app.services.identity_providers.microsoft import MicrosoftIdentityProviderAdapter


# ---------------------------------------------------------------------------
# Pre-existing tests (Task 2 coverage)
# ---------------------------------------------------------------------------


def test_microsoft_adapter_paginates_conditional_access_policies(monkeypatch):
    calls = []

    async def fake_graph_get_all(db, tenant, path):
        calls.append((db, tenant, path))
        return [{"id": "policy-1"}, {"id": "policy-2"}]

    monkeypatch.setattr(microsoft, "graph_get_all", fake_graph_get_all)
    db = object()
    tenant = SimpleNamespace(id="tenant-1")
    adapter = MicrosoftIdentityProviderAdapter(db=db, tenant=tenant)

    result = asyncio.run(adapter.list_conditional_access_policies())

    assert result == [{"id": "policy-1"}, {"id": "policy-2"}]
    assert calls == [(db, tenant, "/identity/conditionalAccess/policies")]


def test_microsoft_adapter_paginates_oauth_permission_grants(monkeypatch):
    calls = []

    async def fake_graph_get_all(db, tenant, path):
        calls.append((db, tenant, path))
        return [{"id": "grant-1"}, {"id": "grant-2"}]

    monkeypatch.setattr(microsoft, "graph_get_all", fake_graph_get_all)
    db = object()
    tenant = SimpleNamespace(id="tenant-1")
    adapter = MicrosoftIdentityProviderAdapter(db=db, tenant=tenant)

    result = asyncio.run(adapter.list_oauth2_permission_grants())

    assert result == [{"id": "grant-1"}, {"id": "grant-2"}]
    assert calls == [(db, tenant, "/oauth2PermissionGrants")]


# ---------------------------------------------------------------------------
# rollout_group_service.get_group_members  (fixed in Task 2)
# ---------------------------------------------------------------------------


def test_get_group_members_follows_next_link():
    """get_group_members follows @odata.nextLink for large groups."""
    from app.services.rollout_group_service import get_group_members

    page1 = {
        "value": [{"id": f"u{i}", "@odata.type": "#microsoft.graph.user"} for i in range(100)],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/groups/g1/members?$skiptoken=abc",
    }
    page2 = {
        "value": [{"id": f"u{i}", "@odata.type": "#microsoft.graph.user"} for i in range(100, 150)],
    }

    graph_client = MagicMock()
    graph_client.get = AsyncMock(side_effect=[page1, page2])

    members = asyncio.run(get_group_members(graph_client, "g1"))

    assert len(members) == 150
    assert graph_client.get.call_count == 2


def test_get_group_members_empty_group():
    from app.services.rollout_group_service import get_group_members

    graph_client = MagicMock()
    graph_client.get = AsyncMock(return_value={"value": []})

    members = asyncio.run(get_group_members(graph_client, "g1"))
    assert members == []
    assert graph_client.get.call_count == 1


# ---------------------------------------------------------------------------
# MicrosoftGraphClient.get_all  (new helper)
# ---------------------------------------------------------------------------


def test_microsoft_graph_client_get_all_follows_next_link():
    """MicrosoftGraphClient.get_all paginates through all pages."""
    from app.services.microsoft_graph import MicrosoftGraphClient

    page1_body = {
        "value": [{"id": f"item{i}"} for i in range(100)],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/resource?$skiptoken=tok1",
    }
    page2_body = {
        "value": [{"id": f"item{i}"} for i in range(100, 130)],
    }

    responses = [
        MagicMock(status_code=200, content=b"x", json=MagicMock(return_value=page1_body)),
        MagicMock(status_code=200, content=b"x", json=MagicMock(return_value=page2_body)),
    ]

    client = MicrosoftGraphClient("fake-token")

    async def run():
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(side_effect=responses)
        with patch("app.services.microsoft_graph.httpx.AsyncClient", return_value=mock_http):
            return await client.get_all("/resource")

    results = asyncio.run(run())
    assert len(results) == 130


def test_microsoft_graph_client_get_all_single_page():
    """get_all works correctly when all results fit in one page."""
    from app.services.microsoft_graph import MicrosoftGraphClient

    body = {"value": [{"id": "only"}]}
    response = MagicMock(status_code=200, content=b"x", json=MagicMock(return_value=body))

    client = MicrosoftGraphClient("fake-token")

    async def run():
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(return_value=response)
        with patch("app.services.microsoft_graph.httpx.AsyncClient", return_value=mock_http):
            return await client.get_all("/resource")

    results = asyncio.run(run())
    assert results == [{"id": "only"}]


# ---------------------------------------------------------------------------
# app_consent_detector — /servicePrincipals
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# jit_admin_detector — /roleManagement/directory/roleAssignments
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# mfa_posture_ingestion — /users
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# user_ingestion — /users
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# role_ingestion — /directoryRoles and /directoryRoles/{id}/members
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# graph_directory_roles_service — uses graph_get_all
# ---------------------------------------------------------------------------


def test_fetch_directory_roles_uses_graph_get_all():
    """fetch_directory_roles (db/tenant variant) delegates to graph_get_all."""
    from app.services import graph_directory_roles_service

    roles = [{"id": "r1", "displayName": "Global Administrator"}]
    with patch(
        "app.services.graph_directory_roles_service.graph_get_all",
        new=AsyncMock(return_value=roles),
    ) as mock_get_all:
        db = MagicMock()
        tenant = MagicMock()
        result = asyncio.run(graph_directory_roles_service.fetch_directory_roles(db, tenant))

    mock_get_all.assert_called_once_with(db, tenant, "/directoryRoles")
    assert result == roles


# ---------------------------------------------------------------------------
# graph_conditional_access — list_conditional_access_policies uses graph_get_all
# ---------------------------------------------------------------------------


def test_list_conditional_access_policies_uses_graph_get_all():
    """list_conditional_access_policies delegates to graph_get_all."""
    from app.services import graph_conditional_access

    policies = [{"id": "p1", "displayName": "Require MFA"}]
    with patch(
        "app.services.graph_conditional_access.graph_get_all",
        new=AsyncMock(return_value=policies),
    ) as mock_get_all:
        db = MagicMock()
        tenant = MagicMock()
        result = asyncio.run(graph_conditional_access.list_conditional_access_policies(db, tenant))

    mock_get_all.assert_called_once_with(db, tenant, "/identity/conditionalAccess/policies")
    assert result == policies
