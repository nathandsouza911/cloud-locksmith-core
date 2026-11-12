from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from app.services.graph.graph_fetcher import GraphFetcher
from app.services.graph.tenant_graph_context import TenantGraphContext

TENANT_ID = "ca-test-tenant-123"
ACCESS_TOKEN = "fake-token"

_SAMPLE_POLICIES = [
    {
        "id": "policy-1",
        "displayName": "Test Policy",
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": {"builtInControls": ["mfa"]},
    }
]


def _make_mock_client(status_code: int, json_body: dict, raise_on_get: Exception | None = None):
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.raise_for_status = MagicMock(
        side_effect=Exception(f"HTTP {status_code}") if status_code >= 400 else None
    )
    mock_response.json.return_value = json_body

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    if raise_on_get:
        mock_client.get = AsyncMock(side_effect=raise_on_get)
    else:
        mock_client.get = AsyncMock(return_value=mock_response)
    return mock_client


def test_build_context_success():
    mock_client = _make_mock_client(200, {"value": _SAMPLE_POLICIES, "@odata.nextLink": None})
    with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=mock_client):
        ctx = asyncio.run(GraphFetcher().build_context(TENANT_ID, ACCESS_TOKEN))

    assert isinstance(ctx, TenantGraphContext)
    assert ctx.tenant_id == TENANT_ID
    assert ctx.conditional_access_policies == _SAMPLE_POLICIES
    assert ctx.break_glass_accounts == []


def test_build_context_with_break_glass_accounts():
    mock_client = _make_mock_client(200, {"value": [], "@odata.nextLink": None})
    bg_accounts = ["bg-user-id-1", "bg-user-id-2"]

    with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=mock_client):
        ctx = asyncio.run(GraphFetcher().build_context(TENANT_ID, ACCESS_TOKEN, break_glass_accounts=bg_accounts))

    assert ctx.break_glass_accounts == bg_accounts


def test_build_context_handles_failure():
    mock_client = _make_mock_client(200, {}, raise_on_get=Exception("Network error"))

    with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=mock_client):
        ctx = asyncio.run(GraphFetcher().build_context(TENANT_ID, ACCESS_TOKEN))

    # Must not crash — returns context with None policies
    assert isinstance(ctx, TenantGraphContext)
    assert ctx.tenant_id == TENANT_ID
    assert ctx.conditional_access_policies is None


def test_returns_none_on_api_error():
    mock_client = _make_mock_client(500, {}, raise_on_get=None)
    # raise_for_status is set to raise by _make_mock_client for 5xx
    with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=mock_client):
        ctx = asyncio.run(GraphFetcher().build_context(TENANT_ID, ACCESS_TOKEN))

    assert ctx.conditional_access_policies is None


def test_build_context_handles_403_as_none():
    # 403 on CA policies → must produce None (evaluation failed), not [] (zero policies)
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.raise_for_status = MagicMock(side_effect=Exception("HTTP 403"))
    mock_response.json.return_value = {}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=mock_client):
        ctx = asyncio.run(GraphFetcher().build_context(TENANT_ID, ACCESS_TOKEN))

    assert (
        ctx.conditional_access_policies is None
    ), "403 must produce None so detectors distinguish 'fetch failed' from 'zero policies'"
