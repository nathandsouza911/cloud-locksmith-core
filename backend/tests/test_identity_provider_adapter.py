import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.graph_ingestion import ingest_tenant_graph_data
from app.services.identity_providers import (
    GoogleWorkspaceAdapter,
    MicrosoftIdentityProviderAdapter,
    UnsupportedIdentityProviderError,
    get_identity_provider_adapter,
)
from app.services.remediation_executor import RemediationGraphClient


def test_factory_returns_microsoft_adapter_for_microsoft_provider():
    tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    adapter = get_identity_provider_adapter(db=object(), tenant=tenant)

    assert isinstance(adapter, MicrosoftIdentityProviderAdapter)
    assert adapter.tenant is tenant


def test_factory_returns_google_adapter_for_google_provider():
    tenant = SimpleNamespace(id="tenant-1", provider="google")

    adapter = get_identity_provider_adapter(db=object(), tenant=tenant)

    assert isinstance(adapter, GoogleWorkspaceAdapter)
    assert adapter.tenant is tenant


def test_factory_rejects_unknown_provider():
    tenant = SimpleNamespace(id="tenant-1", provider="okta")

    with pytest.raises(
        UnsupportedIdentityProviderError,
        match="Unsupported identity provider: okta",
    ):
        get_identity_provider_adapter(db=object(), tenant=tenant)


def test_ingest_tenant_graph_data_delegates_to_provider_adapter(monkeypatch):
    tenant = SimpleNamespace(id="tenant-1", provider="microsoft")
    adapter = SimpleNamespace(ingest_tenant_data=AsyncMock())

    monkeypatch.setattr(
        "app.services.graph_ingestion.get_identity_provider_adapter",
        lambda **kwargs: adapter,
    )

    asyncio.run(ingest_tenant_graph_data(tenant, object()))

    adapter.ingest_tenant_data.assert_awaited_once()


def test_microsoft_adapter_ingest_tenant_data_validates_token(monkeypatch):
    tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    monkeypatch.setattr(
        "app.services.identity_providers.microsoft.has_delegated_oauth_token",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "app.services.identity_providers.microsoft.get_valid_access_token",
        AsyncMock(return_value="header.payload.signature"),
    )

    adapter = MicrosoftIdentityProviderAdapter(db=object(), tenant=tenant)
    asyncio.run(adapter.ingest_tenant_data())


def test_microsoft_adapter_ingest_tenant_data_raises_when_no_token(monkeypatch):
    tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    monkeypatch.setattr(
        "app.services.identity_providers.microsoft.has_delegated_oauth_token",
        AsyncMock(return_value=False),
    )

    adapter = MicrosoftIdentityProviderAdapter(db=object(), tenant=tenant)
    with pytest.raises(Exception, match="no OAuth token"):
        asyncio.run(adapter.ingest_tenant_data())


def test_remediation_graph_client_delegates_and_preserves_context(monkeypatch):
    tenant = SimpleNamespace(id="tenant-1")
    adapter = SimpleNamespace(
        get=AsyncMock(return_value={"ok": True}),
        marker="adapter-marker",
    )

    monkeypatch.setattr(
        "app.services.remediation_executor.get_identity_provider_adapter",
        lambda **kwargs: adapter,
    )

    graph_client = RemediationGraphClient(db="db-session", tenant=tenant)
    result = asyncio.run(graph_client.get("/users"))

    assert graph_client.db == "db-session"
    assert graph_client.tenant is tenant
    assert graph_client.adapter is adapter
    assert graph_client.marker == "adapter-marker"
    assert result == {"ok": True}
    adapter.get.assert_awaited_once_with("/users")
