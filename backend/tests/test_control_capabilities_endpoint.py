import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace


@pytest.mark.asyncio
async def test_capabilities_includes_ca_license_available_true():
    """When check_ca_license_from_skus returns True, response includes ca_license_available=True."""
    from app.api.v1.control import get_control_capabilities_endpoint, _CA_CAPABILITY_KEY

    mock_capabilities = {
        _CA_CAPABILITY_KEY: {
            "detect": True,
            "remediate": True,
            "mode": "manual",
            "allowed": True,
            "reason": "requires_approval",
            "notes": "test",
        }
    }

    mock_adapter = MagicMock()
    mock_adapter.get_control_capabilities.return_value = mock_capabilities

    mock_db = MagicMock()
    mock_tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    with (
        patch("app.services.identity_providers.get_identity_provider_adapter", return_value=mock_adapter),
        patch("app.services.remediation_executor.RemediationGraphClient"),
        patch("app.services.license_check_service.check_ca_license_from_skus", new=AsyncMock(return_value=True)),
    ):
        result = await get_control_capabilities_endpoint(
            db=mock_db,
            current_tenant=mock_tenant,
        )

    assert result[_CA_CAPABILITY_KEY]["ca_license_available"] is True
    assert "license_note" not in result[_CA_CAPABILITY_KEY]


@pytest.mark.asyncio
async def test_capabilities_includes_license_note_when_ca_license_unavailable():
    """When check_ca_license_from_skus returns False, response includes license_note."""
    from app.api.v1.control import get_control_capabilities_endpoint, _CA_CAPABILITY_KEY, _CA_LICENSE_NOTE

    mock_capabilities = {
        _CA_CAPABILITY_KEY: {
            "detect": True,
            "remediate": True,
            "mode": "manual",
            "allowed": True,
            "reason": "requires_approval",
            "notes": "test",
        }
    }

    mock_adapter = MagicMock()
    mock_adapter.get_control_capabilities.return_value = mock_capabilities

    mock_db = MagicMock()
    mock_tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    with (
        patch("app.services.identity_providers.get_identity_provider_adapter", return_value=mock_adapter),
        patch("app.services.remediation_executor.RemediationGraphClient"),
        patch("app.services.license_check_service.check_ca_license_from_skus", new=AsyncMock(return_value=False)),
    ):
        result = await get_control_capabilities_endpoint(
            db=mock_db,
            current_tenant=mock_tenant,
        )

    assert result[_CA_CAPABILITY_KEY]["ca_license_available"] is False
    assert result[_CA_CAPABILITY_KEY]["license_note"] == _CA_LICENSE_NOTE


@pytest.mark.asyncio
async def test_break_glass_exclusion_stamped_license_unavailable():
    """CA_BREAK_GLASS_EXCLUSION must be license-gated exactly like the other CA
    controls: when the tenant lacks CA licensing it gets ca_license_available=False
    plus the license_note, so the UI can render 'License Required'."""
    from app.api.v1.control import (
        get_control_capabilities_endpoint,
        _CA_CAPABILITY_KEY,
        _CA_LICENSE_NOTE,
    )

    def _cap(notes):
        return {
            "detect": True,
            "remediate": True,
            "mode": "manual",
            "allowed": True,
            "reason": "requires_approval",
            "notes": notes,
        }

    mock_capabilities = {
        _CA_CAPABILITY_KEY: _cap("ca chain"),
        "CA_BREAK_GLASS_EXCLUSION": _cap("break glass"),
    }

    mock_adapter = MagicMock()
    mock_adapter.get_control_capabilities.return_value = mock_capabilities

    mock_db = MagicMock()
    mock_tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    with (
        patch("app.services.identity_providers.get_identity_provider_adapter", return_value=mock_adapter),
        patch("app.services.remediation_executor.RemediationGraphClient"),
        patch("app.services.license_check_service.check_ca_license_from_skus", new=AsyncMock(return_value=False)),
    ):
        result = await get_control_capabilities_endpoint(
            db=mock_db,
            current_tenant=mock_tenant,
        )

    assert result["CA_BREAK_GLASS_EXCLUSION"]["ca_license_available"] is False
    assert result["CA_BREAK_GLASS_EXCLUSION"]["license_note"] == _CA_LICENSE_NOTE


@pytest.mark.asyncio
async def test_break_glass_exclusion_stamped_license_available():
    """When the tenant IS CA-licensed, CA_BREAK_GLASS_EXCLUSION is actionable:
    ca_license_available=True and no license_note."""
    from app.api.v1.control import get_control_capabilities_endpoint, _CA_CAPABILITY_KEY

    def _cap(notes):
        return {
            "detect": True,
            "remediate": True,
            "mode": "manual",
            "allowed": True,
            "reason": "requires_approval",
            "notes": notes,
        }

    mock_capabilities = {
        _CA_CAPABILITY_KEY: _cap("ca chain"),
        "CA_BREAK_GLASS_EXCLUSION": _cap("break glass"),
    }

    mock_adapter = MagicMock()
    mock_adapter.get_control_capabilities.return_value = mock_capabilities

    mock_db = MagicMock()
    mock_tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    with (
        patch("app.services.identity_providers.get_identity_provider_adapter", return_value=mock_adapter),
        patch("app.services.remediation_executor.RemediationGraphClient"),
        patch("app.services.license_check_service.check_ca_license_from_skus", new=AsyncMock(return_value=True)),
    ):
        result = await get_control_capabilities_endpoint(
            db=mock_db,
            current_tenant=mock_tenant,
        )

    assert result["CA_BREAK_GLASS_EXCLUSION"]["ca_license_available"] is True
    assert "license_note" not in result["CA_BREAK_GLASS_EXCLUSION"]


@pytest.mark.asyncio
async def test_capabilities_fails_open_on_graph_error():
    """When graph client raises, ca_license_available defaults to True (fail open)."""
    from app.api.v1.control import get_control_capabilities_endpoint, _CA_CAPABILITY_KEY

    mock_capabilities = {
        _CA_CAPABILITY_KEY: {
            "detect": True,
            "remediate": True,
            "mode": "manual",
            "allowed": True,
            "reason": "requires_approval",
            "notes": "test",
        }
    }

    mock_adapter = MagicMock()
    mock_adapter.get_control_capabilities.return_value = mock_capabilities

    mock_db = MagicMock()
    mock_tenant = SimpleNamespace(id="tenant-1", provider="microsoft")

    with (
        patch("app.services.identity_providers.get_identity_provider_adapter", return_value=mock_adapter),
        patch("app.services.remediation_executor.RemediationGraphClient", side_effect=RuntimeError("no token")),
        patch("app.services.license_check_service.check_ca_license_from_skus", new=AsyncMock(return_value=False)),
    ):
        result = await get_control_capabilities_endpoint(
            db=mock_db,
            current_tenant=mock_tenant,
        )

    assert result[_CA_CAPABILITY_KEY]["ca_license_available"] is True
