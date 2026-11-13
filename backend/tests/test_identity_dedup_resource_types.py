import asyncio

import pytest

from app.services import identity_dedup
from app.services.identity_dedup import upsert_control_result


class _NoDb:
    """Fails the test if the upsert reaches the database."""

    async def execute(self, *args, **kwargs):
        raise AssertionError("must be refused before any query")


def test_service_principal_finding_requires_explicit_resource_id(monkeypatch):
    # Falling back to the tenant id would collapse every service principal into one row.
    monkeypatch.setattr(identity_dedup, "compliance_results_has_resource_id", lambda: True)

    with pytest.raises(ValueError, match="resource_id required"):
        asyncio.run(
            upsert_control_result(
                _NoDb(),
                tenant_id="tenant-1",
                control_id="IDENTITY_STALE_SERVICE_PRINCIPAL",
                passed=False,
                severity="MEDIUM",
                evidence={"sp_id": "sp-1"},
                resource_type="SERVICE_PRINCIPAL",
            )
        )


def test_unknown_resource_type_is_still_refused(monkeypatch):
    monkeypatch.setattr(identity_dedup, "compliance_results_has_resource_id", lambda: True)

    with pytest.raises(ValueError, match="unsupported resource_type"):
        asyncio.run(
            upsert_control_result(
                _NoDb(),
                tenant_id="tenant-1",
                control_id="IDENTITY_STALE_SERVICE_PRINCIPAL",
                passed=False,
                severity="MEDIUM",
                evidence={},
                resource_id="x",
                resource_type="DEVICE",
            )
        )


def test_service_principal_remediation_is_audited_as_a_service_principal():
    from app.services.remediation_executor import _resource_metadata

    evidence = {"resource_type": "SERVICE_PRINCIPAL", "resource_id": "sp-1", "sp_id": "sp-1"}

    assert _resource_metadata(evidence) == ("SERVICE_PRINCIPAL", "sp-1")


def test_user_and_tenant_audit_metadata_unchanged():
    from app.services.remediation_executor import _resource_metadata

    assert _resource_metadata({"resource_type": "USER", "resource_id": "u-1", "user_id": "u-1"}) == ("USER", "u-1")
    assert _resource_metadata({"resource_type": "TENANT", "resource_id": "t-1"}) == ("TENANT", "t-1")
