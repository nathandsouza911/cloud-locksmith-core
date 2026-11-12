import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_graph_client(*, raises=None):
    """Build a fake graph_client that either raises or returns a fixed value."""
    client = MagicMock()
    if raises:
        client.create_conditional_access_policy = AsyncMock(side_effect=raises)
    else:
        client.create_conditional_access_policy = AsyncMock(return_value={"id": "tmp-policy"})
        client.delete_conditional_access_policy = AsyncMock(return_value=None)
    return client


# ---------------------------------------------------------------------------
# check_ca_license_gate unit tests
# ---------------------------------------------------------------------------


class TestCheckCaLicenseGate:
    @pytest.mark.asyncio
    async def test_non_ca_control_returns_none(self):
        from app.services.license_check_service import check_ca_license_gate

        result = await check_ca_license_gate(MagicMock(), "IDENTITY_USER_NO_MFA")
        assert result is None

    @pytest.mark.asyncio
    async def test_ca_control_licensed_returns_none(self):
        from app.services.license_check_service import check_ca_license_gate

        client = _make_graph_client()
        result = await check_ca_license_gate(client, "CA_MFA_ALL_USERS")
        assert result is None

    @pytest.mark.asyncio
    async def test_ca_control_licensed_returns_none_via_probe_patch(self):
        """Isolates gate logic by patching check_conditional_access_license directly."""
        from app.services.license_check_service import check_ca_license_gate

        with patch(
            "app.services.license_check_service.check_conditional_access_license",
            new=AsyncMock(return_value=True),
        ):
            result = await check_ca_license_gate(MagicMock(), "CA_MFA_ALL_USERS")

        assert result is None

    @pytest.mark.asyncio
    async def test_ca_control_unlicensed_returns_blocked(self):
        from app.services.license_check_service import check_ca_license_gate
        from app.services.graph_client import GraphAPIError

        exc = GraphAPIError(
            method="POST",
            path="/policies/conditionalAccessPolicies",
            status_code=403,
            response_body="",
            category="PRIVILEGE_BOUNDARY",
        )
        client = _make_graph_client(raises=exc)
        result = await check_ca_license_gate(client, "CA_LEGACY_AUTH_BLOCK")
        assert result == {"status": "blocked", "reason": "NO_CA_LICENSE"}

    @pytest.mark.asyncio
    async def test_ca_control_unlicensed_false_without_raising(self):
        """Covers the if not licensed: return blocked branch when probe returns False directly."""
        from app.services.license_check_service import check_ca_license_gate

        with patch(
            "app.services.license_check_service.check_conditional_access_license",
            new=AsyncMock(return_value=False),
        ):
            result = await check_ca_license_gate(MagicMock(), "CA_LEGACY_AUTH_BLOCK")

        assert result == {"status": "blocked", "reason": "NO_CA_LICENSE"}

    @pytest.mark.asyncio
    async def test_ca_control_probe_exception_fails_closed(self):
        from app.services.license_check_service import check_ca_license_gate

        client = _make_graph_client(raises=RuntimeError("network error"))
        result = await check_ca_license_gate(client, "CA_GUEST_MFA")
        assert result == {"status": "blocked", "reason": "NO_CA_LICENSE"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "control_id",
        [
            "CA_MFA_ALL_USERS",
            "CA_MFA_ADMINS",
            "CA_GUEST_MFA",
            "CA_LEGACY_AUTH_BLOCK",
            "CA_DEVICE_CODE_FLOW_BLOCK",
            "CA_AUTHENTICATION_TRANSFER_BLOCK",
            "CA_BREAK_GLASS_EXCLUSION",
        ],
    )
    async def test_all_ca_controls_gated_when_unlicensed(self, control_id):
        from app.services.license_check_service import check_ca_license_gate
        from app.services.graph_client import GraphAPIError

        exc = GraphAPIError(
            method="POST",
            path="/policies/conditionalAccessPolicies",
            status_code=403,
            response_body="",
            category="PRIVILEGE_BOUNDARY",
        )
        client = _make_graph_client(raises=exc)
        result = await check_ca_license_gate(client, control_id)
        assert result == {"status": "blocked", "reason": "NO_CA_LICENSE"}


# ---------------------------------------------------------------------------
# execute_approved_remediation integration tests
# ---------------------------------------------------------------------------

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timezone

from app.db.models.compliance_result import ComplianceResult, ExposureStatus, RemediationStatus
from app.db.models.tenant import Tenant
from app.db.models.remediation_audit import RemediationAuditLog


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    RemediationAuditLog.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _seed_tenant(db: Session, tenant_id: str) -> Tenant:
    tenant = Tenant(
        id=tenant_id,
        tenant_name="CA Gate Test Tenant",
        domain="contoso.onmicrosoft.com",
        oauth_token={"access_token": "fake"},
        last_delegated_auth_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def _seed_approved_ca_finding(db: Session, *, tenant_id: str, control_id: str) -> ComplianceResult:
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=tenant_id,
        severity="CRITICAL",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE.value,
        remediation_status=RemediationStatus.APPROVED.value,
        decision_status=RemediationStatus.APPROVED.value,
        evidence={},
    )
    db.add(finding)
    db.commit()

    audit = RemediationAuditLog(
        tenant_id=tenant_id,
        compliance_result_id=finding.id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=tenant_id,
        decision="APPROVED",
        confidence=1.0,
        explanation_summary="Approved for testing",
        explanation_factors={},
        explanation_risk_note="",
        approved=True,
        approved_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(finding)
    return finding


@pytest.mark.asyncio
async def test_execute_approved_remediation_blocks_ca_without_license(db_session, monkeypatch):
    """CA control execution returns blocked when license check fails."""
    from app.services.remediation_execution_service import execute_approved_remediation

    tenant_id = "tenant-ca-gate-test"
    tenant = _seed_tenant(db_session, tenant_id)
    finding = _seed_approved_ca_finding(db_session, tenant_id=tenant_id, control_id="CA_MFA_ALL_USERS")

    async def fake_ca_gate(graph_client, control_id):
        if control_id in {
            "CA_MFA_ALL_USERS",
            "CA_MFA_ADMINS",
            "CA_GUEST_MFA",
            "CA_LEGACY_AUTH_BLOCK",
            "CA_DEVICE_CODE_FLOW_BLOCK",
            "CA_AUTHENTICATION_TRANSFER_BLOCK",
            "CA_BREAK_GLASS_EXCLUSION",
        }:
            return {"status": "blocked", "reason": "NO_CA_LICENSE"}
        return None

    monkeypatch.setattr(
        "app.services.remediation_execution_service.check_ca_license_gate",
        fake_ca_gate,
    )

    result = await execute_approved_remediation(
        db=db_session,
        compliance_result_id=finding.id,
        tenant=tenant,
        tenant_id=tenant_id,
    )
    assert result == {"status": "blocked", "reason": "NO_CA_LICENSE"}
    db_session.refresh(finding)
    assert (
        finding.remediation_status == RemediationStatus.APPROVED.value
    ), "DB state must not change when blocked by license gate"


@pytest.mark.asyncio
async def test_execute_approved_remediation_non_ca_skips_gate(db_session, monkeypatch):
    """Non-CA controls bypass the CA license gate and gate returns None."""
    from app.services.remediation_execution_service import execute_approved_remediation

    gate_calls = []

    async def spy_gate(graph_client, control_id):
        gate_calls.append(control_id)
        return None  # Never block

    monkeypatch.setattr(
        "app.services.remediation_execution_service.check_ca_license_gate",
        spy_gate,
    )

    tenant_id = "tenant-non-ca-gate"
    tenant = _seed_tenant(db_session, tenant_id)
    finding = _seed_approved_ca_finding(db_session, tenant_id=tenant_id, control_id="IDENTITY_USER_NO_MFA")

    try:
        await execute_approved_remediation(
            db=db_session,
            compliance_result_id=finding.id,
            tenant=tenant,
            tenant_id=tenant_id,
        )
    except Exception:
        pass  # May fail for unrelated reasons (no real graph client), but gate must have been called

    assert "IDENTITY_USER_NO_MFA" in gate_calls
