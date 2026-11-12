import uuid

from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult, ExposureStatus, ResolutionSource
from app.db.models.msp_security_baseline import BaselineConfig
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.services.baseline.baseline_enforcement_service import (
    apply_baseline_configuration,
)
from app.services.finding_cleanup import resolve_non_baseline_findings_sync


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


def test_apply_baseline_configuration_does_not_execute_or_reset_failed_findings():
    engine = create_engine("sqlite:///:memory:")
    BaselineConfig.__table__.create(engine)
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    PostureSnapshot.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    organization_uuid = uuid.uuid4()
    organization_id = str(organization_uuid)
    tenant = Tenant(
        id="tenant-123",
        tenant_name="Tenant 123",
        organization_id=organization_uuid,
    )
    session.add(tenant)
    session.commit()

    failed_finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id=tenant.id,
        passed=False,
        severity="MEDIUM",
        evidence={},
        decision_status="FAILED",
        remediation_status="FAILED",
    )
    session.add(failed_finding)
    session.commit()

    result = apply_baseline_configuration(
        session,
        organization_id=organization_id,
        baseline_name="Secure Identity",
        controls=[
            "IDENTITY_GUEST_INVITES_OPEN",
            "IDENTITY_GUEST_INVITES_OPEN",
            "UNSUPPORTED_CONTROL",
        ],
    )

    session.refresh(failed_finding)
    stored = session.query(BaselineConfig).one()

    assert result["status"] == "baseline_applied"
    assert result["tenant_ids"] == [tenant.id]
    assert stored.controls == ["IDENTITY_GUEST_INVITES_OPEN"]
    assert failed_finding.remediation_status.value == "FAILED"
    assert failed_finding.decision_status == "FAILED"

    session.close()


def test_removed_baseline_controls_are_resolved_instead_of_deleted():
    engine = create_engine("sqlite:///:memory:")
    BaselineConfig.__table__.create(engine)
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    PostureSnapshot.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    organization_uuid = uuid.uuid4()
    tenant = Tenant(
        id="tenant-456",
        tenant_name="Tenant 456",
        organization_id=organization_uuid,
    )
    session.add(tenant)
    session.commit()

    stale_finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="USER",
        resource_id="user-1",
        passed=False,
        severity="MEDIUM",
        evidence={"user_id": "user-1"},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    in_scope_finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_ADMIN_NO_MFA",
        resource_type="USER",
        resource_id="user-2",
        passed=False,
        severity="CRITICAL",
        evidence={"user_id": "user-2"},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add_all([stale_finding, in_scope_finding])
    session.commit()

    resolved_count = resolve_non_baseline_findings_sync(
        session,
        tenant_id=tenant.id,
        baseline_controls=["IDENTITY_ADMIN_NO_MFA"],
    )
    session.commit()
    session.refresh(stale_finding)
    session.refresh(in_scope_finding)

    assert resolved_count == 1
    assert stale_finding.exposure_status.value == ExposureStatus.RESOLVED.value
    assert stale_finding.resolved_by.value == ResolutionSource.BASELINE_UPDATE.value
    assert stale_finding.resolved_at is not None
    assert in_scope_finding.exposure_status.value == ExposureStatus.ACTIVE.value

    session.close()
