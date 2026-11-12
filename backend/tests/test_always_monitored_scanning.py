"""Parts 2 & 3 — scanner-level effects of the effective control set.

These compose resolve_effective_scan_controls with the finding-cleanup pass
the scanner runs, proving:
  * always-monitored findings survive even when excluded from the customer
    baseline, and
  * licence-gated CA findings are resolved (not left as active FAILs) for an
    unlicensed tenant.
"""

import uuid

from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.services.baseline_service import resolve_effective_scan_controls
from app.services.finding_cleanup import resolve_non_baseline_findings_sync


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


def _session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    return sessionmaker(bind=engine)()


def _finding(session, tenant_id, control_id):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=tenant_id,
        passed=False,
        severity="HIGH",
        evidence={},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def test_always_monitored_findings_survive_baseline_cleanup():
    session = _session()
    tenant = Tenant(id="t1", tenant_name="T1", organization_id=uuid.uuid4())
    session.add(tenant)
    session.commit()

    bg_usage = _finding(session, tenant.id, "IDENTITY_BREAK_GLASS_USAGE")
    ca_exclusion = _finding(session, tenant.id, "CA_BREAK_GLASS_EXCLUSION")
    off_baseline = _finding(session, tenant.id, "IDENTITY_GUEST_INVITES_OPEN")

    # Customer baseline excludes the always-monitored controls.
    customer_baseline = {"IDENTITY_USER_NO_MFA"}
    effective = resolve_effective_scan_controls(customer_baseline, ca_licensed=True)

    resolve_non_baseline_findings_sync(session, tenant_id=tenant.id, baseline_controls=effective)
    session.commit()
    for f in (bg_usage, ca_exclusion, off_baseline):
        session.refresh(f)

    # Always-monitored findings remain active.
    assert bg_usage.exposure_status.value == ExposureStatus.ACTIVE.value
    assert ca_exclusion.exposure_status.value == ExposureStatus.ACTIVE.value
    # A genuinely off-baseline finding is resolved.
    assert off_baseline.exposure_status.value == ExposureStatus.RESOLVED.value
    session.close()


def test_unlicensed_ca_finding_is_resolved_not_left_failing():
    session = _session()
    tenant = Tenant(id="t2", tenant_name="T2", organization_id=uuid.uuid4())
    session.add(tenant)
    session.commit()

    ca_finding = _finding(session, tenant.id, "CA_MFA_ALL_USERS")

    # Customer selected the CA control, but the tenant is unlicensed.
    customer_baseline = {"CA_MFA_ALL_USERS", "IDENTITY_USER_NO_MFA"}
    effective = resolve_effective_scan_controls(customer_baseline, ca_licensed=False)
    assert "CA_MFA_ALL_USERS" not in effective

    resolve_non_baseline_findings_sync(session, tenant_id=tenant.id, baseline_controls=effective)
    session.commit()
    session.refresh(ca_finding)

    # The unlicensed CA finding is resolved (no longer an active FAIL).
    assert ca_finding.exposure_status.value == ExposureStatus.RESOLVED.value
    assert ca_finding.passed is True
    session.close()
