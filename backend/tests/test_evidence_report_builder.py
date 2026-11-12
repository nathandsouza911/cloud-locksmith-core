from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.audit_log import AuditLog
from app.db.models.compliance_result import ComplianceResult
from app.db.models.offboarding_session import OffboardingSession, OffboardingSessionStatus
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.services.insurance.evidence_report_builder import build_evidence_report


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    OffboardingSession.__table__.create(engine)
    AuditLog.__table__.create(engine)
    ReportPayload.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def test_evidence_report_counts_completed_user_offboarding_sessions():
    db = _make_session()
    try:
        tenant = Tenant(id="tenant-report", tenant_name="Report Tenant")
        db.add(tenant)
        db.add(
            OffboardingSession(
                tenant_id=tenant.id,
                control_id="USER_OFFBOARDING",
                resource_id="user-1",
                status=OffboardingSessionStatus.COMPLETED,
                steps=[],
            )
        )
        db.commit()

        report = build_evidence_report(db, tenant, tenant.id)

        assert report["section_offboarding"]["secure_exits"] == 1
    finally:
        db.close()


def test_evidence_report_ignores_reversed_user_offboarding_sessions():
    db = _make_session()
    try:
        tenant = Tenant(id="tenant-report-reversed", tenant_name="Report Tenant")
        db.add(tenant)
        db.add(
            OffboardingSession(
                tenant_id=tenant.id,
                control_id="USER_OFFBOARDING",
                resource_id="user-2",
                status=OffboardingSessionStatus.REVERSED,
                steps=[],
            )
        )
        db.commit()

        report = build_evidence_report(db, tenant, tenant.id)

        assert report["section_offboarding"]["secure_exits"] == 0
    finally:
        db.close()


def test_evidence_report_counts_sessions_with_completed_disable_step():
    db = _make_session()
    try:
        tenant = Tenant(id="tenant-report-progress", tenant_name="Report Tenant")
        db.add(tenant)
        db.add(
            OffboardingSession(
                tenant_id=tenant.id,
                control_id="USER_OFFBOARDING",
                resource_id="user-3",
                status=OffboardingSessionStatus.IN_PROGRESS,
                steps=[
                    {"action": "disable_account", "status": "completed"},
                ],
            )
        )
        db.commit()

        report = build_evidence_report(db, tenant, tenant.id)

        assert report["section_offboarding"]["secure_exits"] == 1
    finally:
        db.close()
