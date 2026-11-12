"""Phase A.5 Task 2 — IDENTITY_ILLICIT_CONSENT_GRANTS Insurance Alignment.

The control is CRITICAL severity, weight-20, fully executable and verifiable,
yet absent from every insurer-facing layer. These tests enforce the correct
alignment:

  1. Evidence report control_coverage includes it under Application Consent Controls.
  2. Insurance readiness scoring treats failure as a material finding.
  3. Remediation history shows a correct action phrase and rollback status.
"""

from datetime import datetime, timezone
from types import SimpleNamespace


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.db.models.offboarding_session import OffboardingSession
from app.db.models.audit_log import AuditLog
from app.db.models.report_payload import ReportPayload

CONTROL_ID = "IDENTITY_ILLICIT_CONSENT_GRANTS"

# ---------------------------------------------------------------------------
# Shared DB helpers
# ---------------------------------------------------------------------------


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    OffboardingSession.__table__.create(engine)
    AuditLog.__table__.create(engine)
    ReportPayload.__table__.create(engine)
    return sessionmaker(bind=engine)()


def _add_result(db, tenant_id, control_id, passed):
    db.add(
        ComplianceResult(
            tenant_id=tenant_id,
            control_id=control_id,
            passed=passed,
            severity="CRITICAL",
            evidence={},
            evaluated_at=datetime(2026, 6, 1, 12, 0, 0),
        )
    )


# ---------------------------------------------------------------------------
# Task 2.1 — Evidence report control coverage
# ---------------------------------------------------------------------------


def test_illicit_consent_grants_appears_in_application_consent_coverage():
    """A scanned ILLICIT_CONSENT_GRANTS result must mark Application Consent Controls as Evaluated."""
    from app.services.insurance.evidence_report_builder import build_evidence_report

    db = _make_session()
    try:
        t = Tenant(id="t-icg-cov", tenant_name="ICG Coverage Tenant")
        db.add(t)
        _add_result(db, t.id, CONTROL_ID, False)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        coverage = {c["category"]: c["status"] for c in report["control_coverage"]}
        assert (
            coverage.get("Application Consent Controls") == "Evaluated"
        ), "IDENTITY_ILLICIT_CONSENT_GRANTS must register in Application Consent Controls coverage"
    finally:
        db.close()


def test_application_consent_coverage_remains_not_evaluated_without_icg_or_consent_policy():
    """When neither consent control is scanned, Application Consent Controls stays Not Evaluated."""
    from app.services.insurance.evidence_report_builder import build_evidence_report

    db = _make_session()
    try:
        t = Tenant(id="t-icg-none", tenant_name="ICG None Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        coverage = {c["category"]: c["status"] for c in report["control_coverage"]}
        assert coverage.get("Application Consent Controls") == "Not Evaluated"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Task 2.2 — Insurance readiness scoring
# ---------------------------------------------------------------------------


def test_illicit_consent_grants_failure_is_material_finding():
    """IDENTITY_ILLICIT_CONSENT_GRANTS must be in MATERIAL_FINDING_CONTROLS."""
    from app.services.insurance.identity_insurance_readiness import MATERIAL_FINDING_CONTROLS

    assert (
        CONTROL_ID in MATERIAL_FINDING_CONTROLS
    ), "IDENTITY_ILLICIT_CONSENT_GRANTS (CRITICAL, weight-20) must be a material finding"


def test_illicit_consent_grants_failure_degrades_readiness_tier():
    """Failing ILLICIT_CONSENT_GRANTS with high score must NOT reach READY tier."""
    from app.services.insurance.identity_insurance_readiness import calculate_identity_insurance_readiness

    results = [
        SimpleNamespace(control_id=CONTROL_ID, passed=False),
        SimpleNamespace(control_id="IDENTITY_USER_NO_MFA", passed=True),
        SimpleNamespace(control_id="IDENTITY_ADMIN_NO_MFA", passed=True),
    ]
    readiness = calculate_identity_insurance_readiness(results, score=85)
    assert readiness["readiness"] != "READY", "A failing ILLICIT_CONSENT_GRANTS must prevent READY tier"


def test_illicit_consent_grants_passing_does_not_block_ready_tier():
    """Passing ILLICIT_CONSENT_GRANTS must not itself block READY."""
    from app.services.insurance.identity_insurance_readiness import calculate_identity_insurance_readiness

    results = [
        SimpleNamespace(control_id=CONTROL_ID, passed=True),
        SimpleNamespace(control_id="IDENTITY_USER_NO_MFA", passed=True),
        SimpleNamespace(control_id="IDENTITY_ADMIN_NO_MFA", passed=True),
    ]
    readiness = calculate_identity_insurance_readiness(results, score=85)
    assert readiness["readiness"] == "READY"


# ---------------------------------------------------------------------------
# Task 2.3 — Remediation history action phrase and rollback
# ---------------------------------------------------------------------------


def test_illicit_consent_grants_has_action_phrase():
    """_ACTION_PHRASES must contain an entry for IDENTITY_ILLICIT_CONSENT_GRANTS."""
    from app.services.insurance.remediation_history import _ACTION_PHRASES

    assert (
        CONTROL_ID in _ACTION_PHRASES
    ), "IDENTITY_ILLICIT_CONSENT_GRANTS must have a remediation history action phrase"
    assert _ACTION_PHRASES[CONTROL_ID], "Action phrase must be non-empty"


def test_illicit_consent_grants_rollback_available_in_history():
    """Executed (non-rolled-back) ILLICIT_CONSENT_GRANTS row shows rollback as Available."""
    from app.services.insurance.remediation_history import rows_to_remediation_history

    audit = SimpleNamespace(
        control_id=CONTROL_ID,
        executed_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        verified_at=None,
        rolled_back=False,
    )
    result = rows_to_remediation_history([audit], current_state={CONTROL_ID: True})
    row = result["rows"][0]
    assert (
        row["rollback_available"] == "Available"
    ), "IDENTITY_ILLICIT_CONSENT_GRANTS has_rollback=True — should show Available in history"


def test_illicit_consent_grants_rolled_back_shows_reversed():
    """Rolled-back ILLICIT_CONSENT_GRANTS shows Reversed."""
    from app.services.insurance.remediation_history import rows_to_remediation_history

    audit = SimpleNamespace(
        control_id=CONTROL_ID,
        executed_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        verified_at=None,
        rolled_back=True,
    )
    result = rows_to_remediation_history([audit], current_state={CONTROL_ID: False})
    row = result["rows"][0]
    assert row["rollback_available"] == "Reversed"


def test_illicit_consent_grants_appears_in_db_remediation_history():
    """build_remediation_history must return an EXECUTED ICG row from the real DB."""
    from app.services.insurance.remediation_history import build_remediation_history

    engine = create_engine("sqlite:///:memory:")
    RemediationAuditLog.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        db.add(
            RemediationAuditLog(
                compliance_result_id=1,
                tenant_id="t-icg-hist",
                control_id=CONTROL_ID,
                resource_type="TENANT",
                resource_id="t-icg-hist",
                decision="APPROVED",
                execution_status="EXECUTED",
                executed_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
                rolled_back=False,
            )
        )
        db.commit()
        result = build_remediation_history(
            db,
            tenant_id="t-icg-hist",
            window_days=90,
            current_state={CONTROL_ID: True},
        )
        assert len(result["rows"]) == 1
        assert result["rows"][0]["control_id"] == CONTROL_ID
    finally:
        db.close()
