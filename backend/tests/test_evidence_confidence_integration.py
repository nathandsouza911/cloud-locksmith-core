import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.db.models.verification_lifecycle import RemediationVerification
from app.services.insurance.evidence_report_builder import (
    build_evidence_report,
    _build_section_verification,
)


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    from app.db.base import Base

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def _fake_rv(status: str, control_id: str = "CA_MFA_ALL_USERS") -> MagicMock:
    rv = MagicMock()
    rv.status = status
    rv.verification_count = 2
    rv.first_verified_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rv.last_verified_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
    return rv


class TestSectionVerificationConfidenceTiers:
    def test_verified_confirmed_entry_has_tier_a(self):
        v_states = {"CA_MFA_ALL_USERS": _fake_rv("VERIFIED_CONFIRMED")}
        rows = _build_section_verification(v_states)
        assert len(rows) == 1
        assert rows[0]["evidence_tier"] == "A"
        assert rows[0]["evidence_classification"] == "Verified & Confirmed"

    def test_verified_provisional_entry_has_tier_b(self):
        v_states = {"CA_MFA_ADMINS": _fake_rv("VERIFIED_PROVISIONAL", "CA_MFA_ADMINS")}
        rows = _build_section_verification(v_states)
        assert rows[0]["evidence_tier"] == "B"
        assert rows[0]["evidence_classification"] == "Verified & Provisional"

    def test_drift_detected_entry_has_tier_d(self):
        v_states = {"CA_LEGACY_AUTH_BLOCK": _fake_rv("DRIFT_DETECTED", "CA_LEGACY_AUTH_BLOCK")}
        rows = _build_section_verification(v_states)
        assert rows[0]["evidence_tier"] == "D"
        assert rows[0]["evidence_classification"] == "Drift Detected"

    def test_verification_label_still_uses_canonical_display_label(self):
        v_states = {"CA_MFA_ALL_USERS": _fake_rv("VERIFIED_CONFIRMED")}
        rows = _build_section_verification(v_states)
        # Must be the human label, not the raw status string
        assert rows[0]["verification_status"] == "Verified (Confirmed)"

    def test_identity_admin_no_mfa_shows_not_applicable_tier(self):
        """IDENTITY_ADMIN_NO_MFA has verification_supported=False → N/A tier."""
        v_states = {"IDENTITY_ADMIN_NO_MFA": _fake_rv("VERIFIED_CONFIRMED", "IDENTITY_ADMIN_NO_MFA")}
        rows = _build_section_verification(v_states)
        assert rows[0]["evidence_tier"] == "N/A"
        assert rows[0]["evidence_classification"] == "Not Applicable"


class TestReportUnderwriterSummaryBlock:
    def test_report_contains_underwriter_summary_key(self):
        db = _make_db()
        try:
            tenant = Tenant(id="t-summary", tenant_name="Test Tenant")
            db.add(tenant)
            db.commit()
            report = build_evidence_report(db, tenant, "t-summary")
            assert "underwriter_summary" in report, "build_evidence_report must include 'underwriter_summary' key"
        finally:
            db.close()

    def test_underwriter_summary_has_required_keys(self):
        db = _make_db()
        try:
            tenant = Tenant(id="t-summary-keys", tenant_name="Keys Tenant")
            db.add(tenant)
            db.commit()
            report = build_evidence_report(db, tenant, "t-summary-keys")
            us = report["underwriter_summary"]
            required = {
                "tenant_name",
                "controls_evaluated",
                "controls_verified",
                "overall_confidence_tier",
                "overall_confidence_label",
                "posture_statement",
                "drift_notice",
                "score",
                "score_band",
            }
            missing = required - set(us.keys())
            assert not missing, f"underwriter_summary missing keys: {missing}"
        finally:
            db.close()


class TestDriftTierAggregationAlignment:
    """Verify that controls_drifted and overall_confidence_tier == 'D' agree.

    Invariant under test: controls_drifted comes from build_verification_coverage()
    (raw DRIFT_DETECTED count) and overall_confidence_tier comes from
    _section_verification tier-D counts (which apply the verification_supported gate).
    Controls with verification_supported=False never reach DRIFT_DETECTED via the
    verification engine, so the two paths cannot diverge. This test confirms they
    both register when a verification-supported control drifts.
    """

    def test_drifted_control_surfaces_in_both_controls_drifted_and_tier_d(self):
        """End-to-end: one DRIFT_DETECTED row → controls_drifted > 0 AND tier == 'D'."""
        # Import all models so Base.metadata includes every table (including
        # remediation_audit_logs, which RemediationVerification has an FK to).
        import app.db.models  # noqa: F401 — registers all tables with Base

        engine = create_engine("sqlite:///:memory:")
        from app.db.base import Base

        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()
        try:
            tenant = Tenant(id="t-drift-align", tenant_name="Drift Align Tenant")
            db.add(tenant)
            # A ComplianceResult row is required so that CA_MFA_ALL_USERS appears in
            # control_ids_evaluated; build_verification_coverage only queries controls
            # that have compliance results.
            cr = ComplianceResult(
                tenant_id="t-drift-align",
                control_id="CA_MFA_ALL_USERS",
                passed=True,
                severity="HIGH",
                evidence={},
                evaluated_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
            )
            db.add(cr)
            db.commit()

            # Insert a RemediationVerification row for a verification-supported control.
            # CA_MFA_ALL_USERS has verification_supported=True in CONTROL_REGISTRY.
            # SQLite does not enforce FK constraints by default, so execution_id and
            # compliance_result_id can reference non-existent parent rows.
            rv = RemediationVerification(
                id=str(uuid.uuid4()),
                execution_id=str(uuid.uuid4()),  # no parent row needed in SQLite
                tenant_id="t-drift-align",
                compliance_result_id=1,  # no parent row needed in SQLite
                control_id="CA_MFA_ALL_USERS",
                status="DRIFT_DETECTED",
                verification_count=1,
                confidence=0.0,
            )
            db.add(rv)
            db.commit()

            report = build_evidence_report(db, tenant, "t-drift-align")
            us = report["underwriter_summary"]

            assert (
                us["controls_drifted"] > 0
            ), "controls_drifted must be > 0 when a DRIFT_DETECTED verification row exists"
            assert us["overall_confidence_tier"] == "D", (
                f"overall_confidence_tier must be 'D' when a control is drifted, "
                f"got {us['overall_confidence_tier']!r}"
            )
        finally:
            db.close()
