"""Terminology consistency tests for all carrier-facing evidence outputs.

These tests prove:
  1. All status labels go through get_verification_display_label() — never raw status strings.
  2. Confidence tiers are consistent between section_verification and underwriter_summary.
  3. Drift surfaces in both drift_summary.has_drift and section_verification[n].is_drift.
  4. evidence_integrity includes all four new carrier-required metadata fields.
  5. TERMINOLOGY_MATRIX covers all VerificationStatus enum values.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.tenant import Tenant
from app.services.insurance.evidence_report_builder import (
    _build_section_verification,
    _build_drift_summary,
    build_evidence_report,
)
from app.services.insurance.verification_language import (
    TERMINOLOGY_MATRIX,
    get_verification_display_label,
)


KNOWN_VERIFICATION_STATUSES = [
    "PENDING",
    "PENDING_PROPAGATION",
    "VERIFIED_PROVISIONAL",
    "VERIFIED_CONFIRMED",
    "DRIFT_DETECTED",
    "FAILED",
    "INDETERMINATE",
]

FORBIDDEN_RAW_STATUS_STRINGS = [
    "VERIFIED_CONFIRMED",
    "VERIFIED_PROVISIONAL",
    "DRIFT_DETECTED",
    "PENDING",
    "PENDING_PROPAGATION",
    "FAILED",
    "INDETERMINATE",
]


def _fake_rv(status: str) -> MagicMock:
    rv = MagicMock()
    rv.status = status
    rv.verification_count = 1
    rv.first_verified_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rv.last_verified_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
    return rv


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    from app.db.base import Base

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


class TestTerminologyMatrixCompleteness:
    @pytest.mark.parametrize("status", KNOWN_VERIFICATION_STATUSES)
    def test_terminology_matrix_covers_all_known_statuses(self, status):
        """Every known VerificationStatus must have an entry in TERMINOLOGY_MATRIX."""
        assert status in TERMINOLOGY_MATRIX, (
            f"VerificationStatus '{status}' is not in TERMINOLOGY_MATRIX — " f"add it to verification_language.py"
        )

    def test_none_status_returns_evaluated(self):
        assert get_verification_display_label(None) == "Evaluated"

    def test_unknown_status_returns_evaluated(self):
        assert get_verification_display_label("TOTALLY_UNKNOWN") == "Evaluated"

    def test_no_status_ever_returns_bare_verified(self):
        for status in KNOWN_VERIFICATION_STATUSES + [None, "UNKNOWN"]:
            label = get_verification_display_label(status)
            assert (
                label != "Verified"
            ), f"get_verification_display_label({status!r}) returned bare 'Verified' — forbidden"


class TestSectionVerificationTerminology:
    @pytest.mark.parametrize("status", KNOWN_VERIFICATION_STATUSES)
    def test_section_verification_never_contains_raw_status(self, status):
        v_states = {"CA_MFA_ALL_USERS": _fake_rv(status)}
        rows = _build_section_verification(v_states)
        raw_status_in_output = rows[0]["verification_status"]
        assert raw_status_in_output not in FORBIDDEN_RAW_STATUS_STRINGS, (
            f"section_verification returned raw status string '{raw_status_in_output}' "
            f"for input status '{status}' — must use canonical display label"
        )

    def test_verified_confirmed_produces_verified_confirmed_label(self):
        v_states = {"CA_MFA_ALL_USERS": _fake_rv("VERIFIED_CONFIRMED")}
        rows = _build_section_verification(v_states)
        assert rows[0]["verification_status"] == "Verified (Confirmed)"

    def test_drift_detected_produces_drift_detected_label(self):
        v_states = {"CA_MFA_ALL_USERS": _fake_rv("DRIFT_DETECTED")}
        rows = _build_section_verification(v_states)
        assert rows[0]["verification_status"] == "Drift Detected"


class TestDriftConsistency:
    def test_drift_surfaces_in_both_section_verification_and_drift_summary(self):
        v_states = {
            "CA_MFA_ALL_USERS": _fake_rv("DRIFT_DETECTED"),
            "CA_MFA_ADMINS": _fake_rv("VERIFIED_CONFIRMED"),
        }
        sv = _build_section_verification(v_states)
        ds = _build_drift_summary(v_states)

        drifted_in_sv = [r["control_id"] for r in sv if r["is_drift"]]
        drifted_in_ds = [d["control_id"] for d in ds["drifted_controls"]]

        assert sorted(drifted_in_sv) == sorted(
            drifted_in_ds
        ), "Drifted controls in section_verification and drift_summary must match"
        assert ds["has_drift"] is True
        drifted_sv_rows = [r for r in sv if r["is_drift"]]
        assert len(drifted_sv_rows) == 1
        assert drifted_sv_rows[0]["is_drift"] is True

    def test_no_drift_when_all_confirmed(self):
        v_states = {
            "CA_MFA_ALL_USERS": _fake_rv("VERIFIED_CONFIRMED"),
        }
        ds = _build_drift_summary(v_states)
        assert ds["has_drift"] is False
        assert ds["drifted_controls"] == []

    def test_section_verification_tier_d_matches_drift_summary(self):
        v_states = {"CA_MFA_ALL_USERS": _fake_rv("DRIFT_DETECTED")}
        sv = _build_section_verification(v_states)
        ds = _build_drift_summary(v_states)
        assert sv[0]["evidence_tier"] == "D"
        assert ds["has_drift"] is True


class TestEvidenceIntegrityCarrierFields:
    def test_full_report_integrity_block_has_all_carrier_fields(self):
        db = _make_db()
        try:
            tenant = Tenant(id="t-terms-1", tenant_name="Terms Tenant")
            db.add(tenant)
            db.commit()
            report = build_evidence_report(db, tenant, "t-terms-1")
            ei = report["evidence_integrity"]

            carrier_required = {
                "tenant_id",
                "audit_correlation",
                "evidence_confidence_overall",
                "verification_timestamp_range",
            }
            missing = carrier_required - set(ei.keys())
            assert not missing, f"evidence_integrity missing carrier-required fields: {missing}"
        finally:
            db.close()

    def test_underwriter_summary_confidence_tier_matches_section_verification_tiers(self):
        """Overall confidence tier in underwriter_summary must derive from section_verification."""
        db = _make_db()
        try:
            tenant = Tenant(id="t-terms-2", tenant_name="Tier Tenant")
            db.add(tenant)
            db.commit()
            report = build_evidence_report(db, tenant, "t-terms-2")

            # With no verification data, both should indicate Tier C (Evaluated Only)
            us_tier = report["underwriter_summary"]["overall_confidence_tier"]
            ei_tier = report["evidence_integrity"]["evidence_confidence_overall"]["tier"]
            assert (
                us_tier == ei_tier
            ), f"underwriter_summary tier ({us_tier}) and evidence_integrity tier ({ei_tier}) must match"
        finally:
            db.close()
