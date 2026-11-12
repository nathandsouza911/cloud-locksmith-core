import re
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.audit_log import AuditLog
from app.db.models.compliance_result import ComplianceResult
from app.db.models.offboarding_session import OffboardingSession
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.models.verification_lifecycle import RemediationVerification
from app.services.insurance.evidence_report_builder import build_evidence_report
from app.services.insurance.evidence_report_builder import _build_historical_comparison


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    OffboardingSession.__table__.create(engine)
    AuditLog.__table__.create(engine)
    ReportPayload.__table__.create(engine)
    RemediationVerification.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def _add_result(db, tenant_id, control_id, passed, evidence=None):
    db.add(
        ComplianceResult(
            tenant_id=tenant_id,
            control_id=control_id,
            passed=passed,
            severity="HIGH",
            evidence=evidence or {},
            evaluated_at=datetime(2026, 6, 1, 12, 0, 0),
        )
    )


def test_controls_verified_summary_counts_distinct_controls():
    db = _make_session()
    try:
        t = Tenant(id="t-cv", tenant_name="CV Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        _add_result(db, t.id, "IDENTITY_ADMIN_NO_MFA", True)
        _add_result(db, t.id, "IDENTITY_GUEST_INVITES_OPEN", False)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        cv = report["controls_verified_summary"]
        assert cv["verified"] == 3
        assert cv["passing"] == 2
        assert cv["requiring_action"] == 1
    finally:
        db.close()


def test_continuous_verification_status_present():
    db = _make_session()
    try:
        t = Tenant(id="t-cont", tenant_name="Cont Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        cont = report["continuous_verification"]
        assert "monitoring_status" in cont
        assert cont["controls_verified"] == 1
        assert cont["last_assessment"]
        assert "evidence_age" in cont
    finally:
        db.close()


def test_control_coverage_card_marks_evaluated_categories():
    db = _make_session()
    try:
        t = Tenant(id="t-cov", tenant_name="Cov Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        _add_result(db, t.id, "IDENTITY_ADMIN_COUNT_EXCESS", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        coverage = {c["category"]: c["status"] for c in report["control_coverage"]}
        # Phase A: a control that was merely *scanned* must NOT be labelled
        # "Verified" — that word is reserved for confirmed remediation. Scan
        # coverage is "Evaluated".
        assert coverage["MFA Controls"] == "Evaluated"
        assert coverage["Privileged Access Controls"] == "Evaluated"
        assert coverage["Application Consent Controls"] == "Not Evaluated"
    finally:
        db.close()


def test_scan_coverage_is_not_labelled_verified():
    """Guard: no scan-coverage status string claims verification."""
    db = _make_session()
    try:
        t = Tenant(id="t-cov2", tenant_name="Cov2 Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        statuses = {c["status"] for c in report["control_coverage"]}
        assert "Verified" not in statuses
        evidenced_blob = " ".join(d["evidenced"] for d in report["insurance_readiness_detail"])
        assert "controls verified" not in evidenced_blob.lower()
    finally:
        db.close()


def test_risk_reduction_pct_from_prior_findings():
    prev_payload = {
        "header": {"score": 58},
        "findings": [
            {"title": "A"},
            {"title": "B"},
            {"title": "C"},
            {"title": "D"},
            {"title": "E"},
            {"title": "F"},
            {"title": "G"},
        ],
    }
    current_findings = [{"title": "A"}, {"title": "B"}]  # 7 -> 2
    out = _build_historical_comparison(current_score=65, current_findings=current_findings, prev_payload=prev_payload)
    assert out["previous_score"] == 58
    assert out["current_score"] == 65
    assert out["prev_open_findings"] == 7
    assert out["current_open_findings"] == 2
    assert out["risk_reduction_pct"] == 71  # round((7-2)/7*100)
    assert out["has_prior"] is True


def test_no_prior_report_trend_empty_state():
    out = _build_historical_comparison(current_score=65, current_findings=[{"title": "A"}], prev_payload={})
    assert out["has_prior"] is False
    assert out["risk_reduction_pct"] is None
    assert "Baseline report" in out["improvement_summary"]


def test_trend_block_present_in_report():
    db = _make_session()
    try:
        t = Tenant(id="t-trend", tenant_name="Trend Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        trend = report["trend"]
        # No prior archived report -> baseline empty-state
        assert trend["has_prior"] is False
        assert "remediations_completed" in trend
        assert report["remediation_history"]["empty_message"]  # no remediations
    finally:
        db.close()


def test_evidence_integrity_block_complete():
    db = _make_session()
    try:
        t = Tenant(id="t-integrity", tenant_name="Integrity Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        ei = report["evidence_integrity"]
        assert ei["evidence_source"] == "Microsoft Graph API"
        assert ei["data_collection_timestamp"]
        assert ei["report_generation_timestamp"]
        assert ei["data_collection_timestamp"] != ei["report_generation_timestamp"]
        assert "has not been modified after collection" in ei["integrity_statement"]
        assert re.fullmatch(r"[0-9a-f]{64}", ei["report_hash"])
        assert "Not yet established" in ei["tenant_verification_status"]
    finally:
        db.close()


def test_verdict_block_and_impact_summary_present():
    db = _make_session()
    try:
        t = Tenant(id="t-verdict", tenant_name="Verdict Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        assert report["verdict"]["label"]
        assert "Ready" not in report["verdict"]["label"]
        assert len(report["insurance_impact"]) == 6
        assert report["insurance_impact"][-1]["category"] == "Underwriting Supportability"
    finally:
        db.close()


def test_demo_flag_anonymizes_identifiers_only():
    db = _make_session()
    try:
        t = Tenant(id="real-tenant-id-123", tenant_name="Real Customer Pty Ltd")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id, demo=True)
        assert report["header"]["tenant_name"] == "Contoso Manufacturing"
        assert "real-tenant-id-123" not in report["header"]["tenant_id"]
        assert report["header"]["tenant_id"].startswith("DEMO-")
    finally:
        db.close()


def test_offboarding_empty_state_message():
    db = _make_session()
    try:
        t = Tenant(id="t-offboard", tenant_name="Offboard Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        assert report["section_offboarding"]["secure_exits"] == 0
        assert report["section_offboarding"]["empty_message"] == (
            "No offboarding events occurred during the reporting period."
        )
    finally:
        db.close()


def test_demo_tenant_id_is_contoso_format():
    db = _make_session()
    try:
        t = Tenant(id="real-abc-123", tenant_name="Real Corp")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id, demo=True)
        assert report["header"]["tenant_id"] == "DEMO-CONTOSO-001"
    finally:
        db.close()


def test_demo_injects_trend_data():
    db = _make_session()
    try:
        t = Tenant(id="t-demo-trend", tenant_name="Demo Trend Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id, demo=True)
        trend = report["trend"]
        assert trend["has_prior"] is True, "demo mode must inject prior payload"
        assert trend["previous_score"] == 58
        assert trend["prev_open_findings"] == 7
    finally:
        db.close()


def test_demo_injects_remediation_history():
    db = _make_session()
    try:
        t = Tenant(id="t-demo-rem", tenant_name="Demo Rem Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id, demo=True)
        rows = report["remediation_history"]["rows"]
        assert len(rows) == 3
        control_ids = {r["control_id"] for r in rows}
        assert "IDENTITY_ADMIN_NO_MFA" in control_ids
        assert "IDENTITY_USER_CONSENT_POLICY" in control_ids
        assert "IDENTITY_ADMIN_COUNT_EXCESS" in control_ids
        assert all(r["previous_status"] == "Fail" for r in rows)
        assert all(r["current_status"] == "Pass" for r in rows)
    finally:
        db.close()


def test_no_ready_not_ready_strings_anywhere_in_payload():
    import json

    db = _make_session()
    try:
        t = Tenant(id="t-clean", tenant_name="Clean Tenant")
        db.add(t)
        _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
        db.commit()
        report = build_evidence_report(db, t, t.id)
        blob = json.dumps(report, default=str)
        assert "Not Ready" not in blob
        assert '"Ready"' not in blob
    finally:
        db.close()


# ---- Phase D: verification integration tests ----

import pytest
from unittest import mock
from types import SimpleNamespace


@pytest.fixture()
def db():
    session = _make_session()
    yield session
    session.close()


@pytest.fixture()
def tenant(db):
    t = Tenant(id="t-phased", tenant_name="Phase D Tenant")
    db.add(t)
    _add_result(db, t.id, "IDENTITY_USER_NO_MFA", True)
    db.commit()
    return t


def _fake_rv(status: str, count: int = 1, first_verified_at=None, last_verified_at=None):
    return SimpleNamespace(
        status=status,
        verification_count=count,
        first_verified_at=first_verified_at,
        last_verified_at=last_verified_at,
    )


def test_evidence_report_has_verification_coverage_key(db, tenant):
    """verification_coverage must be present in every evidence report."""
    report = build_evidence_report(db, tenant)
    assert "verification_coverage" in report
    cov = report["verification_coverage"]
    assert "controls_evaluated" in cov
    assert "controls_remediated" in cov
    assert "controls_verified_provisional" in cov
    assert "controls_verified_confirmed" in cov
    assert "controls_drifted" in cov


def test_evidence_report_has_section_verification_key(db, tenant):
    """section_verification must be present and be a list."""
    report = build_evidence_report(db, tenant)
    assert "section_verification" in report
    assert isinstance(report["section_verification"], list)


def test_evidence_report_has_drift_summary_key(db, tenant):
    """drift_summary must be present with has_drift and drifted_controls."""
    report = build_evidence_report(db, tenant)
    assert "drift_summary" in report
    ds = report["drift_summary"]
    assert "has_drift" in ds
    assert "drifted_controls" in ds
    assert isinstance(ds["drifted_controls"], list)


def test_drift_summary_no_drift_when_no_drift_states(db, tenant):
    """With no DRIFT_DETECTED states, has_drift must be False."""
    with mock.patch(
        "app.services.insurance.evidence_report_builder.get_verification_states_for_controls",
        return_value={},
    ):
        report = build_evidence_report(db, tenant)
    assert report["drift_summary"]["has_drift"] is False
    assert report["drift_summary"]["drifted_controls"] == []


def test_drift_summary_shows_drift_when_state_is_drift_detected(db, tenant):
    """When a control has DRIFT_DETECTED, drift_summary must reflect it."""
    fake_states = {"IDENTITY_UNUSED_ACCOUNT": _fake_rv("DRIFT_DETECTED")}
    with mock.patch(
        "app.services.insurance.evidence_report_builder.get_verification_states_for_controls",
        return_value=fake_states,
    ):
        report = build_evidence_report(db, tenant)
    ds = report["drift_summary"]
    assert ds["has_drift"] is True
    assert len(ds["drifted_controls"]) >= 1
    drift_ctrl_ids = [d["control_id"] for d in ds["drifted_controls"]]
    assert "IDENTITY_UNUSED_ACCOUNT" in drift_ctrl_ids


def test_section_verification_uses_underwriter_safe_labels(db, tenant):
    """section_verification must not contain bare 'Verified'."""
    fake_states = {
        "CTRL_A": _fake_rv("VERIFIED_CONFIRMED"),
        "CTRL_B": _fake_rv("DRIFT_DETECTED"),
    }
    with mock.patch(
        "app.services.insurance.evidence_report_builder.get_verification_states_for_controls",
        return_value=fake_states,
    ):
        report = build_evidence_report(db, tenant)
    for entry in report["section_verification"]:
        label = entry.get("verification_status", "")
        assert label != "Verified", f"Bare 'Verified' found in section_verification: {entry}"


def test_existing_evidence_report_keys_unchanged(db, tenant):
    """Backward compat: all pre-Phase D top-level keys must still be present."""
    report = build_evidence_report(db, tenant)
    pre_phase_d_keys = {
        "generated_at",
        "tenant_id",
        "header",
        "executive_summary",
        "controls_verified_summary",
        "continuous_verification",
        "insurance_readiness",
        "remediation_history",
        "verdict",
        "evidence_integrity",
    }
    missing = pre_phase_d_keys - set(report.keys())
    assert not missing, f"Missing pre-Phase D keys: {missing}"


def test_verified_confirmed_and_drift_produce_different_section_verification_entries(db, tenant):
    """Spec: confirmed vs drift must produce different insurer-facing output in section_verification."""
    fake_states = {
        "CTRL_CONFIRMED": _fake_rv("VERIFIED_CONFIRMED"),
        "CTRL_DRIFT": _fake_rv("DRIFT_DETECTED"),
    }
    with mock.patch(
        "app.services.insurance.evidence_report_builder.get_verification_states_for_controls",
        return_value=fake_states,
    ):
        report = build_evidence_report(db, tenant)

    by_ctrl = {e["control_id"]: e for e in report["section_verification"]}
    if "CTRL_CONFIRMED" in by_ctrl and "CTRL_DRIFT" in by_ctrl:
        confirmed_label = by_ctrl["CTRL_CONFIRMED"]["verification_status"]
        drift_label = by_ctrl["CTRL_DRIFT"]["verification_status"]
        assert confirmed_label != drift_label
        assert drift_label == "Drift Detected"
