from types import SimpleNamespace

from app.services.insurance.identity_insurance_readiness import (
    calculate_identity_insurance_readiness,
)


def _result(control_id, passed, severity="HIGH", evidence=None):
    return SimpleNamespace(
        control_id=control_id,
        passed=passed,
        severity=severity,
        evidence=evidence or {},
        evaluated_at=None,
        id=1,
    )


def test_admins_without_mfa_force_high_risk_review(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 90, "breakdown": {}},
    )
    results = [_result("IDENTITY_ADMIN_NO_MFA", False, evidence={"affected_admins": 1})]
    out = calculate_identity_insurance_readiness(results)
    assert out["readiness"] == "NOT_READY"
    assert out["tier_label"] == "High Risk Review Required"


def test_low_score_forces_high_risk_review(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 30, "breakdown": {}},
    )
    out = calculate_identity_insurance_readiness([])
    assert out["readiness"] == "NOT_READY"
    assert out["tier_label"] == "High Risk Review Required"


def test_mid_score_is_elevated_risk(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 50, "breakdown": {}},
    )
    out = calculate_identity_insurance_readiness([])
    assert out["readiness"] == "HIGH_RISK"
    assert out["tier_label"] == "Elevated Risk"


def test_strong_with_governance_finding_is_eligible_with_recommendations(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 84, "breakdown": {}},
    )
    # Over-privileged admin = material (High), admins protected, score >= 60
    results = [_result("IDENTITY_OVERPRIVILEGED_USER", False)]
    out = calculate_identity_insurance_readiness(results)
    assert out["readiness"] == "CONDITIONAL"
    assert out["tier_label"] == "Eligible With Recommendations"


def test_medium_governance_recommendation_does_not_block_eligible(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 88, "breakdown": {}},
    )
    # Guest invites = non-material (Medium); admins protected; score >= 80
    results = [_result("IDENTITY_GUEST_INVITES_OPEN", False, severity="MEDIUM")]
    out = calculate_identity_insurance_readiness(results)
    assert out["readiness"] == "READY"
    assert out["tier_label"] == "Eligible"


def test_no_ready_not_ready_terminology_in_labels(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 88, "breakdown": {}},
    )
    out = calculate_identity_insurance_readiness([])
    assert "Not Ready" not in out["tier_label"]
    assert out["tier_label"] != "Ready"


def test_mid_band_no_findings_is_conditional_by_score(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 70, "breakdown": {}},
    )
    # Score in [60, 80), no findings at all -> CONDITIONAL purely by score band.
    out = calculate_identity_insurance_readiness([])
    assert out["readiness"] == "CONDITIONAL"
    assert out["tier_label"] == "Eligible With Recommendations"


def test_material_finding_demotes_high_score_from_eligible(monkeypatch):
    monkeypatch.setattr(
        "app.services.insurance.identity_insurance_readiness.calculate_identity_posture_score",
        lambda results: {"score": 90, "breakdown": {}},
    )
    # Score >= 80 but a material (High) finding present -> demoted to CONDITIONAL.
    results = [_result("IDENTITY_USER_CONSENT_POLICY", False)]
    out = calculate_identity_insurance_readiness(results)
    assert out["readiness"] == "CONDITIONAL"
    assert out["tier_label"] == "Eligible With Recommendations"
