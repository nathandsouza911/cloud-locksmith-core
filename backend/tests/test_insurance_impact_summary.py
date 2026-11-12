from app.services.insurance.impact_summary import build_insurance_impact_summary


def _full_strong():
    return dict(
        mfa_enforcement_pass=True,
        mfa_coverage_pct=100,
        admin_mfa_missing=0,
        privileged_access_pass=True,
        identity_governance_pass=True,
        oauth_consent_failed=False,
        has_prior_report=True,
        tier_state="READY",
    )


def test_returns_six_categories_in_order():
    rows = build_insurance_impact_summary(**_full_strong())
    cats = [r["category"] for r in rows]
    assert cats == [
        "MFA Enforcement",
        "Privileged Access Controls",
        "Identity Governance",
        "Application Consent Controls",
        "Evidence Maturity",
        "Underwriting Supportability",
    ]


def test_strong_posture_marks_categories_strong():
    rows = build_insurance_impact_summary(**_full_strong())
    by_cat = {r["category"]: r for r in rows}
    assert by_cat["MFA Enforcement"]["status"] == "Strong"
    assert by_cat["Underwriting Supportability"]["status"] == "Strong"
    assert by_cat["MFA Enforcement"]["commentary"]


def test_admin_mfa_gap_marks_mfa_needs_attention():
    data = _full_strong()
    data.update(mfa_enforcement_pass=False, admin_mfa_missing=2, mfa_coverage_pct=85)
    rows = build_insurance_impact_summary(**data)
    by_cat = {r["category"]: r for r in rows}
    assert by_cat["MFA Enforcement"]["status"] == "Needs Attention"


def test_no_prior_report_lowers_evidence_maturity():
    data = _full_strong()
    data.update(has_prior_report=False)
    rows = build_insurance_impact_summary(**data)
    by_cat = {r["category"]: r for r in rows}
    assert by_cat["Evidence Maturity"]["status"] in {"Moderate", "Needs Attention"}
