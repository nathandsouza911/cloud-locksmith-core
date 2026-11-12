from jinja2 import Environment, FileSystemLoader


def _sample_report():
    return {
        "header": {
            "tenant_name": "Contoso Manufacturing",
            "tenant_id": "DEMO-0000-CONTOSO",
            "reporting_period": "Last 90 Days",
            "platform": "Cloud Locksmith",
            "attestation_date": "09 June 2026",
            "report_generated_at": "2026-06-09 12:00:00 UTC",
            "score": 84,
            "score_band": "High",
        },
        "verdict": {
            "tier_state": "CONDITIONAL",
            "label": "Eligible With Recommendations",
            "meaning": "Core controls in place; limited recommendations remain.",
            "recommendation": "Address remaining recommendations.",
        },
        "executive_summary": {"headline": "Executive Summary", "summary": "s", "outlook": "o"},
        "insurance_impact": [
            {"category": "MFA Enforcement", "status": "Strong", "commentary": "c"},
            {"category": "Underwriting Supportability", "status": "Moderate", "commentary": "c"},
        ],
        "continuous_verification": {
            "last_assessment": "2026-06-01 12:00:00 UTC",
            "monitoring_status": "Active — controls continuously evaluated",
            "controls_verified": 3,
            "evidence_age": "8 days",
        },
        "control_coverage": [
            {"category": "MFA Controls", "status": "Verified"},
            {"category": "Offboarding Controls", "status": "Not Evaluated"},
        ],
        "controls_verified_summary": {"verified": 3, "passing": 2, "requiring_action": 1, "remediated": 1},
        "trend": {
            "previous_score": 58,
            "current_score": 65,
            "delta": 7,
            "prev_open_findings": 7,
            "current_open_findings": 2,
            "risk_reduction_pct": 71,
            "remediations_completed": 5,
            "has_prior": True,
            "summary": "Improved.",
        },
        "remediation_history": {
            "rows": [
                {
                    "control_id": "IDENTITY_ADMIN_NO_MFA",
                    "previous_status": "Fail",
                    "action_taken": "Enforced MFA on privileged accounts",
                    "remediation_date": "05 May 2026",
                    "current_status": "Pass",
                    "rollback_available": "Available",
                }
            ],
            "empty_message": "",
        },
        "insurance_readiness_detail": [
            {"area": "MFA Enforcement", "risk": "r", "severity": "Low", "improving": "Improving", "evidenced": "e"},
        ],
        "evidence_integrity": {
            "data_collection_timestamp": "2026-06-01 12:00:00 UTC",
            "report_generation_timestamp": "2026-06-09 12:00:00 UTC",
            "evidence_source": "Microsoft Graph API",
            "integrity_statement": "Evidence has not been modified after collection.",
            "report_hash": "a" * 64,
            "tenant_verification_status": "Verified",
        },
        "metrics": {
            "mfa_missing": 0,
            "admin_mfa_missing": 0,
            "overpriv_count": 0,
            "global_admin_excess": 0,
            "open_findings": 1,
            "compliance_result_count": 3,
        },
        "findings": [{"title": "X", "severity": "High", "risk": "r", "recommendation": "rec"}],
        "recommendations": {"Immediate": [], "Short-term": [], "Ongoing": [{"title": "t", "action": "a"}]},
        "framework_coverage": {},
        "control_compliance": [],
        "section_mfa": {
            "coverage_pct": 100,
            "coverage_label": "100% (3/3 users)",
            "admin_mfa": "All admins protected",
            "last_scan": "2026-06-01",
        },
        "section_privileged": {"overprivileged_label": "Within policy", "risk": "Secure"},
        "section_offboarding": {
            "secure_exits": 0,
            "empty_message": "No offboarding events occurred during the reporting period.",
        },
        "section_defaults": {"oauth_consent": "Hardened", "oauth_consent_risk": "Secure"},
        "posture_breakdown": {
            "identity": {"score": 90, "label": "Strong", "detail": "d"},
            "privileged_access": {"score": 90, "label": "Strong", "detail": "d"},
            "config": {"score": 90, "label": "Strong", "detail": "d"},
        },
        "disclaimer": "Disclaimer text.",
    }


def _render():
    env = Environment(loader=FileSystemLoader("app/templates"), autoescape=True)
    return env.get_template("insurance_evidence_report.html").render(report=_sample_report())


def test_template_has_no_ready_not_ready():
    html = _render()
    assert "Not Ready" not in html


def test_template_renders_key_underwriting_sections():
    html = _render()
    for needle in [
        "Eligible With Recommendations",
        "Insurance Impact Summary",
        "Continuous Verification Status",
        "Insurance-Relevant Control Coverage",
        "Risk Reduction",
        "Remediation History",
        "Evidence Integrity",
        "Microsoft Graph API",
        "Underwriting Supportability",
        "a" * 64,  # report hash
    ]:
        assert needle in html, f"missing: {needle}"


def test_template_renders_remediation_six_columns():
    html = _render()
    for header in ["Previous Status", "Action Taken", "Remediation Date", "Current Status", "Rollback Available"]:
        assert header in html


def test_template_renders_empty_offboarding_message():
    html = _render()
    assert "No offboarding events occurred during the reporting period." in html
