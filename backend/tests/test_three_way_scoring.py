"""Part 4 — three-way posture scoring.

A control is PASS, FAIL, or NOT_EVALUATED. NOT_EVALUATED controls (no result
rows, or only rows with passed=None) must be excluded from the numerator,
denominator, and baseline weight totals. They must NOT count as PASS.
"""

from types import SimpleNamespace

from app.services.posture_snapshot_service import build_baseline_summary


def _result(control_id, passed, severity="HIGH", **extra):
    return SimpleNamespace(
        control_id=control_id,
        passed=passed,
        severity=severity,
        evidence=extra.get("evidence"),
        resource_id=extra.get("resource_id"),
        resource_type=extra.get("resource_type", "TENANT"),
        exposure_status=extra.get("exposure_status", "ACTIVE"),
    )


def test_control_with_no_results_is_excluded_from_score_and_weights():
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", True, "CRITICAL"),  # weight 25
        _result("IDENTITY_USER_NO_MFA", False, "HIGH"),  # weight 15
    ]
    # CA_MFA_ALL_USERS is active but has no result rows -> NOT_EVALUATED.
    summary = build_baseline_summary(
        results,
        active_controls=["IDENTITY_ADMIN_NO_MFA", "IDENTITY_USER_NO_MFA", "CA_MFA_ALL_USERS"],
    )

    assert summary["total_controls"] == 2
    assert summary["compliant_controls"] == 1
    assert summary["total_weight"] == 40
    assert summary["compliant_weight"] == 25
    assert summary["score"] == 62  # round(25/40*100) -> round(62.5) -> 62 (banker's rounding)

    statuses = {c["control_id"]: c["status"] for c in summary["controls"]}
    assert statuses["IDENTITY_ADMIN_NO_MFA"] == "PASS"
    assert statuses["IDENTITY_USER_NO_MFA"] == "FAIL"
    assert statuses["CA_MFA_ALL_USERS"] == "NOT_EVALUATED"
    assert summary["not_evaluated_controls"] == ["CA_MFA_ALL_USERS"]


def test_passed_none_rows_are_not_evaluated_not_failed():
    # A NOT_EVALUATED marker row (passed=None) must not be scored as a failure.
    results = [_result("IDENTITY_ADMIN_NO_MFA", None, "CRITICAL")]
    summary = build_baseline_summary(results, active_controls=["IDENTITY_ADMIN_NO_MFA"])

    assert summary["total_controls"] == 0
    assert summary["total_weight"] == 0
    assert summary["compliant_controls"] == 0
    assert summary["score"] == 100  # nothing evaluated -> no risk expressed
    control = summary["controls"][0]
    assert control["control_id"] == "IDENTITY_ADMIN_NO_MFA"
    assert control["status"] == "NOT_EVALUATED"


def test_evaluated_controls_report_pass_fail_status():
    results = [
        _result("IDENTITY_GUEST_INVITES_OPEN", True, "MEDIUM"),
        _result("IDENTITY_USER_CONSENT_POLICY", False, "HIGH"),
    ]
    summary = build_baseline_summary(
        results,
        active_controls=["IDENTITY_GUEST_INVITES_OPEN", "IDENTITY_USER_CONSENT_POLICY"],
    )
    statuses = {c["control_id"]: c["status"] for c in summary["controls"]}
    assert statuses["IDENTITY_GUEST_INVITES_OPEN"] == "PASS"
    assert statuses["IDENTITY_USER_CONSENT_POLICY"] == "FAIL"
    assert summary["not_evaluated_controls"] == []
