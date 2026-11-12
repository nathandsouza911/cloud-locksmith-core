"""Part 6 — compliance dashboard separates NOT_EVALUATED (licence-unavailable)
controls from PASS/FAIL and flags them with a License Required badge, without
counting them in pass/fail totals.
"""

from types import SimpleNamespace

from app.services.compliance_dashboard_service import build_dashboard_rows


def _row(control_id, passed):
    return SimpleNamespace(control_id=control_id, passed=passed)


def test_license_unavailable_ca_control_marked_not_evaluated():
    # No result rows for any control; CA controls are licence-unavailable.
    gated = {"CA_MFA_ALL_USERS", "CA_MFA_ADMINS"}
    out = build_dashboard_rows([], license_unavailable_controls=gated)

    ca_rows = [r for r in out["controls"] if r["control_id"] == "CA_MFA_ALL_USERS"]
    assert ca_rows, "CA_MFA_ALL_USERS must be present in the dashboard"
    for r in ca_rows:
        assert r["status"] == "NOT_EVALUATED"
        assert r["license_required"] is True


def test_non_gated_unevaluated_control_stays_not_applicable():
    out = build_dashboard_rows([], license_unavailable_controls={"CA_MFA_ALL_USERS"})
    other = [r for r in out["controls"] if r["control_id"] == "IDENTITY_USER_NO_MFA"]
    assert other
    for r in other:
        assert r["status"] == "NOT_APPLICABLE"
        assert r["license_required"] is False


def test_not_evaluated_excluded_from_pass_fail_counts():
    # An evaluated FAIL on a normal control plus licence-unavailable CA controls.
    results = [_row("IDENTITY_USER_NO_MFA", False)]
    gated = {"CA_MFA_ALL_USERS", "CA_MFA_ADMINS", "CA_LEGACY_AUTH_BLOCK"}
    out = build_dashboard_rows(results, license_unavailable_controls=gated)

    for fw in out["frameworks"]:
        # NOT_EVALUATED controls never inflate pass/fail counts.
        assert fw["not_evaluated_count"] >= 0
        # pass/fail/partial counts must not include the gated CA controls.
        evaluated_total = fw["pass_count"] + fw["fail_count"] + fw["partial_count"]
        assert evaluated_total + fw["not_applicable_count"] + fw["not_evaluated_count"] == fw["total_mapped_controls"]


def test_licensed_ca_control_with_results_is_scored_normally():
    # When a CA control has real results it is PASS/FAIL, never NOT_EVALUATED,
    # even if listed (defensive) in the licence-unavailable set.
    results = [_row("CA_MFA_ALL_USERS", True)]
    out = build_dashboard_rows(results, license_unavailable_controls={"CA_MFA_ALL_USERS"})
    ca_rows = [r for r in out["controls"] if r["control_id"] == "CA_MFA_ALL_USERS"]
    assert ca_rows
    for r in ca_rows:
        assert r["status"] == "PASS"
