"""Tests for compliance_dashboard_service.build_dashboard_rows().

TDD: these tests were written BEFORE the implementation. They define the
4-state status logic and filtering/summary contract for Phase 1 of the
compliance dashboard.

Fixtures use real catalog data (no mocking of the catalog loader), so the
tests also exercise that the catalog is coherent with the service logic.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Minimal mock result object — a plain class (no unittest.mock)
# ---------------------------------------------------------------------------


class _Result:
    """Minimal stand-in for a ComplianceResult ORM row."""

    def __init__(self, control_id: str, passed: bool) -> None:
        self.control_id = control_id
        self.passed = passed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rows_for(control_id: str, passed: bool, count: int = 1) -> list[_Result]:
    """Return ``count`` result rows for a control, all with the same passed value."""
    return [_Result(control_id, passed) for _ in range(count)]


def _get_status(rows: list[dict], control_id: str, framework_id: str) -> str | None:
    """Find the status of a specific (control_id, framework_id) pair in the output."""
    for row in rows:
        if row["control_id"] == control_id and row["framework_id"] == framework_id:
            return row["status"]
    return None


def _get_summary(frameworks: list[dict], framework_id: str) -> dict | None:
    for f in frameworks:
        if f["id"] == framework_id:
            return f
    return None


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from app.services.compliance_dashboard_service import build_dashboard_rows  # noqa: E402


# ---------------------------------------------------------------------------
# Catalog facts used across tests (chosen from real compliance_mappings.json)
#
# IDENTITY_ADMIN_NO_MFA -> cis-m365  mapping_strength="direct"
# IDENTITY_UNUSED_ACCOUNT -> cis-m365  mapping_strength="partial"
# IDENTITY_USER_NO_MFA -> cis-m365  mapping_strength="evidence"   (also partial-family)
# CA_GUEST_MFA -> cis-m365  mapping_strength="partial"
# ---------------------------------------------------------------------------

_DIRECT_CONTROL = "IDENTITY_ADMIN_NO_MFA"  # cis-m365: direct
_PARTIAL_CONTROL = "IDENTITY_UNUSED_ACCOUNT"  # cis-m365: partial
_EVIDENCE_CONTROL = "IDENTITY_USER_NO_MFA"  # cis-m365: evidence  (non-direct)
_TARGET_FRAMEWORK = "cis-m365"


# ---------------------------------------------------------------------------
# 1. test_pass_status
# ---------------------------------------------------------------------------


def test_pass_status():
    """All result rows pass → status PASS."""
    results = _rows_for(_DIRECT_CONTROL, passed=True, count=3)
    output = build_dashboard_rows(results)
    status = _get_status(output["controls"], _DIRECT_CONTROL, _TARGET_FRAMEWORK)
    assert status == "PASS", f"Expected PASS, got {status!r}"


# ---------------------------------------------------------------------------
# 2. test_fail_status_direct
# ---------------------------------------------------------------------------


def test_fail_status_direct():
    """All rows fail + mapping_strength 'direct' → status FAIL."""
    results = _rows_for(_DIRECT_CONTROL, passed=False, count=2)
    output = build_dashboard_rows(results)
    status = _get_status(output["controls"], _DIRECT_CONTROL, _TARGET_FRAMEWORK)
    assert status == "FAIL", f"Expected FAIL, got {status!r}"


# ---------------------------------------------------------------------------
# 3. test_partial_status_partial_strength
# ---------------------------------------------------------------------------


def test_partial_status_partial_strength():
    """All rows fail + mapping_strength 'partial' → status PARTIAL (not FAIL)."""
    results = _rows_for(_PARTIAL_CONTROL, passed=False, count=2)
    output = build_dashboard_rows(results)
    status = _get_status(output["controls"], _PARTIAL_CONTROL, _TARGET_FRAMEWORK)
    assert status == "PARTIAL", f"Expected PARTIAL, got {status!r}"


# ---------------------------------------------------------------------------
# 4. test_partial_status_mixed
# ---------------------------------------------------------------------------


def test_partial_status_mixed():
    """Some rows pass, some fail → PARTIAL (regardless of mapping_strength)."""
    results = [
        _Result(_DIRECT_CONTROL, True),
        _Result(_DIRECT_CONTROL, False),
    ]
    output = build_dashboard_rows(results)
    status = _get_status(output["controls"], _DIRECT_CONTROL, _TARGET_FRAMEWORK)
    assert status == "PARTIAL", f"Expected PARTIAL (mixed), got {status!r}"


# ---------------------------------------------------------------------------
# 5. test_not_applicable
# ---------------------------------------------------------------------------


def test_not_applicable():
    """No result rows for the control → NOT_APPLICABLE."""
    # Pass results only for a different control so the catalog has data, but
    # _PARTIAL_CONTROL has no rows.
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results)
    status = _get_status(output["controls"], _PARTIAL_CONTROL, _TARGET_FRAMEWORK)
    assert status == "NOT_APPLICABLE", f"Expected NOT_APPLICABLE, got {status!r}"


# ---------------------------------------------------------------------------
# 6. test_framework_filter
# ---------------------------------------------------------------------------


def test_framework_filter():
    """framework_id filter keeps only controls with that framework_id."""
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results, framework_id="cis-m365")
    controls = output["controls"]
    assert len(controls) > 0, "Expected at least one control for cis-m365"
    assert all(c["framework_id"] == "cis-m365" for c in controls), "Found controls with wrong framework_id after filter"


# ---------------------------------------------------------------------------
# 7. test_status_filter
# ---------------------------------------------------------------------------


def test_status_filter():
    """status_filter keeps only controls with that status."""
    # Make DIRECT_CONTROL fail so we have at least one FAIL
    results = _rows_for(_DIRECT_CONTROL, passed=False)
    output = build_dashboard_rows(results, status_filter="FAIL")
    controls = output["controls"]
    assert len(controls) > 0, "Expected at least one FAIL control"
    assert all(c["status"] == "FAIL" for c in controls), "Found non-FAIL controls after status_filter=FAIL"


# ---------------------------------------------------------------------------
# 8. test_search_by_control_id
# ---------------------------------------------------------------------------


def test_search_by_control_id():
    """search substring matches control_id case-insensitively."""
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    # 'admin_no_mfa' is a lowercase substring of IDENTITY_ADMIN_NO_MFA
    output = build_dashboard_rows(results, search="admin_no_mfa")
    controls = output["controls"]
    assert len(controls) > 0, "Expected controls matching 'admin_no_mfa' in control_id"
    assert all(
        "admin_no_mfa" in c["control_id"].lower()
        or "admin_no_mfa" in c["reference_id"].lower()
        or "admin_no_mfa" in c["label"].lower()
        for c in controls
    )


# ---------------------------------------------------------------------------
# 9. test_search_by_reference_id
# ---------------------------------------------------------------------------


def test_search_by_reference_id():
    """search substring matches reference_id case-insensitively."""
    # IDENTITY_ADMIN_NO_MFA → cis-m365 reference_id = '5.2.2.4'
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results, search="5.2.2.4")
    controls = output["controls"]
    assert len(controls) > 0, "Expected controls matching '5.2.2.4' in reference_id"
    assert all(
        "5.2.2.4" in c["control_id"].lower()
        or "5.2.2.4" in c["reference_id"].lower()
        or "5.2.2.4" in c["label"].lower()
        for c in controls
    )


# ---------------------------------------------------------------------------
# 10. test_search_by_label
# ---------------------------------------------------------------------------


def test_search_by_label():
    """search substring matches label (report_label) case-insensitively."""
    # IDENTITY_ADMIN_NO_MFA → cis-m365 report_label contains 'administrative roles'
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results, search="administrative roles")
    controls = output["controls"]
    assert len(controls) > 0, "Expected controls matching 'administrative roles' in label"
    assert all(
        "administrative roles" in c["control_id"].lower()
        or "administrative roles" in c["reference_id"].lower()
        or "administrative roles" in c["label"].lower()
        for c in controls
    )


# ---------------------------------------------------------------------------
# 11. test_framework_summaries_not_filtered
# ---------------------------------------------------------------------------


def test_framework_summaries_not_filtered():
    """frameworks summaries are never filtered — all 4 frameworks appear even with framework_id filter."""
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results, framework_id="cis-m365")
    framework_ids = {f["id"] for f in output["frameworks"]}
    assert framework_ids == {
        "cis-m365",
        "cisa-scuba",
        "cyber-insurance",
        "nist-csf",
    }, f"Expected all 4 frameworks in summaries, got: {framework_ids}"


# ---------------------------------------------------------------------------
# 12. test_framework_summary_counts
# ---------------------------------------------------------------------------


def test_framework_summary_counts():
    """For each framework, pass + fail + partial + not_applicable == total_mapped_controls."""
    results = _rows_for(_DIRECT_CONTROL, passed=True) + _rows_for(_PARTIAL_CONTROL, passed=False)
    output = build_dashboard_rows(results)
    for summary in output["frameworks"]:
        total = summary["total_mapped_controls"]
        component_sum = (
            summary["pass_count"] + summary["fail_count"] + summary["partial_count"] + summary["not_applicable_count"]
        )
        assert component_sum == total, f"Framework {summary['id']}: {component_sum} != total {total}"


# ---------------------------------------------------------------------------
# 13. test_nist_csf_functions_populated
# ---------------------------------------------------------------------------


def test_nist_csf_functions_populated():
    """Controls with NIST functions in the catalog have them in the output."""
    # IDENTITY_ADMIN_NO_MFA has nist_csf_functions: ["PR.AA-03"] in all its mappings
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results)
    matching = [
        c for c in output["controls"] if c["control_id"] == _DIRECT_CONTROL and c["framework_id"] == _TARGET_FRAMEWORK
    ]
    assert len(matching) == 1, "Expected exactly one row for the control+framework pair"
    assert (
        "PR.AA-03" in matching[0]["nist_csf_functions"]
    ), f"Expected PR.AA-03 in nist_csf_functions, got {matching[0]['nist_csf_functions']!r}"


# ---------------------------------------------------------------------------
# 14. test_unevaluated_controls_are_not_applicable
# ---------------------------------------------------------------------------


def test_unevaluated_controls_are_not_applicable():
    """A control in the catalog but with no result rows appears as NOT_APPLICABLE."""
    # Pass ONLY results for _DIRECT_CONTROL. _PARTIAL_CONTROL has no results.
    results = _rows_for(_DIRECT_CONTROL, passed=True)
    output = build_dashboard_rows(results)
    # _PARTIAL_CONTROL (IDENTITY_UNUSED_ACCOUNT) maps to cis-m365 — should be NOT_APPLICABLE
    status = _get_status(output["controls"], _PARTIAL_CONTROL, _TARGET_FRAMEWORK)
    assert status is not None, f"{_PARTIAL_CONTROL} not found in output — unevaluated controls must be included"
    assert status == "NOT_APPLICABLE", f"Expected NOT_APPLICABLE for unevaluated control, got {status!r}"
