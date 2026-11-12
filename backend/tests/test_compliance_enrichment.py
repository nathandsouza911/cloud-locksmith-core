"""Phase 2 — read-only compliance enrichment over the frozen Phase 1 catalog.

All framework references must come from app/services/control_catalog only.
Enrichment must be a pure function of control_id / a list of results — never a
DB handle or tenant — so it cannot affect tenant isolation or any scoring.
"""

import inspect
from types import SimpleNamespace

from app.services import compliance_enrichment as ce


def _result(control_id, passed):
    return SimpleNamespace(control_id=control_id, passed=passed)


# ---------------------------------------------------------------------------
# Finding-level mappings (the framework_mappings shape)
# ---------------------------------------------------------------------------


def test_get_framework_mappings_returns_framework_reference_label():
    mappings = ce.get_framework_mappings("IDENTITY_ADMIN_NO_MFA")
    frameworks = {m["framework"] for m in mappings}
    assert "CIS Microsoft 365 Foundations Benchmark" in frameworks
    assert "CISA SCuBA (Microsoft Entra ID)" in frameworks
    for m in mappings:
        assert set(m.keys()) == {"framework", "reference_id", "label"}
        assert m["reference_id"]
        assert m["label"]


def test_get_framework_mappings_resolves_scuba_reference_id():
    mappings = ce.get_framework_mappings("CA_LEGACY_AUTH_BLOCK")
    scuba = [m for m in mappings if m["framework"].startswith("CISA SCuBA")]
    assert scuba and scuba[0]["reference_id"] == "MS.AAD.1.1v1"


def test_get_framework_mappings_unknown_control_returns_empty():
    assert ce.get_framework_mappings("NOT_A_CONTROL") == []


def test_get_framework_mappings_canonicalizes_alias():
    assert ce.get_framework_mappings("IDENTITY_DORMANT_ACCOUNT") == ce.get_framework_mappings("IDENTITY_UNUSED_ACCOUNT")


def test_enrichment_is_pure_no_db_or_tenant_argument():
    # Structural guard for tenant isolation: enrichment takes only a control_id.
    params = list(inspect.signature(ce.get_framework_mappings).parameters)
    assert params == ["control_id"]


# ---------------------------------------------------------------------------
# CSV / report reference fields
# ---------------------------------------------------------------------------


def test_framework_reference_fields_splits_by_framework():
    fields = ce.framework_reference_fields("IDENTITY_ADMIN_NO_MFA")
    assert fields["cis_refs"] == "5.2.2.4"
    assert fields["scuba_refs"] == "MS.AAD.3.6v1"
    assert fields["insurance_refs"] == "MFA-ADMIN"
    assert "PR.AA-03" in fields["nist_functions"]
    assert fields["insurance_category"] == "MFA-ADMIN"


def test_framework_reference_fields_unknown_control_is_blank():
    fields = ce.framework_reference_fields("NOT_A_CONTROL")
    assert fields["cis_refs"] == ""
    assert fields["scuba_refs"] == ""
    assert fields["frameworks"] == ""


# ---------------------------------------------------------------------------
# Framework coverage metrics (counts only — no percentages, no readiness)
# ---------------------------------------------------------------------------


def test_compute_framework_coverage_counts_passing_and_failing():
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", False),  # mapped cis/scuba/insurance
        _result("CA_LEGACY_AUTH_BLOCK", True),  # mapped cis/scuba/insurance
        _result("IDENTITY_ADMIN_COUNT_EXCESS", True),
    ]
    coverage = ce.compute_framework_coverage(results)
    cis = coverage["cis-m365"]
    assert cis["mapped_controls"] == 3
    assert cis["passing"] == 2
    assert cis["failing"] == 1


def test_coverage_excludes_derived_frameworks_and_has_no_percentages():
    coverage = ce.compute_framework_coverage([_result("IDENTITY_ADMIN_NO_MFA", True)])
    assert "nist-csf" not in coverage  # derived framework is not a coverage metric
    for entry in coverage.values():
        assert set(entry.keys()) == {"framework", "mapped_controls", "passing", "failing"}


def test_coverage_failing_wins_across_multiple_rows_of_same_control():
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", True),
        _result("IDENTITY_ADMIN_NO_MFA", False),
    ]
    coverage = ce.compute_framework_coverage(results)
    assert coverage["cis-m365"]["mapped_controls"] == 1
    assert coverage["cis-m365"]["failing"] == 1
    assert coverage["cis-m365"]["passing"] == 0


def test_coverage_ignores_controls_with_no_mapping():
    coverage = ce.compute_framework_coverage([_result("USER_OFFBOARDING", True)])
    assert coverage["cis-m365"]["mapped_controls"] == 0


# ---------------------------------------------------------------------------
# Per-control compliance detail for the insurance report
# ---------------------------------------------------------------------------


def test_build_control_compliance_lists_evaluated_mapped_controls():
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", False),
        _result("USER_OFFBOARDING", True),  # not mapped — excluded
    ]
    rows = ce.build_control_compliance(results)
    control_ids = {r["control_id"] for r in rows}
    assert "IDENTITY_ADMIN_NO_MFA" in control_ids
    assert "USER_OFFBOARDING" not in control_ids
    row = next(r for r in rows if r["control_id"] == "IDENTITY_ADMIN_NO_MFA")
    assert row["passed"] is False
    assert row["scuba_refs"] == "MS.AAD.3.6v1"
    assert row["insurance_category"] == "MFA-ADMIN"
    assert any(m["framework"].startswith("CIS") for m in row["framework_mappings"])
