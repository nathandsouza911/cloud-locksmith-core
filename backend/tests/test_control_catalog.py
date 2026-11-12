"""Phase 1 — Compliance mapping catalog integrity and loader behavior.

These tests are the safety net for the read-only compliance mapping overlay.
They guarantee the authored JSON in app/services/control_catalog/ references
only real (canonical) controls and known frameworks, and that the loader's
accessors behave correctly. The catalog is consumed by nothing yet (Phase 2),
so these tests are the only thing protecting the data.
"""

import pytest

from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE
from app.services.compliance_registry import canonicalize_control_id
from app.services.control_catalog import loader
from app.services.control_catalog.schema import CatalogValidationError


# ---------------------------------------------------------------------------
# Real-catalog integrity (drives the authored JSON data)
# ---------------------------------------------------------------------------


def test_real_catalog_loads_and_revalidates_cleanly():
    # Import-time validation already ran (fail-closed). Re-validate explicitly
    # so a regression in the real data fails this test, not just startup.
    loader.validate_catalog(
        loader.frameworks_doc(),
        loader.mappings_doc(),
        loader.crosswalks_doc(),
    )


def test_every_baseline_control_has_at_least_one_mapping():
    unmapped = [c for c in MSP_SECURITY_BASELINE if not loader.get_control_mappings(c)]
    assert unmapped == [], f"baseline controls without any framework mapping: {unmapped}"


def test_mappings_reference_only_canonical_baseline_controls():
    baseline = set(MSP_SECURITY_BASELINE)
    offenders = [
        control_id for control_id in loader.mappings_doc().keys() if canonicalize_control_id(control_id) not in baseline
    ]
    assert offenders == [], f"mappings reference non-baseline controls: {offenders}"


def test_list_frameworks_includes_v1_frameworks():
    ids = {f["id"] for f in loader.list_frameworks()}
    assert {"cis-m365", "cisa-scuba", "cyber-insurance", "nist-csf"} <= ids


# ---------------------------------------------------------------------------
# Accessor behavior
# ---------------------------------------------------------------------------


def test_get_control_mappings_unknown_returns_empty_list():
    assert loader.get_control_mappings("NOT_A_REAL_CONTROL") == []


def test_get_control_mappings_canonicalizes_legacy_alias():
    canonical = loader.get_control_mappings("IDENTITY_UNUSED_ACCOUNT")
    legacy = loader.get_control_mappings("IDENTITY_DORMANT_ACCOUNT")
    assert legacy != []
    assert legacy == canonical


def test_get_framework_returns_known_framework_and_none_for_unknown():
    assert loader.get_framework("cisa-scuba")["name"]
    assert loader.get_framework("does-not-exist") is None


def test_get_nist_functions_for_control_is_derived_from_mappings():
    funcs = loader.get_nist_functions_for_control("IDENTITY_ADMIN_NO_MFA")
    assert "PR.AA-03" in funcs


def test_get_nist_functions_for_unmapped_control_is_empty():
    assert loader.get_nist_functions_for_control("NOT_A_REAL_CONTROL") == []


# ---------------------------------------------------------------------------
# validate_catalog — pure-function failure modes (crafted bad inputs)
# ---------------------------------------------------------------------------


def _good_frameworks() -> dict:
    return {
        "frameworks": [
            {"id": "cis-m365", "name": "CIS M365", "version": "v5.0", "kind": "authored", "display_order": 1},
            {"id": "nist-csf", "name": "NIST CSF", "version": "2.0", "kind": "derived", "display_order": 2},
        ]
    }


def _good_crosswalks() -> dict:
    return {"nist_csf_to_iso27001": {"PR.AA-03": {"iso_27001": "A.8.5", "label": "Secure authentication"}}}


def _good_mappings() -> dict:
    return {
        "IDENTITY_ADMIN_NO_MFA": [
            {
                "framework_id": "cis-m365",
                "reference_id": "5.2.2.1",
                "mapping_strength": "direct",
                "evidence_type": "configuration_state",
                "report_label": "Admin MFA",
                "nist_csf_functions": ["PR.AA-03"],
            }
        ]
    }


def test_validate_accepts_a_well_formed_catalog():
    loader.validate_catalog(_good_frameworks(), _good_mappings(), _good_crosswalks())


def test_validate_rejects_unknown_framework_id():
    mappings = _good_mappings()
    mappings["IDENTITY_ADMIN_NO_MFA"][0]["framework_id"] = "ghost-framework"
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_validate_rejects_non_baseline_control_id():
    mappings = _good_mappings()
    mappings["TOTALLY_FAKE_CONTROL"] = mappings.pop("IDENTITY_ADMIN_NO_MFA")
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_validate_rejects_bad_mapping_strength():
    mappings = _good_mappings()
    mappings["IDENTITY_ADMIN_NO_MFA"][0]["mapping_strength"] = "super-direct"
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_validate_rejects_bad_evidence_type():
    mappings = _good_mappings()
    mappings["IDENTITY_ADMIN_NO_MFA"][0]["evidence_type"] = "vibes"
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_validate_rejects_unknown_nist_function():
    mappings = _good_mappings()
    mappings["IDENTITY_ADMIN_NO_MFA"][0]["nist_csf_functions"] = ["ZZ.ZZ-99"]
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_validate_rejects_missing_required_mapping_field():
    mappings = _good_mappings()
    del mappings["IDENTITY_ADMIN_NO_MFA"][0]["report_label"]
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_validate_rejects_duplicate_control_framework_pair():
    mappings = _good_mappings()
    # Same control mapped twice to the same framework_id — ambiguous, must fail.
    duplicate = dict(mappings["IDENTITY_ADMIN_NO_MFA"][0])
    duplicate["reference_id"] = "5.2.2.99"
    mappings["IDENTITY_ADMIN_NO_MFA"].append(duplicate)
    with pytest.raises(CatalogValidationError):
        loader.validate_catalog(_good_frameworks(), mappings, _good_crosswalks())


def test_real_catalog_has_no_duplicate_control_framework_pairs():
    for control_id, mappings in loader.mappings_doc().items():
        pairs = [m["framework_id"] for m in mappings]
        assert len(pairs) == len(set(pairs)), f"{control_id} has duplicate framework mappings"
