"""SCuBA references must be real, verbatim and honestly graded (ROADMAP 3.2).

Before 2026-11-15 the catalog cited MS.AAD.3.3v1, 7.3v1 and 7.4v1 with statement text
that does not exist in CISA's baseline, although its README called the SCuBA IDs
authoritative. Every cisa-scuba reference must now be an ID in
control_catalog/scuba_statements.json (copied verbatim from cisagov/ScubaGear) and its
report_label must be that statement, word for word. "Maps to" is not compliance.
"""

import json
from pathlib import Path

from app.services.compliance_enrichment import framework_reference_fields
from app.services.control_catalog import loader

STATEMENTS = json.loads((Path(loader.__file__).parent / "scuba_statements.json").read_text(encoding="utf-8"))[
    "statements"
]


def _scuba(control_id):
    return [m for m in loader.get_control_mappings(control_id) if m["framework_id"] == "cisa-scuba"]


def test_every_scuba_reference_exists_and_quotes_the_statement():
    for control_id, mappings in loader.mappings_doc().items():
        for m in mappings:
            if m["framework_id"] != "cisa-scuba":
                continue
            assert m["reference_id"] in STATEMENTS, (control_id, m["reference_id"])
            assert m["report_label"] == STATEMENTS[m["reference_id"]], control_id


EXPECTED = {
    "CA_LEGACY_AUTH_BLOCK": ("MS.AAD.1.1v1", "direct"),
    "CA_HIGH_RISK_SIGN_IN_BLOCK": ("MS.AAD.2.3v1", "direct"),
    "CA_RISK_BASED_STEP_UP_MFA": ("MS.AAD.2.3v1", "partial"),
    "CA_MFA_ALL_USERS": ("MS.AAD.3.2v2", "direct"),
    "IDENTITY_USER_NO_MFA": ("MS.AAD.3.2v2", "evidence"),
    "CA_GUEST_MFA": ("MS.AAD.3.2v2", "partial"),
    "CA_MFA_ADMINS": ("MS.AAD.3.6v1", "partial"),
    "IDENTITY_ADMIN_NO_MFA": ("MS.AAD.3.6v1", "partial"),
    "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA": ("MS.AAD.3.6v1", "direct"),
    "CA_DEVICE_CODE_FLOW_BLOCK": ("MS.AAD.3.9v1", "direct"),
    "IDENTITY_USER_CONSENT_POLICY": ("MS.AAD.5.2v1", "direct"),
    "IDENTITY_ILLICIT_CONSENT_GRANTS": ("MS.AAD.5.2v1", "evidence"),
    "IDENTITY_ADMIN_COUNT_EXCESS": ("MS.AAD.7.1v1", "partial"),
    "IDENTITY_OVERPRIVILEGED_USER": ("MS.AAD.7.2v1", "partial"),
    "IDENTITY_PERMANENT_ROLE_ASSIGNMENT": ("MS.AAD.7.4v1", "direct"),
    "IDENTITY_GUEST_INVITES_OPEN": ("MS.AAD.8.2v1", "direct"),
    "IDENTITY_MAIL_FORWARDING_RULE": ("MS.EXO.1.1v2", "partial"),
}


def test_scuba_mapping_table():
    actual = {}
    for control_id in loader.mappings_doc():
        found = _scuba(control_id)
        if found:
            actual[control_id] = (found[0]["reference_id"], found[0]["mapping_strength"])
    assert actual == EXPECTED


def test_password_never_expires_is_not_mapped_to_scuba():
    """SCuBA MS.AAD.6.1v1 says passwords SHALL NOT expire: the opposite of this control."""
    assert _scuba("IDENTITY_PASSWORD_NEVER_EXPIRES") == []


def test_unverified_cis_numbers_are_not_printed():
    """CIS reference numbers were inferred, not taken from the licensed benchmark: keep
    them in the catalog for review, but do not show them in reports or CSVs."""
    assert loader.get_framework("cis-m365")["verified"] is False
    assert framework_reference_fields("CA_LEGACY_AUTH_BLOCK")["cis_refs"] == ""
    assert framework_reference_fields("CA_LEGACY_AUTH_BLOCK")["scuba_refs"] == "MS.AAD.1.1v1"


def test_loader_rejects_a_scuba_reference_that_is_not_in_the_baseline():
    import copy

    import pytest

    from app.services.control_catalog.schema import CatalogValidationError

    mappings = copy.deepcopy(loader.mappings_doc())
    mappings["CA_LEGACY_AUTH_BLOCK"][[m["framework_id"] for m in mappings["CA_LEGACY_AUTH_BLOCK"]].index("cisa-scuba")][
        "reference_id"
    ] = "MS.AAD.7.3v9"
    with pytest.raises(CatalogValidationError, match="SCuBA"):
        loader.validate_catalog(loader.frameworks_doc(), mappings, loader.crosswalks_doc())
