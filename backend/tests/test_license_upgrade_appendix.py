"""Part 7 — reports include a 'Security Improvements Available with License
Upgrade' appendix listing licence-unavailable CA controls, and never count
them as failures.
"""

from app.services.baseline.baseline_definition import LICENSE_GATED_CA_CONTROLS
from app.services.reports.executive_summary_service import (
    build_license_upgrade_appendix,
)


def test_appendix_lists_unevaluated_gated_ca_controls():
    appendix = build_license_upgrade_appendix(evaluated_control_ids={"IDENTITY_USER_NO_MFA"})
    ids = [item["control_id"] for item in appendix]
    assert set(ids) == set(LICENSE_GATED_CA_CONTROLS)
    for item in appendix:
        assert item["license_required"] == "Entra P1/P2"
        # Enriched with business-grade presentation metadata.
        assert item["name"]
        assert item["narrative"]


def test_appendix_excludes_evaluated_ca_controls():
    appendix = build_license_upgrade_appendix(evaluated_control_ids={"CA_MFA_ALL_USERS"})
    ids = [item["control_id"] for item in appendix]
    assert "CA_MFA_ALL_USERS" not in ids


def test_appendix_empty_when_all_ca_controls_evaluated():
    appendix = build_license_upgrade_appendix(evaluated_control_ids=set(LICENSE_GATED_CA_CONTROLS))
    assert appendix == []
