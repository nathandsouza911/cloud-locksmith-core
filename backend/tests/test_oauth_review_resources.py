"""Sprint 5 — OAuth review resources.

The detector produces ONE tenant-level finding whose evidence holds a list of
grants. A technician reviews one *application* at a time, so the finding is
projected into per-grant review resources. Projection only — the finding is not
split, re-detected or mutated.
"""

import pytest

from app.services.workflows.oauth_review.resources import (
    RiskLevel,
    build_review_resources,
    classify_grant_risk,
    normalize_grant,
    scope_risk,
)

GRANT = {
    "id": "grant-1",
    "clientId": "app-1",
    "resourceId": "resource-1",
    "principalId": "user-1",
    "consentType": "Principal",
    "scope": "Mail.Read Files.Read.All",
    "matched_scopes": ["Files.Read.All", "Mail.Read"],
}


def _evidence(*grants):
    return {"illicit_grants": list(grants), "total_grants_examined": len(grants)}


# ── Normalisation ───────────────────────────────────────────────────────────


def test_a_graph_grant_is_normalised_to_stable_field_names():
    normalized = normalize_grant(GRANT)

    assert normalized["grant_id"] == "grant-1"
    assert normalized["client_id"] == "app-1"
    assert normalized["consent_type"] == "Principal"
    assert normalized["principal_id"] == "user-1"
    assert normalized["scopes"] == ["Files.Read.All", "Mail.Read"]


def test_scopes_are_parsed_from_the_space_delimited_graph_string():
    normalized = normalize_grant({**GRANT, "scope": "Mail.Read  Files.Read.All "})

    assert normalized["scopes"] == ["Files.Read.All", "Mail.Read"]


def test_a_grant_with_no_scope_normalises_to_an_empty_list():
    assert normalize_grant({**GRANT, "scope": None})["scopes"] == []


def test_enrichment_fields_are_carried_through_when_present():
    enriched = {
        **GRANT,
        "app_display_name": "Zapier",
        "publisher": "Zapier Inc",
        "verified_publisher": True,
        "last_used": "2026-07-30T00:00:00",
        "owners": ["owner-1"],
    }

    normalized = normalize_grant(enriched)

    assert normalized["application_name"] == "Zapier"
    assert normalized["publisher"] == "Zapier Inc"
    assert normalized["verified_publisher"] is True
    assert normalized["last_used"] == "2026-07-30T00:00:00"
    assert normalized["owners"] == ["owner-1"]


def test_a_grant_without_a_display_name_falls_back_to_its_client_id():
    assert normalize_grant(GRANT)["application_name"] == "app-1"


# ── Scope risk ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "scope",
    ["Mail.ReadWrite", "Directory.ReadWrite.All", "Files.ReadWrite.All", "Mail.Send"],
)
def test_write_and_send_scopes_are_critical(scope):
    assert scope_risk(scope) == RiskLevel.CRITICAL


@pytest.mark.parametrize("scope", ["Mail.Read", "Files.Read.All", "Directory.Read.All"])
def test_broad_read_scopes_are_high(scope):
    assert scope_risk(scope) == RiskLevel.HIGH


def test_offline_access_is_high_because_it_outlives_the_session():
    assert scope_risk("offline_access") == RiskLevel.HIGH


def test_an_unrecognised_scope_is_not_assumed_harmless():
    """Unknown scopes get a floor, not a free pass."""
    assert scope_risk("Some.Unknown.Scope") in (RiskLevel.MEDIUM, RiskLevel.HIGH)


def test_a_narrow_profile_scope_is_low():
    assert scope_risk("User.Read") == RiskLevel.LOW


# ── Grant risk classification ───────────────────────────────────────────────


def test_a_grant_takes_the_risk_of_its_worst_scope():
    grant = normalize_grant({**GRANT, "scope": "User.Read Mail.ReadWrite"})

    assert classify_grant_risk(grant).level == RiskLevel.CRITICAL


def test_tenant_wide_consent_escalates_risk():
    """AllPrincipals means every user in the tenant, not one."""
    single = classify_grant_risk(normalize_grant({**GRANT, "scope": "User.Read"}))
    tenant_wide = classify_grant_risk(normalize_grant({**GRANT, "scope": "User.Read", "consentType": "AllPrincipals"}))

    assert tenant_wide.level != single.level


def test_an_unverified_publisher_is_called_out_in_the_explanation():
    grant = normalize_grant({**GRANT, "verified_publisher": False})

    explanation = classify_grant_risk(grant).explanation

    assert "publisher" in explanation.lower()


def test_the_explanation_names_the_scopes_that_drove_the_risk():
    grant = normalize_grant({**GRANT, "scope": "Mail.ReadWrite"})

    assert "Mail.ReadWrite" in classify_grant_risk(grant).explanation


def test_the_explanation_is_written_for_a_human_not_a_machine():
    grant = normalize_grant(GRANT)
    explanation = classify_grant_risk(grant).explanation

    assert len(explanation) > 40
    assert explanation[0].isupper()


def test_a_critical_grant_is_recommended_for_revocation():
    grant = normalize_grant({**GRANT, "scope": "Mail.ReadWrite"})

    assert classify_grant_risk(grant).recommended_action == "REVOKE"


def test_a_low_risk_grant_is_not_recommended_for_revocation():
    grant = normalize_grant({**GRANT, "scope": "User.Read"})

    assert classify_grant_risk(grant).recommended_action != "REVOKE"


# ── Building review resources ───────────────────────────────────────────────


def test_each_grant_becomes_its_own_review_resource():
    evidence = _evidence(
        GRANT,
        {**GRANT, "id": "grant-2", "clientId": "app-2"},
    )

    resources = build_review_resources(evidence)

    assert len(resources) == 2
    assert {r.grant_id for r in resources} == {"grant-1", "grant-2"}


def test_a_review_resource_exposes_everything_the_reviewer_needs():
    resource = build_review_resources(_evidence(GRANT))[0]

    assert resource.grant_id
    assert resource.application_name
    assert resource.scopes
    assert resource.consent_type
    assert resource.risk_level
    assert resource.risk_explanation
    assert resource.recommended_action
    assert resource.evidence
    assert resource.evidence_hash


def test_each_resource_gets_its_own_evidence_fingerprint():
    resources = build_review_resources(_evidence(GRANT, {**GRANT, "id": "grant-2", "clientId": "app-2"}))

    assert resources[0].evidence_hash != resources[1].evidence_hash


def test_a_scope_change_changes_that_resources_fingerprint():
    before = build_review_resources(_evidence(GRANT))[0]
    after = build_review_resources(_evidence({**GRANT, "scope": "Mail.Read Files.Read.All Mail.ReadWrite"}))[0]

    assert before.evidence_hash != after.evidence_hash


def test_resources_are_ordered_riskiest_first():
    low = {**GRANT, "id": "low", "scope": "User.Read"}
    critical = {**GRANT, "id": "critical", "scope": "Mail.ReadWrite"}

    resources = build_review_resources(_evidence(low, critical))

    assert resources[0].grant_id == "critical"


def test_ordering_is_stable_for_equal_risk():
    a = {**GRANT, "id": "a", "scope": "Mail.Read"}
    b = {**GRANT, "id": "b", "scope": "Mail.Read"}

    first = [r.grant_id for r in build_review_resources(_evidence(a, b))]
    second = [r.grant_id for r in build_review_resources(_evidence(a, b))]

    assert first == second


def test_evidence_with_no_grants_produces_no_resources():
    assert build_review_resources(_evidence()) == []


def test_missing_evidence_is_handled_without_raising():
    assert build_review_resources({}) == []
    assert build_review_resources(None) == []


def test_a_grant_without_an_id_is_skipped_rather_than_crashing():
    """A resource with no identity cannot be reviewed or revoked safely."""
    resources = build_review_resources(_evidence({**GRANT, "id": None}, GRANT))

    assert [r.grant_id for r in resources] == ["grant-1"]


def test_building_resources_does_not_mutate_the_evidence():
    evidence = _evidence(GRANT)
    snapshot = repr(evidence)

    build_review_resources(evidence)

    assert repr(evidence) == snapshot
