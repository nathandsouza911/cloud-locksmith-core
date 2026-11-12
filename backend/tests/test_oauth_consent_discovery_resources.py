"""Resource projection for IDENTITY_OAUTH_APP_CONSENT_DISCOVERY.

Discovery only: no risk score, no severity classification, no verdict. The
platform's ReviewResource still requires risk_level/recommended_action
fields structurally -- this module supplies a fixed, neutral placeholder,
never a real assessment, and documents why.
"""

from types import SimpleNamespace

from app.services.workflows.oauth_review.consent_discovery_resources import (
    CONSENT_DISCOVERY_CONTROL_ID,
    DISCOVERY_RISK_LEVEL,
    build_consent_discovery_resource,
)

ENTRY = {
    "grant_id": "grant-1",
    "client_id": "sp-1",
    "service_principal_id": "sp-1",
    "resource_id": "resource-sp",
    "application_name": "Contoso App",
    "consent_type": "Principal",
    "principal_id": "user-1",
    "consented_by": "Jane Doe",
    "scope": "User.Read Mail.Read",
    "scopes": ["Mail.Read", "User.Read"],
    "date": None,
    "date_source": "unknown",
}


def test_control_id_is_the_dedicated_discovery_control():
    assert CONSENT_DISCOVERY_CONTROL_ID == "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"


def test_resource_title_is_the_application_name():
    resource = build_consent_discovery_resource(ENTRY, None)
    assert resource.title == "Contoso App"


def test_resource_key_is_keyed_on_grant_id():
    resource = build_consent_discovery_resource(ENTRY, None)
    assert resource.key.control_id == CONSENT_DISCOVERY_CONTROL_ID
    assert resource.key.resource_id == "grant-1"


def test_resource_carries_no_real_risk_assessment():
    """Discovery only -- the risk fields are a fixed neutral placeholder,
    never computed from scopes/consent-type the way OAuthReviewResource's
    classify_grant_risk does for illicit-consent-grants.
    """
    resource = build_consent_discovery_resource(ENTRY, None)
    assert resource.risk_level == DISCOVERY_RISK_LEVEL
    assert resource.recommended_action == "REVIEW"
    assert resource.risk_drivers == []


def test_facts_show_the_four_column_contract():
    resource = build_consent_discovery_resource(ENTRY, None)
    labels = {fact.label: fact.value for fact in resource.facts}
    assert labels["Consented by"] == "Jane Doe"
    assert "Mail.Read" in labels["Permissions"]
    assert "User.Read" in labels["Permissions"]
    assert labels["Date"] == "Unknown"


def test_date_shows_unknown_not_blank_and_not_fabricated():
    resource = build_consent_discovery_resource(ENTRY, None)
    facts = {f.label: f.value for f in resource.facts}
    assert facts["Date"] == "Unknown"


def test_a_real_date_when_present_is_shown_verbatim_not_reinterpreted():
    dated = {**ENTRY, "date": "2026-06-01T00:00:00Z", "date_source": "audit_log"}
    resource = build_consent_discovery_resource(dated, None)
    facts = {f.label: f.value for f in resource.facts}
    assert facts["Date"] == "2026-06-01T00:00:00Z"


def test_evidence_carries_stable_identifiers_for_future_review_and_revocation():
    resource = build_consent_discovery_resource(ENTRY, None)
    for field in (
        "grant_id",
        "client_id",
        "service_principal_id",
        "application_name",
        "consent_type",
        "principal_id",
        "scopes",
        "date",
        "date_source",
    ):
        assert field in resource.evidence


def test_evidence_fingerprint_is_stable_and_present():
    resource = build_consent_discovery_resource(ENTRY, None)
    assert resource.evidence_hash


def test_compliance_result_id_is_carried_from_the_finding():
    finding = SimpleNamespace(id=42)
    resource = build_consent_discovery_resource(ENTRY, finding)
    assert resource.compliance_result_id == 42


def test_projecting_does_not_mutate_the_source_entry():
    original = dict(ENTRY)
    build_consent_discovery_resource(ENTRY, None)
    assert ENTRY == original
