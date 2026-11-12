"""OAUTH_REVIEW now covers two independently-fanned-out controls
(IDENTITY_ILLICIT_CONSENT_GRANTS and the new IDENTITY_OAUTH_APP_CONSENT_DISCOVERY),
but the platform's projector registry allows exactly one projector per
workflow_id (app/services/workflows/_shared/projector_registry.py). The
composite projector dispatches project() across both single-control
projectors and concatenates their resources, without touching
EvidenceFanOutProjector or IDENTITY_ILLICIT_CONSENT_GRANTS's own tested
behavior at all.
"""

from types import SimpleNamespace

from app.services.workflows.oauth_review.projector import OAUTH_REVIEW_PROJECTOR


def _finding(control_id, evidence, finding_id=1):
    return SimpleNamespace(
        id=finding_id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id="tenant-1",
        evidence=evidence,
    )


def test_controls_covers_both_illicit_grants_and_discovery():
    controls = OAUTH_REVIEW_PROJECTOR.controls()
    assert "IDENTITY_ILLICIT_CONSENT_GRANTS" in controls
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in controls


def test_illicit_consent_grants_still_project_correctly():
    """The existing, tested control's behavior must be completely unchanged."""
    finding = _finding(
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
        {
            "illicit_grants": [
                {
                    "id": "grant-1",
                    "clientId": "app-1",
                    "consentType": "Principal",
                    "principalId": "user-1",
                    "scope": "Mail.Read",
                }
            ]
        },
    )

    resources = OAUTH_REVIEW_PROJECTOR.project([finding])

    assert len(resources) == 1
    assert resources[0].key.control_id == "IDENTITY_ILLICIT_CONSENT_GRANTS"
    assert resources[0].key.resource_id == "grant-1"


def test_discovery_grants_project_correctly():
    finding = _finding(
        "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
        {
            "oauth_app_consents": [
                {
                    "grant_id": "grant-2",
                    "client_id": "app-2",
                    "application_name": "App Two",
                    "consent_type": "AllPrincipals",
                    "principal_id": None,
                    "consented_by": "Admin (tenant-wide)",
                    "scope": "User.Read",
                    "scopes": ["User.Read"],
                    "date": None,
                    "date_source": "unknown",
                }
            ]
        },
        finding_id=2,
    )

    resources = OAUTH_REVIEW_PROJECTOR.project([finding])

    assert len(resources) == 1
    assert resources[0].key.control_id == "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"
    assert resources[0].key.resource_id == "grant-2"


def test_both_controls_together_produce_resources_for_each():
    illicit_finding = _finding(
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
        {
            "illicit_grants": [
                {"id": "g1", "clientId": "app-1", "consentType": "Principal", "principalId": "u1", "scope": "Mail.Read"}
            ]
        },
        finding_id=1,
    )
    discovery_finding = _finding(
        "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
        {
            "oauth_app_consents": [
                {
                    "grant_id": "g2",
                    "client_id": "app-2",
                    "application_name": "App Two",
                    "consent_type": "AllPrincipals",
                    "principal_id": None,
                    "consented_by": "Admin (tenant-wide)",
                    "scope": "User.Read",
                    "scopes": ["User.Read"],
                    "date": None,
                    "date_source": "unknown",
                }
            ]
        },
        finding_id=2,
    )

    resources = OAUTH_REVIEW_PROJECTOR.project([illicit_finding, discovery_finding])

    keys = {(r.key.control_id, r.key.resource_id) for r in resources}
    assert ("IDENTITY_ILLICIT_CONSENT_GRANTS", "g1") in keys
    assert ("IDENTITY_OAUTH_APP_CONSENT_DISCOVERY", "g2") in keys


def test_a_finding_for_an_unrelated_control_produces_no_resources():
    finding = _finding("SOME_OTHER_CONTROL", {"whatever": []})
    resources = OAUTH_REVIEW_PROJECTOR.project([finding])
    assert resources == []


def test_workflow_id_is_oauth_review():
    assert OAUTH_REVIEW_PROJECTOR.workflow_id == "OAUTH_REVIEW"
