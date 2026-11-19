"""The CA payload schema must never silently drop a condition (review 2026-11-19, R1-1).

Pydantic ignores unknown fields by default, and the schema listed only users,
applications, clientAppTypes and authenticationFlows. Every other condition was
removed before the POST/PATCH: CA_HIGH_RISK_SIGN_IN_BLOCK lost signInRiskLevels and
was written as "block All users, All apps". A condition the schema does not know
must now fail before any write, and the known ones must reach Graph unchanged.
"""

import pytest
from pydantic import ValidationError

from app.api.v1.remediation_rollback import CA_ENGINE_CONTROLS
from app.schemas.graph_payloads import ConditionalAccessPolicySchema
from app.services.remediation.mfa_policy import (
    build_high_risk_sign_in_block_policy,
    build_risk_based_step_up_mfa_policy,
)

BREAK_GLASS = ["bg-1", "bg-2"]


def _dump(payload: dict) -> dict:
    return ConditionalAccessPolicySchema.model_validate(payload).model_dump(mode="json", exclude_none=True)


def test_high_risk_block_keeps_its_sign_in_risk_condition():
    sent = _dump(build_high_risk_sign_in_block_policy(exclude_users=BREAK_GLASS))
    assert sent["conditions"]["signInRiskLevels"] == ["high"]
    assert sent["grantControls"]["builtInControls"] == ["block"]
    assert sent["conditions"]["users"]["excludeUsers"] == BREAK_GLASS


def test_risk_based_step_up_keeps_its_sign_in_risk_condition():
    sent = _dump(build_risk_based_step_up_mfa_policy(exclude_users=BREAK_GLASS))
    assert sent["conditions"]["signInRiskLevels"] == ["medium", "high"]


def _tenant_policy(**condition_overrides) -> dict:
    """A policy as Graph returns it on GET (read-only fields included)."""
    conditions = {
        "users": {"includeUsers": ["All"], "excludeUsers": ["bg-1"]},
        "applications": {
            "includeApplications": ["All"],
            "excludeApplications": [],
            "includeUserActions": [],
            "includeAuthenticationContextClassReferences": [],
            "applicationFilter": None,
        },
        "clientAppTypes": ["all"],
        "signInRiskLevels": [],
        "userRiskLevels": ["high"],
        "servicePrincipalRiskLevels": [],
        "insiderRiskLevels": None,
        "locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]},
        "platforms": {"includePlatforms": ["android", "iOS"], "excludePlatforms": []},
        "devices": {"deviceFilter": {"mode": "exclude", "rule": 'device.trustType -eq "ServerAD"'}},
        "clientApplications": None,
        "authenticationFlows": None,
    }
    conditions.update(condition_overrides)
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies/$entity",
        "id": "11111111-2222-3333-4444-555555555555",
        "templateId": None,
        "displayName": "Block outside trusted locations",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "modifiedDateTime": "2026-02-01T00:00:00Z",
        "state": "enabled",
        "conditions": conditions,
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
            "customAuthenticationFactors": [],
            "termsOfUse": [],
            "authenticationStrength": None,
        },
        "sessionControls": {"signInFrequency": {"value": 4, "type": "hours", "isEnabled": True}},
    }


def test_a_tenant_policy_round_trips_every_condition():
    """Rollback re-creates a policy from its tenant snapshot: nothing may be lost."""
    sent = _dump(_tenant_policy())
    conditions = sent["conditions"]
    assert conditions["locations"] == {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}
    assert conditions["platforms"]["includePlatforms"] == ["android", "iOS"]
    assert conditions["devices"]["deviceFilter"]["mode"] == "exclude"
    assert conditions["userRiskLevels"] == ["high"]
    assert sent["sessionControls"]["signInFrequency"]["value"] == 4


def test_read_only_fields_from_a_tenant_read_are_not_sent():
    sent = _dump(_tenant_policy())
    for key in ("@odata.context", "id", "templateId", "createdDateTime", "modifiedDateTime"):
        assert key not in sent


@pytest.mark.parametrize("path", ["conditions", "users", "applications", "grantControls", "policy"])
def test_an_unknown_field_fails_before_any_write(path):
    payload = _tenant_policy()
    target = {
        "conditions": payload["conditions"],
        "users": payload["conditions"]["users"],
        "applications": payload["conditions"]["applications"],
        "grantControls": payload["grantControls"],
        "policy": payload,
    }[path]
    target["someFutureCondition"] = ["x"]
    with pytest.raises(ValidationError):
        ConditionalAccessPolicySchema.model_validate(payload)


@pytest.mark.parametrize("control_id", ["CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"])
def test_risk_controls_can_be_rolled_back_by_the_ca_engine(control_id):
    assert control_id in CA_ENGINE_CONTROLS
