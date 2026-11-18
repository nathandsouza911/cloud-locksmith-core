"""Tenant-level Conditional Access checks apply the same per-policy rules as CA Coverage.

A policy only satisfies a tenant-level check if it covers every sign-in it is meant to:
all cloud apps with no app excluded, all client app types, and no condition that narrows
when it applies (locations, platforms, risk, device filter, authentication flows), except
the one condition the check is about. CA-09 accepts a block on client app type "all"
(Graph includes the legacy types in it), and both CA-09 and the coverage page accept the
two legacy types being blocked by two policies.
"""

from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone

import pytest

from app.services.detection.conditional_access.ca_auth_vector_checks import (
    detect_ca_authentication_transfer_blocked,
    detect_ca_device_code_flow_blocked,
    detect_ca_legacy_auth_other_blocked,
)
from app.services.detection.conditional_access.ca_mfa_checks import detect_ca_mfa_admins, detect_ca_mfa_all_users
from app.services.detection.conditional_access.ca_risk_checks import (
    detect_ca_high_risk_sign_in_block,
    detect_ca_risk_based_step_up_mfa,
)
from app.services.detection.conditional_access.constants import PRIVILEGED_ROLE_TEMPLATE_IDS
from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.remediation import mfa_policy
from app.simulation.coverage import COVERED, build_coverage
from app.simulation.tenant_reader import TenantIdentity

ALL_USERS = {"includeUsers": ["All"]}
ADMIN_ROLES = {"includeRoles": sorted(PRIVILEGED_ROLE_TEMPLATE_IDS)}


def _policy(users: dict, grant: list[str], operator: str = "OR", **conditions) -> dict:
    return {
        "id": "p",
        "displayName": "p",
        "state": "enabled",
        "conditions": {"users": users, "applications": {"includeApplications": ["All"]}, **conditions},
        "grantControls": {"operator": operator, "builtInControls": grant},
    }


def _passed(detector, policies: list[dict]) -> bool:
    ctx = TenantGraphContext(
        tenant_id="t",
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=policies,
        break_glass_accounts=[],
    )
    return asyncio.run(detector(ctx=ctx))[0]["passed"]


# Each check with a policy that satisfies it.
CHECKS = {
    "mfa_all_users": (detect_ca_mfa_all_users, _policy(ALL_USERS, ["mfa"])),
    "mfa_admins": (detect_ca_mfa_admins, _policy(ADMIN_ROLES, ["mfa"])),
    "legacy_auth": (
        detect_ca_legacy_auth_other_blocked,
        _policy(ALL_USERS, ["block"], clientAppTypes=["exchangeActiveSync", "other"]),
    ),
    "device_code": (
        detect_ca_device_code_flow_blocked,
        _policy(ALL_USERS, ["block"], authenticationFlows={"transferMethods": "deviceCodeFlow"}),
    ),
    "auth_transfer": (
        detect_ca_authentication_transfer_blocked,
        _policy(ALL_USERS, ["block"], authenticationFlows={"transferMethods": "authenticationTransfer"}),
    ),
    "high_risk_block": (detect_ca_high_risk_sign_in_block, _policy(ALL_USERS, ["block"], signInRiskLevels=["high"])),
    "risk_step_up_mfa": (
        detect_ca_risk_based_step_up_mfa,
        _policy(ALL_USERS, ["mfa"], signInRiskLevels=["medium", "high"]),
    ),
}

# Changes that make a policy cover only some sign-ins.
NARROWING = {
    "excluded app": lambda c: c["applications"].update(excludeApplications=["00000002-0000-0ff1-ce00-000000000000"]),
    "untrusted locations only": lambda c: c.update(
        locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}
    ),
    "android only": lambda c: c.update(platforms={"includePlatforms": ["android"]}),
    "device filter": lambda c: c.update(
        devices={"deviceFilter": {"mode": "include", "rule": 'device.trustType -eq "AzureAD"'}}
    ),
    "user risk": lambda c: c.update(userRiskLevels=["high"]),
}


@pytest.mark.parametrize("check", sorted(CHECKS))
def test_check_passes_its_reference_policy_with_a_break_glass_exclusion(check):
    detector, policy = CHECKS[check]
    policy = copy.deepcopy(policy)
    policy["conditions"]["users"]["excludeUsers"] = ["break-glass-1"]
    assert _passed(detector, [policy]) is True


@pytest.mark.parametrize("narrowing", sorted(NARROWING))
@pytest.mark.parametrize("check", sorted(CHECKS))
def test_check_fails_when_the_policy_covers_only_some_sign_ins(check, narrowing):
    detector, policy = CHECKS[check]
    policy = copy.deepcopy(policy)
    NARROWING[narrowing](policy["conditions"])
    assert _passed(detector, [policy]) is False


@pytest.mark.parametrize("check", ["device_code", "auth_transfer", "high_risk_block"])
def test_block_check_fails_when_policy_adds_an_unrelated_condition(check):
    detector, policy = CHECKS[check]
    policy = copy.deepcopy(policy)
    if check == "high_risk_block":
        policy["conditions"]["authenticationFlows"] = {"transferMethods": "deviceCodeFlow"}
    else:
        policy["conditions"]["signInRiskLevels"] = ["high"]
    assert _passed(detector, [policy]) is False


@pytest.mark.parametrize("check", ["mfa_all_users", "mfa_admins", "risk_step_up_mfa"])
def test_mfa_check_fails_for_browser_only_or_mfa_or_another_control(check):
    detector, policy = CHECKS[check]
    browser_only = copy.deepcopy(policy)
    browser_only["conditions"]["clientAppTypes"] = ["browser"]
    assert _passed(detector, [browser_only]) is False

    mfa_or_compliant = copy.deepcopy(policy)
    mfa_or_compliant["grantControls"]["builtInControls"] = ["mfa", "compliantDevice"]
    assert _passed(detector, [mfa_or_compliant]) is False

    mfa_and_compliant = copy.deepcopy(mfa_or_compliant)
    mfa_and_compliant["grantControls"]["operator"] = "AND"
    assert _passed(detector, [mfa_and_compliant]) is True


@pytest.mark.parametrize("client_app_types", [["all"], []])
def test_legacy_check_accepts_a_block_on_all_client_app_types(client_app_types):
    policy = _policy(ALL_USERS, ["block"], clientAppTypes=client_app_types)
    assert _passed(detect_ca_legacy_auth_other_blocked, [policy]) is True


# Apply's own policies, switched to enforced, must pass the check they fix.
APPLY = {
    "mfa_all_users": lambda: mfa_policy.build_mfa_all_users_policy(exclude_users=["bg"]),
    "mfa_admins": lambda: mfa_policy.build_mfa_admins_policy(),
    "legacy_auth": lambda: mfa_policy.build_legacy_auth_block_policy(exclude_users=["bg"]),
    "device_code": lambda: mfa_policy.build_device_code_flow_block_policy(exclude_users=["bg"]),
    "auth_transfer": lambda: mfa_policy.build_authentication_transfer_block_policy(exclude_users=["bg"]),
    "high_risk_block": lambda: mfa_policy.build_high_risk_sign_in_block_policy(exclude_users=["bg"]),
    "risk_step_up_mfa": lambda: mfa_policy.build_risk_based_step_up_mfa_policy(exclude_users=["bg"]),
}


@pytest.mark.parametrize("check", sorted(CHECKS))
def test_apply_policy_passes_its_check(check):
    policy = APPLY[check]()
    policy["state"] = "enabled"
    policy.setdefault("id", f"apply-{check}")
    assert _passed(CHECKS[check][0], [policy]) is True


# The coverage page and the tenant-level checks must agree on the same policies.
USERS = [
    {"id": u, "displayName": u, "userPrincipalName": f"{u}@x", "accountEnabled": True, "userType": "Member"}
    for u in ("alice", "bob")
]


def _all_users_covered(policies: list[dict], key: str) -> bool:
    identity = TenantIdentity(users=USERS, policies=policies)
    return all(row[key]["status"] == COVERED for row in build_coverage(identity)["users"])


def _two(*policies: dict) -> list[dict]:
    out = []
    for index, policy in enumerate(policies):
        policy = copy.deepcopy(policy)
        policy["id"] = policy["displayName"] = f"p{index}"
        out.append(policy)
    return out


LEGACY_SCENARIOS = {
    "both types, one policy": [_policy(ALL_USERS, ["block"], clientAppTypes=["exchangeActiveSync", "other"])],
    "both types, two policies": _two(
        _policy(ALL_USERS, ["block"], clientAppTypes=["exchangeActiveSync"]),
        _policy(ALL_USERS, ["block"], clientAppTypes=["other"]),
    ),
    "one type only": [_policy(ALL_USERS, ["block"], clientAppTypes=["exchangeActiveSync"])],
    "all client types": [_policy(ALL_USERS, ["block"], clientAppTypes=["all"])],
    "untrusted locations only": [
        _policy(
            ALL_USERS,
            ["block"],
            clientAppTypes=["exchangeActiveSync", "other"],
            locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]},
        )
    ],
    "excluded app": [
        {
            **_policy(ALL_USERS, ["block"], clientAppTypes=["exchangeActiveSync", "other"]),
            "conditions": {
                "users": ALL_USERS,
                "applications": {"includeApplications": ["All"], "excludeApplications": ["app-1"]},
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
        }
    ],
}

MFA_SCENARIOS = {
    "mfa all apps": [_policy(ALL_USERS, ["mfa"], clientAppTypes=["all"])],
    "mfa untrusted locations only": [
        _policy(
            ALL_USERS,
            ["mfa"],
            clientAppTypes=["all"],
            locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]},
        )
    ],
    "mfa browser only": [_policy(ALL_USERS, ["mfa"], clientAppTypes=["browser"])],
    "mfa or compliant device": [_policy(ALL_USERS, ["mfa", "compliantDevice"], clientAppTypes=["all"])],
    "mfa android only": [
        _policy(ALL_USERS, ["mfa"], clientAppTypes=["all"], platforms={"includePlatforms": ["android"]})
    ],
}


@pytest.mark.parametrize("scenario", sorted(LEGACY_SCENARIOS))
def test_coverage_and_legacy_check_agree(scenario):
    policies = LEGACY_SCENARIOS[scenario]
    assert _all_users_covered(policies, "legacy_auth") == _passed(detect_ca_legacy_auth_other_blocked, policies)


@pytest.mark.parametrize("scenario", sorted(MFA_SCENARIOS))
def test_coverage_and_mfa_all_users_check_agree(scenario):
    policies = MFA_SCENARIOS[scenario]
    assert _all_users_covered(policies, "mfa") == _passed(detect_ca_mfa_all_users, policies)


def test_two_policies_each_blocking_one_legacy_type_cover_the_user():
    policies = LEGACY_SCENARIOS["both types, two policies"]
    assert _all_users_covered(policies, "legacy_auth") is True
