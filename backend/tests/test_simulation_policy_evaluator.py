"""Policy assignment rules shared by Simulate Fix and the CA coverage report (ROADMAP 3.1).

Graph semantics (learn.microsoft.com, conditionalAccessUsers): a policy applies only to
the users it includes; an empty include scope or ``None`` includes no one; exclusions win.
"""

from app.simulation.policy_evaluator import get_applicable_policies, match_policy
from app.simulation.policy_parser import PolicyParser

GROUPS = {"g-excl": ["u2"], "g-incl": ["u3"]}
ROLES = {"role-ga": ["u1"]}


def _policy(users: dict, **extra) -> object:
    raw = {"id": "p1", "displayName": "P1", "state": "enabled", "conditions": {"users": users}}
    raw.update(extra)
    return PolicyParser().parse(raw)


def _applies(policy, user_id, guest_ids=frozenset()):
    return bool(get_applicable_policies(user_id, [policy], GROUPS, ROLES, guest_ids=guest_ids))


def test_empty_include_scope_applies_to_no_one():
    assert not _applies(_policy({"includeUsers": [], "includeGroups": [], "includeRoles": []}), "u1")


def test_none_include_applies_to_no_one():
    assert not _applies(_policy({"includeUsers": ["None"]}), "u1")


def test_all_users_applies_to_everyone_not_excluded():
    policy = _policy({"includeUsers": ["All"], "excludeGroups": ["g-excl"]})
    assert _applies(policy, "u1")
    assert not _applies(policy, "u2")


def test_role_and_group_includes():
    assert _applies(_policy({"includeRoles": ["role-ga"]}), "u1")
    assert _applies(_policy({"includeGroups": ["g-incl"]}), "u3")
    assert not _applies(_policy({"includeGroups": ["g-incl"]}), "u1")


def test_guest_include_is_not_counted_as_covering():
    policy = _policy({"includeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"}})
    assert not _applies(policy, "guest-1", guest_ids={"guest-1"})
    assert not _applies(_policy({"includeUsers": ["GuestsOrExternalUsers"]}), "guest-1", guest_ids={"guest-1"})


def test_guest_exclude_excludes_every_guest():
    policy = _policy(
        {
            "includeUsers": ["All"],
            "excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "internalGuest"},
        }
    )
    assert not _applies(policy, "guest-1", guest_ids={"guest-1"})
    assert _applies(policy, "u1", guest_ids={"guest-1"})


def test_match_policy_explains_exclusion():
    policy = _policy({"includeUsers": ["All"], "excludeGroups": ["g-excl"], "excludeRoles": ["role-ga"]})
    by_group = match_policy("u2", policy, GROUPS, ROLES)
    assert by_group.included and by_group.excluded_by == ("group", "g-excl")
    by_role = match_policy("u1", policy, GROUPS, ROLES)
    assert by_role.excluded_by == ("role", "role-ga")
    direct = match_policy("u9", _policy({"includeUsers": ["All"], "excludeUsers": ["u9"]}), GROUPS, ROLES)
    assert direct.excluded_by == ("user", "u9")
    assert match_policy("u3", policy, GROUPS, ROLES).applies


def test_parser_reads_apps_client_types_grant_and_conditions():
    policy = PolicyParser().parse(
        {
            "id": "p",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {
                    "includeApplications": ["All"],
                    "excludeApplications": ["app-1"],
                    "includeUserActions": [],
                },
                "clientAppTypes": ["exchangeActiveSync", "other"],
                "locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]},
                "platforms": None,
                "signInRiskLevels": ["high"],
                "userRiskLevels": [],
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa", "compliantDevice"],
                "authenticationStrength": {"id": "x"},
            },
        }
    )
    assert policy.include_applications == ["All"]
    assert policy.exclude_applications == ["app-1"]
    assert policy.client_app_types == ["exchangeActiveSync", "other"]
    assert policy.grant_operator == "OR"
    assert policy.has_authentication_strength is True
    assert policy.narrowing_conditions == ["locations", "sign-in risk"]
    assert policy.state == "enabledForReportingButNotEnforced"
