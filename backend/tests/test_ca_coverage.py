"""Per-user Conditional Access coverage (ROADMAP 3.1): statuses and reasons."""

from app.simulation.coverage import build_coverage
from app.simulation.tenant_reader import TenantIdentity

GA = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator template (privileged)
READER = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # Directory Readers template (not privileged)

USERS = [
    {
        "id": "admin",
        "displayName": "Admin",
        "userPrincipalName": "admin@x",
        "accountEnabled": True,
        "userType": "Member",
    },
    {
        "id": "alice",
        "displayName": "Alice",
        "userPrincipalName": "alice@x",
        "accountEnabled": True,
        "userType": "Member",
    },
    {"id": "bob", "displayName": "Bob", "userPrincipalName": "bob@x", "accountEnabled": True, "userType": "Member"},
    {
        "id": "guest",
        "displayName": "Guest",
        "userPrincipalName": "g#EXT#@x",
        "accountEnabled": True,
        "userType": "Guest",
    },
]


def _policy(name, users, *, state="enabled", grant=("mfa",), apps=None, conditions=None, operator="OR", strength=None):
    cond = {"users": users, "applications": apps or {"includeApplications": ["All"]}, "clientAppTypes": ["all"]}
    cond.update(conditions or {})
    grant_controls = {"operator": operator, "builtInControls": list(grant)}
    if strength:
        grant_controls["authenticationStrength"] = strength
    return {"id": name, "displayName": name, "state": state, "conditions": cond, "grantControls": grant_controls}


def _identity(policies, *, security_defaults=False, groups=None):
    return TenantIdentity(
        users=USERS,
        policies=policies,
        groups=groups or {"g-ex": {"name": "CA exclusions", "member_ids": ["bob"]}},
        roles={
            GA: {"name": "Global Administrator", "member_ids": ["admin"]},
            READER: {"name": "Directory Readers", "member_ids": ["alice"]},
        },
        security_defaults_enabled=security_defaults,
    )


def _user(report, user_id):
    return next(u for u in report["users"] if u["id"] == user_id)


def test_no_policies_every_user_has_gaps_with_reason():
    report = build_coverage(_identity([]))
    alice = _user(report, "alice")
    assert alice["mfa"]["status"] == "gap"
    assert alice["mfa"]["reasons"] == ["No policy requires MFA for this user"]
    assert alice["legacy_auth"]["reasons"] == ["No policy blocks legacy authentication for this user"]
    assert report["summary"]["mfa"] == {"covered": 0, "report_only": 0, "gap": 4}


def test_all_users_mfa_policy_with_group_exclusion():
    report = build_coverage(_identity([_policy("MFA all", {"includeUsers": ["All"], "excludeGroups": ["g-ex"]})]))
    assert _user(report, "alice")["mfa"] == {"status": "covered", "policies": ["MFA all"], "reasons": []}
    assert _user(report, "bob")["mfa"]["status"] == "gap"
    assert _user(report, "bob")["mfa"]["reasons"] == ["Excluded from 'MFA all' by group 'CA exclusions'"]


def test_report_only_policy_is_reported_separately():
    report = build_coverage(
        _identity([_policy("MFA all", {"includeUsers": ["All"]}, state="enabledForReportingButNotEnforced")])
    )
    alice = _user(report, "alice")["mfa"]
    assert alice["status"] == "report_only"
    assert alice["policies"] == ["MFA all"]


def test_disabled_policy_is_named_in_the_reason():
    report = build_coverage(_identity([_policy("MFA all", {"includeUsers": ["All"]}, state="disabled")]))
    assert _user(report, "alice")["mfa"]["reasons"] == ["'MFA all' would cover this user but is turned off"]


def test_policy_that_does_not_cover_every_sign_in_is_a_gap_with_reason():
    policies = [
        _policy("Some apps", {"includeUsers": ["All"]}, apps={"includeApplications": ["app-1"]}),
        _policy(
            "Excl apps",
            {"includeUsers": ["All"]},
            apps={"includeApplications": ["All"], "excludeApplications": ["app-2"]},
        ),
        _policy(
            "Untrusted only",
            {"includeUsers": ["All"]},
            conditions={"locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}},
        ),
        _policy("Or device", {"includeUsers": ["All"]}, grant=("mfa", "compliantDevice")),
        _policy("Browser only", {"includeUsers": ["All"]}, conditions={"clientAppTypes": ["browser"]}),
    ]
    reasons = _user(build_coverage(_identity(policies)), "alice")["mfa"]["reasons"]
    assert reasons == [
        "'Some apps' applies only to some applications",
        "'Excl apps' excludes some applications",
        "'Untrusted only' applies only under conditions: locations",
        "'Or device' allows another control instead of MFA",
        "'Browser only' applies only to some client apps",
    ]
    assert _user(build_coverage(_identity(policies)), "alice")["mfa"]["status"] == "gap"


def test_and_grant_and_authentication_strength_require_mfa():
    report = build_coverage(
        _identity([_policy("And", {"includeUsers": ["alice"]}, grant=("mfa", "compliantDevice"), operator="AND")])
    )
    assert _user(report, "alice")["mfa"]["status"] == "covered"
    report = build_coverage(
        _identity([_policy("Strength", {"includeUsers": ["bob"]}, grant=(), strength={"id": "phish"})])
    )
    assert _user(report, "bob")["mfa"]["status"] == "covered"


def test_guest_exclusion_reason():
    policy = _policy(
        "MFA all",
        {
            "includeUsers": ["All"],
            "excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"},
        },
    )
    assert _user(build_coverage(_identity([policy])), "guest")["mfa"]["reasons"] == [
        "Excluded from 'MFA all' as a guest"
    ]


def test_admin_question_only_for_privileged_roles_and_role_exclusion_named():
    policy = _policy("MFA all", {"includeUsers": ["All"], "excludeRoles": [GA]})
    report = build_coverage(_identity([policy]))
    admin = _user(report, "admin")
    assert admin["is_admin"] is True
    assert admin["admin_mfa"]["status"] == "gap"
    assert admin["admin_mfa"]["reasons"] == ["Excluded from 'MFA all' by role 'Global Administrator'"]
    alice = _user(report, "alice")
    assert alice["is_admin"] is False and alice["admin_mfa"]["status"] == "not_applicable"
    assert report["summary"]["admin_mfa"]["not_applicable"] == 3


def test_legacy_auth_block_requires_both_client_types():
    both = _policy(
        "Block legacy",
        {"includeUsers": ["All"], "excludeUsers": ["bob"]},
        grant=("block",),
        conditions={"clientAppTypes": ["exchangeActiveSync", "other"]},
    )
    report = build_coverage(_identity([both]))
    assert _user(report, "alice")["legacy_auth"]["status"] == "covered"
    assert _user(report, "bob")["legacy_auth"]["reasons"] == ["Excluded from 'Block legacy' directly"]
    one = _policy(
        "EAS only", {"includeUsers": ["All"]}, grant=("block",), conditions={"clientAppTypes": ["exchangeActiveSync"]}
    )
    assert _user(build_coverage(_identity([one])), "alice")["legacy_auth"]["reasons"] == [
        "'EAS only' blocks only exchangeActiveSync, not other"
    ]


def test_block_policy_does_not_count_as_mfa():
    block_all = _policy("Block all", {"includeUsers": ["alice"]}, grant=("block",))
    report = build_coverage(_identity([block_all]))
    assert _user(report, "alice")["mfa"]["status"] == "gap"
    # Blocking every client type for all apps also blocks legacy authentication.
    assert _user(report, "alice")["legacy_auth"]["status"] == "covered"


def test_security_defaults_cover_mfa_and_legacy_for_everyone():
    report = build_coverage(_identity([], security_defaults=True))
    assert report["security_defaults_enabled"] is True
    for user in report["users"]:
        assert user["mfa"] == {"status": "covered", "policies": ["Security defaults"], "reasons": []}
        assert user["legacy_auth"]["status"] == "covered"


def test_report_carries_disclaimer_and_limits():
    report = build_coverage(_identity([]))
    assert "not Microsoft's evaluation engine" in report["disclaimer"]
    assert any("PIM" in limit for limit in report["limits"])


def test_policies_without_ids_are_evaluated_independently():
    excluded = _policy("A", {"includeUsers": ["All"], "excludeUsers": ["alice"]})
    covering = _policy("B", {"includeUsers": ["alice"]})
    for p in (excluded, covering):
        p["id"] = ""
    assert _user(build_coverage(_identity([covering, excluded])), "alice")["mfa"]["status"] == "covered"
