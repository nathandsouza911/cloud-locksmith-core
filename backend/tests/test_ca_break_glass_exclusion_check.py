"""Review R2-16: CA_BREAK_GLASS_EXCLUSION reads group and role exclusions.

Before the fix the check read only excludeUsers. A break-glass account
excluded through a group or a role was reported as missing (false FAIL),
and a policy that excluded some other user but not the break-glass account
was skipped as "maybe a group" (false PASS).
"""

import asyncio
from datetime import datetime, timezone

from app.services.detection.conditional_access.ca_policy_checks import detect_ca_break_glass_excluded
from app.services.graph.tenant_graph_context import TenantGraphContext

BG = "bg-user-1"
BG_GROUP = "group-break-glass"
GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def _policy(pid: str, **user_conditions) -> dict:
    users = {"includeUsers": ["All"], **user_conditions}
    return {
        "id": pid,
        "displayName": pid,
        "state": "enabled",
        "conditions": {"users": users, "applications": {"includeApplications": ["All"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


def _check(policies, *, groups=None, roles=None) -> dict | None:
    ctx = TenantGraphContext(
        tenant_id="tenant-bg",
        fetched_at=datetime.now(timezone.utc),
        conditional_access_policies=policies,
        break_glass_accounts=[BG],
        group_member_map=groups,
        role_member_map=roles,
    )
    results = asyncio.run(detect_ca_break_glass_excluded(ctx=ctx))
    return results[0] if results else None


def test_direct_exclusion_passes():
    assert _check([_policy("p1", excludeUsers=[BG])])["passed"] is True


def test_exclusion_through_a_group_passes():
    result = _check([_policy("p1", excludeGroups=[BG_GROUP])], groups={BG_GROUP: [BG]}, roles={})
    assert result["passed"] is True


def test_exclusion_through_a_role_passes():
    result = _check([_policy("p1", excludeRoles=[GA_TEMPLATE])], groups={}, roles={GA_TEMPLATE: [BG]})
    assert result["passed"] is True


def test_group_that_does_not_contain_the_account_fails():
    result = _check([_policy("p1", excludeGroups=[BG_GROUP])], groups={BG_GROUP: ["someone-else"]}, roles={})
    assert result["passed"] is False
    assert result["evidence"]["non_compliant_policies"][0]["missing_exclusions"] == [BG]


def test_excluding_another_user_is_not_a_pass():
    result = _check([_policy("p1", excludeUsers=["someone-else"])])
    assert result["passed"] is False


def test_group_exclusion_without_membership_data_is_unknown():
    result = _check([_policy("p1", excludeGroups=[BG_GROUP])])
    assert result["passed"] is None
    assert result["evidence"]["exclusion_membership_unavailable"] is True


def test_a_definite_gap_fails_even_when_another_policy_is_unknown():
    result = _check([_policy("p1", excludeGroups=[BG_GROUP]), _policy("p2")])
    assert result["passed"] is False


# Membership is read only when a policy excludes by group or role, fail-closed.


def _ctx(policies) -> TenantGraphContext:
    return TenantGraphContext(
        tenant_id="tenant-bg",
        fetched_at=datetime.now(timezone.utc),
        conditional_access_policies=policies,
        break_glass_accounts=[BG],
    )


def test_membership_is_not_read_when_no_policy_excludes_indirectly(monkeypatch):
    from app.services.detection.conditional_access import ca_policy_checks

    async def must_not_read(db, tenant):
        raise AssertionError("membership read without a group or role exclusion")

    monkeypatch.setattr(ca_policy_checks, "read_tenant_identity", must_not_read)
    ctx = _ctx([_policy("p1", excludeUsers=[BG])])

    asyncio.run(ca_policy_checks.attach_exclusion_membership(ctx, db=None, tenant=None))

    assert ctx.group_member_map is None


def test_membership_is_attached_when_a_policy_excludes_a_group(monkeypatch):
    from app.services.detection.conditional_access import ca_policy_checks
    from app.simulation.tenant_reader import TenantIdentity

    async def identity(db, tenant):
        return TenantIdentity(users=[], policies=[], groups={BG_GROUP: {"name": "BG", "member_ids": [BG]}}, roles={})

    monkeypatch.setattr(ca_policy_checks, "read_tenant_identity", identity)
    ctx = _ctx([_policy("p1", excludeGroups=[BG_GROUP])])

    asyncio.run(ca_policy_checks.attach_exclusion_membership(ctx, db=None, tenant=None))
    result = asyncio.run(detect_ca_break_glass_excluded(ctx=ctx))[0]

    assert result["passed"] is True


def test_a_failed_membership_read_leaves_the_result_unknown(monkeypatch):
    from app.services.detection.conditional_access import ca_policy_checks

    async def failing(db, tenant):
        raise RuntimeError("graph down")

    monkeypatch.setattr(ca_policy_checks, "read_tenant_identity", failing)
    ctx = _ctx([_policy("p1", excludeGroups=[BG_GROUP])])

    asyncio.run(ca_policy_checks.attach_exclusion_membership(ctx, db=None, tenant=None))
    result = asyncio.run(detect_ca_break_glass_excluded(ctx=ctx))[0]

    assert result["passed"] is None
