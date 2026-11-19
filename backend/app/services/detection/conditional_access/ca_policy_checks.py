from __future__ import annotations

import logging

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.ca_helpers import is_effective_policy, is_policy_enabled
from app.simulation.policy_evaluator import match_policy
from app.simulation.policy_parser import PolicyParser
from app.simulation.tenant_reader import read_tenant_identity

logger = logging.getLogger(__name__)


def _excludes_by_group_or_role(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    return bool(users.get("excludeGroups") or users.get("excludeRoles"))


async def attach_exclusion_membership(ctx: TenantGraphContext, *, db, tenant) -> None:
    """Read group and role membership into ``ctx`` when a policy that matters
    to the break-glass check excludes by group or role. The read is fail-closed;
    on failure the maps stay None and the check reports unknown."""
    if not ctx.break_glass_accounts or not ctx.conditional_access_policies:
        return
    if not any(
        is_policy_enabled(p) and is_effective_policy(p) and _excludes_by_group_or_role(p)
        for p in ctx.conditional_access_policies
    ):
        return
    try:
        identity = await read_tenant_identity(db, tenant)
    except Exception:
        logger.warning("ca_exclusion_membership_read_failed tenant_id=%s", ctx.tenant_id, exc_info=True)
        return
    ctx.group_member_map = identity.group_map()
    ctx.role_member_map = identity.role_map()


async def detect_ca_break_glass_excluded(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-BG: every enabled, effective CA policy must exclude every break-glass
    account: directly (excludeUsers), through a group (nested members) or
    through a role, with the shared Graph assignment matcher.

    Returns [] when the policies could not be read or there are no break-glass
    accounts. When a policy excludes by group or role and that membership was
    not read (ctx maps are None), the policy cannot be evaluated: the result is
    unknown (passed=None) unless another policy has a definite gap.
    """
    if ctx.conditional_access_policies is None:
        return []

    if not ctx.break_glass_accounts:
        return []

    membership_known = ctx.group_member_map is not None and ctx.role_member_map is not None
    group_map = ctx.group_member_map or {}
    role_map = ctx.role_member_map or {}
    non_compliant: list[dict] = []
    membership_unavailable = False

    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue

        parsed = PolicyParser().parse(policy)
        excludes_indirectly = bool(parsed.exclude_groups or parsed.exclude_roles)
        missing: list[str] = []
        for account_id in ctx.break_glass_accounts:
            if account_id in parsed.exclude_users:
                continue
            if excludes_indirectly and not membership_known:
                membership_unavailable = True
                continue
            if match_policy(account_id, parsed, group_map, role_map).excluded_by is None:
                missing.append(account_id)

        if not missing:
            continue

        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        name = policy.get("displayName") or "<unnamed>"
        non_compliant.append(
            {
                "policy_id": str(pid),
                "policy_name": str(name),
                "missing_exclusions": sorted(missing),
            }
        )

    if non_compliant:
        passed: bool | None = False
    elif membership_unavailable:
        passed = None
    else:
        passed = True
    evidence: dict = {
        "non_compliant_policies": non_compliant,
        "total_policies_evaluated": len(ctx.conditional_access_policies),
        "break_glass_accounts_checked": list(ctx.break_glass_accounts),
    }
    if membership_unavailable:
        evidence["exclusion_membership_unavailable"] = True

    return [
        {
            "control_id": "CA_BREAK_GLASS_EXCLUSION",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "CRITICAL",
            "evidence": evidence,
        }
    ]
