from __future__ import annotations

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.ca_helpers import is_effective_policy, is_policy_enabled


async def detect_ca_break_glass_excluded(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-BG: Verify that every enabled, effective CA policy explicitly excludes ALL
    break-glass accounts in conditions.users.excludeUsers.

    Returns [] when:
    - conditional_access_policies is None (fetch failed — cannot evaluate)
    - break_glass_accounts is empty (Fix 4: nothing to check — skip)

    Group exclusion uncertainty (Fix 2):
    If excludeUsers contains IDs that are not break-glass accounts (potential group IDs),
    and break-glass accounts are not directly excluded, we cannot confirm failure because
    the unknown IDs may be groups that contain the break-glass accounts. Such policies are
    not added to non_compliant; evidence carries group_exclusion_unknown=True instead.
    """
    if ctx.conditional_access_policies is None:
        return []

    if not ctx.break_glass_accounts:
        return []

    bg_set = set(ctx.break_glass_accounts)
    non_compliant: list[dict] = []
    group_exclusion_unknown = False

    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue

        users = (policy.get("conditions") or {}).get("users", {})
        excluded = set(users.get("excludeUsers") or [])
        missing = sorted(bg_set - excluded)

        if not missing:
            continue

        unknown_ids = excluded - bg_set
        if unknown_ids:
            # Unknown IDs may be groups containing break-glass accounts — uncertain, not a hard fail.
            group_exclusion_unknown = True
            continue

        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        name = policy.get("displayName") or "<unnamed>"
        non_compliant.append(
            {
                "policy_id": str(pid),
                "policy_name": str(name),
                "missing_exclusions": missing,
            }
        )

    passed = len(non_compliant) == 0
    evidence: dict = {
        "non_compliant_policies": non_compliant,
        "total_policies_evaluated": len(ctx.conditional_access_policies),
        "break_glass_accounts_checked": list(ctx.break_glass_accounts),
    }
    if group_exclusion_unknown:
        evidence["group_exclusion_unknown"] = True

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
