from __future__ import annotations

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.ca_helpers import is_effective_policy, is_mfa_grant, is_policy_enabled
from app.services.detection.conditional_access.constants import PRIVILEGED_ROLE_IDS


async def detect_ca_mfa_all_users(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-02: Verify at least one enabled CA policy enforces MFA for all users
    (includeUsers == ["All"]).
    Returns a single TENANT-scoped finding.

    Tier 1 fallback: Entra Security Defaults, when enabled, enforces MFA for
    every user tenant-wide without a named CA policy — a free alternative to
    Entra P1/P2. Tenants on Security Defaults pass this control directly,
    mirroring the same equivalence already applied to IDENTITY_USER_NO_MFA.
    """
    if ctx.security_defaults_enabled is True:
        return [
            {
                "control_id": "CA_MFA_ALL_USERS",
                "resource_type": "TENANT",
                "resource_id": ctx.tenant_id,
                "passed": True,
                "severity": "CRITICAL",
                "evidence": {
                    "detection_source": "security_defaults",
                    "matching_policy_ids": [],
                    "total_policies_evaluated": 0,
                },
            }
        ]

    if ctx.conditional_access_policies is None:
        return []

    matching_policy_ids: list[str] = []
    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue
        include_users = (policy.get("conditions") or {}).get("users", {}).get("includeUsers") or []
        if "All" not in include_users:
            continue
        if is_mfa_grant(policy.get("grantControls")):
            pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
            matching_policy_ids.append(str(pid))

    passed = bool(matching_policy_ids)
    return [
        {
            "control_id": "CA_MFA_ALL_USERS",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "CRITICAL",
            "evidence": {
                "matching_policy_ids": matching_policy_ids,
                "total_policies_evaluated": len(ctx.conditional_access_policies),
            },
        }
    ]


async def detect_ca_mfa_admins(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-03: Verify at least one enabled CA policy covers all 14 privileged role
    template IDs in includeRoles with an MFA grant.
    Returns a single TENANT-scoped finding.

    Tier 1 fallback: Entra Security Defaults enforces MFA for every user,
    admins included, tenant-wide. See detect_ca_mfa_all_users for the same
    fallback and rationale.
    """
    if ctx.security_defaults_enabled is True:
        return [
            {
                "control_id": "CA_MFA_ADMINS",
                "resource_type": "TENANT",
                "resource_id": ctx.tenant_id,
                "passed": True,
                "severity": "CRITICAL",
                "evidence": {
                    "detection_source": "security_defaults",
                    "uncovered_role_template_ids": [],
                    "covered_role_template_ids": sorted(PRIVILEGED_ROLE_IDS),
                    "total_policies_evaluated": 0,
                },
            }
        ]

    if ctx.conditional_access_policies is None:
        return []

    # Build a set of role template IDs covered by at least one enabled MFA policy.
    # Role definitions map roleTemplateId -> id (object ID used in CA policies).
    # CA policies use roleTemplateId directly in includeRoles, not the object ID.
    covered_role_template_ids: set[str] = set()

    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue
        if not is_mfa_grant(policy.get("grantControls")):
            continue
        include_roles = (policy.get("conditions") or {}).get("users", {}).get("includeRoles") or []
        for role_id in include_roles:
            covered_role_template_ids.add(role_id)
        # A policy targeting All users covers all roles too
        include_users = (policy.get("conditions") or {}).get("users", {}).get("includeUsers") or []
        if "All" in include_users:
            covered_role_template_ids.update(PRIVILEGED_ROLE_IDS)

    uncovered = sorted(PRIVILEGED_ROLE_IDS - covered_role_template_ids)
    passed = len(uncovered) == 0

    return [
        {
            "control_id": "CA_MFA_ADMINS",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "CRITICAL",
            "evidence": {
                "uncovered_role_template_ids": uncovered,
                "covered_role_template_ids": sorted(covered_role_template_ids & PRIVILEGED_ROLE_IDS),
                "total_policies_evaluated": len(ctx.conditional_access_policies),
            },
        }
    ]
