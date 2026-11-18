"""Per-policy Conditional Access rules shared by CA Coverage and the tenant-level checks.

One definition of "does this policy cover every sign-in it is meant to", so the coverage
page and the scan's tenant findings cannot disagree. Each rule returns the problems that
stop a policy from counting (an empty list means it counts) or None when the policy is not
about that question at all.
"""

from __future__ import annotations

from app.services.detection.conditional_access.constants import LEGACY_AUTH_CLIENT_APP_TYPES
from app.simulation.policy_parser import ConditionalAccessPolicy

LEGACY_TYPES = frozenset(LEGACY_AUTH_CLIENT_APP_TYPES)  # exchangeActiveSync, other

# Labels from policy_parser._narrowing_conditions that a check may allow because the
# check is about that condition.
AUTHENTICATION_FLOWS = "authentication flows"
SIGN_IN_RISK = "sign-in risk"


def scope_problems(policy: ConditionalAccessPolicy, *, allowed_conditions: frozenset[str] = frozenset()) -> list[str]:
    """Reasons the policy does not apply to every app and every sign-in.

    ``allowed_conditions`` lists narrowing conditions the caller's check is about (for
    example sign-in risk for a risk-based policy); every other one is a problem.
    """
    problems = []
    if "All" not in policy.include_applications or policy.include_user_actions:
        problems.append("applies only to some applications")
    if policy.exclude_applications:
        problems.append("excludes some applications")
    narrowing = [c for c in policy.narrowing_conditions if c not in allowed_conditions]
    if narrowing:
        problems.append("applies only under conditions: " + ", ".join(narrowing))
    return problems


def all_client_types(policy: ConditionalAccessPolicy) -> bool:
    return [t.lower() for t in policy.client_app_types] in ([], ["all"])


def is_block(policy: ConditionalAccessPolicy) -> bool:
    return "block" in {c.lower() for c in policy.grant_controls}


def mfa_problems(
    policy: ConditionalAccessPolicy, *, allowed_conditions: frozenset[str] = frozenset()
) -> list[str] | None:
    """None if the policy does not require MFA; otherwise why it does not require it on every sign-in."""
    controls = {c.lower() for c in policy.grant_controls}
    if "block" in controls or not ("mfa" in controls or policy.has_authentication_strength):
        return None
    problems = scope_problems(policy, allowed_conditions=allowed_conditions)
    if not all_client_types(policy):
        problems.append("applies only to some client apps")
    if policy.grant_operator != "AND" and controls - {"mfa"}:
        problems.append("allows another control instead of MFA")
    return problems


def block_problems(
    policy: ConditionalAccessPolicy, *, allowed_conditions: frozenset[str] = frozenset()
) -> list[str] | None:
    """None if the policy does not block; otherwise why the block does not cover every sign-in."""
    if not is_block(policy):
        return None
    problems = scope_problems(policy, allowed_conditions=allowed_conditions)
    if not all_client_types(policy):
        problems.append("applies only to some client apps")
    return problems


def legacy_blocked_types(policy: ConditionalAccessPolicy) -> tuple[frozenset[str], list[str]] | None:
    """The legacy client types the policy blocks, and why that block does not count.

    None when the policy does not block or blocks only modern clients. A block on client
    app type "all" (or none listed, which Graph treats as all) blocks both legacy types.
    Blocking only one type is not a problem here: two policies may block one type each.
    """
    if not is_block(policy):
        return None
    if all_client_types(policy):
        blocked = LEGACY_TYPES
    else:
        blocked = LEGACY_TYPES & frozenset(policy.client_app_types)
        if not blocked:
            return None
    return blocked, scope_problems(policy)
