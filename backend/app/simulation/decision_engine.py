from __future__ import annotations

from app.simulation.policy_parser import ConditionalAccessPolicy


def evaluate_user_access(
    user_id: str,
    applicable_policies: list[ConditionalAccessPolicy],
) -> dict[str, str | list[str]]:
    policy_ids = [policy.id for policy in applicable_policies if policy.id]

    if any("block" in _normalize_controls(policy) for policy in applicable_policies):
        result = "BLOCKED"
    elif any("mfa" in _normalize_controls(policy) for policy in applicable_policies):
        result = "MFA_REQUIRED"
    else:
        result = "ALLOW"

    return {
        "user_id": user_id,
        "result": result,
        "policies": policy_ids,
    }


def _normalize_controls(policy: ConditionalAccessPolicy) -> set[str]:
    return {control.strip().lower() for control in policy.grant_controls if isinstance(control, str)}
