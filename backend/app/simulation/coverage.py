"""Per-user Conditional Access coverage (ROADMAP 3.1).

For every user: is MFA required on every sign-in, is legacy authentication blocked, and
(for privileged-role holders) is admin MFA required — with the policies that cover them
or the reasons they are not covered. Uses the shared policy matcher; read-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.detection.conditional_access.constants import PRIVILEGED_ROLE_TEMPLATE_IDS
from app.simulation.policy_evaluator import match_policy
from app.simulation.policy_parser import ConditionalAccessPolicy, PolicyParser
from app.simulation.policy_rules import LEGACY_TYPES, legacy_blocked_types, mfa_problems
from app.simulation.tenant_reader import TenantIdentity

COVERED, REPORT_ONLY, GAP, NOT_APPLICABLE = "covered", "report_only", "gap", "not_applicable"
_ENABLED, _REPORT_ONLY_STATE, _DISABLED = "enabled", "enabledforreportingbutnotenforced", "disabled"
_SECURITY_DEFAULTS = "Security defaults"

DISCLAIMER = (
    "Models policy assignment; it is not Microsoft's evaluation engine. Conditions other "
    "than users, applications, client app types and the conditions listed are not evaluated."
)
LIMITS = [
    "Role holders are read from active role assignments; PIM-eligible assignments and "
    "administrative-unit scoped roles are not modelled.",
    "Users who hold a role through a role-assignable group are counted as holding it.",
    "A policy that targets guests or external users is not counted as covering them; a "
    "guest exclusion is applied to every guest.",
    "Security defaults, when on, are reported as covering MFA and legacy authentication " "for every user.",
]


def build_coverage(identity: TenantIdentity) -> dict[str, Any]:
    policies = PolicyParser().parse_many([p for p in identity.policies if isinstance(p, dict)])
    group_map, role_map, guest_ids = identity.group_map(), identity.role_map(), identity.guest_ids()
    names = _Names(identity)
    admin_ids = {
        user_id
        for template_id, role in identity.roles.items()
        if template_id in PRIVILEGED_ROLE_TEMPLATE_IDS
        for user_id in role.get("member_ids") or []
    }

    rows = []
    for user in identity.users:
        user_id = user.get("id")
        if not user_id:
            continue
        if identity.security_defaults_enabled:
            mfa = legacy = _result(COVERED, [_SECURITY_DEFAULTS], [])
        else:
            matches = [match_policy(user_id, p, group_map, role_map, guest_ids) for p in policies]
            mfa = _evaluate(policies, matches, names, mfa_problems, "No policy requires MFA for this user")
            legacy = _evaluate_legacy(policies, matches, names)
        is_admin = user_id in admin_ids
        rows.append(
            {
                "id": user_id,
                "display_name": user.get("displayName"),
                "user_principal_name": user.get("userPrincipalName"),
                "enabled": bool(user.get("accountEnabled", True)),
                "is_guest": user_id in guest_ids,
                "is_admin": is_admin,
                "mfa": mfa,
                "legacy_auth": legacy,
                "admin_mfa": dict(mfa) if is_admin else _result(NOT_APPLICABLE, [], []),
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "security_defaults_enabled": identity.security_defaults_enabled,
        "disclaimer": DISCLAIMER,
        "limits": list(LIMITS),
        "summary": {
            "users": len(rows),
            "mfa": _count(rows, "mfa", (COVERED, REPORT_ONLY, GAP)),
            "legacy_auth": _count(rows, "legacy_auth", (COVERED, REPORT_ONLY, GAP)),
            "admin_mfa": _count(rows, "admin_mfa", (COVERED, REPORT_ONLY, GAP, NOT_APPLICABLE)),
        },
        "users": rows,
    }


def _evaluate(policies, matches, names, problems_of, no_policy_reason: str) -> dict[str, Any]:
    enforced, report_only, reasons, enforced_ids, report_only_ids = [], [], [], [], []
    for policy, match in zip(policies, matches):
        problems = problems_of(policy)
        if problems is None:  # not a policy for this question
            continue
        if not match.included:
            continue
        label = names.policy(policy)
        if match.excluded_by is not None:
            reasons.append(f"Excluded from {label} {names.exclusion(match.excluded_by)}")
            continue
        if problems:
            reasons.extend(f"{label} {problem}" for problem in problems)
            continue
        state = policy.state.lower()
        if state == _ENABLED:
            enforced.append(names.plain(policy))
            enforced_ids.append(policy.id)
        elif state == _REPORT_ONLY_STATE:
            report_only.append(names.plain(policy))
            report_only_ids.append(policy.id)
        elif state == _DISABLED:
            reasons.append(f"{label} would cover this user but is turned off")
    if enforced:
        return _result(COVERED, enforced, [], enforced_ids)
    if report_only:
        return _result(REPORT_ONLY, report_only, reasons, report_only_ids)
    return _result(GAP, [], reasons or [no_policy_reason])


def _evaluate_legacy(policies, matches, names) -> dict[str, Any]:
    """Legacy authentication is blocked when the policies covering the user together block
    both legacy client types (one policy may block each), as the tenant-level check allows."""
    reasons: list[str] = []
    enforced: list[tuple[ConditionalAccessPolicy, frozenset[str]]] = []
    report_only: list[tuple[ConditionalAccessPolicy, frozenset[str]]] = []
    for policy, match in zip(policies, matches):
        rule = legacy_blocked_types(policy)
        if rule is None or not match.included:
            continue
        label = names.policy(policy)
        if match.excluded_by is not None:
            reasons.append(f"Excluded from {label} {names.exclusion(match.excluded_by)}")
            continue
        blocked, problems = rule
        if problems:
            reasons.extend(f"{label} {problem}" for problem in problems)
            continue
        state = policy.state.lower()
        if state == _ENABLED:
            enforced.append((policy, blocked))
        elif state == _REPORT_ONLY_STATE:
            report_only.append((policy, blocked))
        elif state == _DISABLED:
            reasons.append(f"{label} would cover this user but is turned off")

    def blocked_by(entries) -> frozenset[str]:
        return frozenset().union(*(blocked for _, blocked in entries))

    if blocked_by(enforced) == LEGACY_TYPES:
        return _result(COVERED, [names.plain(p) for p, _ in enforced], [], [p.id for p, _ in enforced])
    partial = [(p, b) for p, b in enforced + report_only if b != LEGACY_TYPES]
    if report_only and blocked_by(enforced + report_only) == LEGACY_TYPES:
        return _result(REPORT_ONLY, [names.plain(p) for p, _ in report_only], reasons, [p.id for p, _ in report_only])
    for policy, blocked in partial:
        missing = sorted(LEGACY_TYPES - blocked)
        reasons.append(f"{names.policy(policy)} blocks only {', '.join(sorted(blocked))}, not {', '.join(missing)}")
    return _result(GAP, [], reasons or ["No policy blocks legacy authentication for this user"])


def _result(
    status: str, policies: list[str], reasons: list[str], policy_ids: list[str] | None = None
) -> dict[str, Any]:
    # ``policies`` are display names for people; ``policy_ids`` the matching policy IDs.
    return {"status": status, "policies": policies, "reasons": reasons, "policy_ids": list(policy_ids or [])}


def _count(rows, key, statuses) -> dict[str, int]:
    return {status: sum(1 for row in rows if row[key]["status"] == status) for status in statuses}


class _Names:
    def __init__(self, identity: TenantIdentity) -> None:
        self._groups = {gid: g.get("name") or gid for gid, g in identity.groups.items()}
        self._roles = {rid: r.get("name") or rid for rid, r in identity.roles.items()}

    @staticmethod
    def plain(policy: ConditionalAccessPolicy) -> str:
        return policy.display_name or policy.id

    def policy(self, policy: ConditionalAccessPolicy) -> str:
        return f"'{self.plain(policy)}'"

    def exclusion(self, excluded_by: tuple[str, str]) -> str:
        kind, object_id = excluded_by
        if kind == "group":
            return f"by group '{self._groups.get(object_id, object_id)}'"
        if kind == "role":
            return f"by role '{self._roles.get(object_id, object_id)}'"
        if kind == "guest":
            return "as a guest"
        return "directly"
