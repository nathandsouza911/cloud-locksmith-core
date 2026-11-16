"""Per-user Conditional Access coverage (ROADMAP 3.1).

For every user: is MFA required on every sign-in, is legacy authentication blocked, and
(for privileged-role holders) is admin MFA required — with the policies that cover them
or the reasons they are not covered. Uses the shared policy matcher; read-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.detection.conditional_access.constants import (
    LEGACY_AUTH_CLIENT_APP_TYPES,
    PRIVILEGED_ROLE_TEMPLATE_IDS,
)
from app.simulation.policy_evaluator import match_policy
from app.simulation.policy_parser import ConditionalAccessPolicy, PolicyParser
from app.simulation.tenant_reader import TenantIdentity

COVERED, REPORT_ONLY, GAP, NOT_APPLICABLE = "covered", "report_only", "gap", "not_applicable"
_ENABLED, _REPORT_ONLY_STATE, _DISABLED = "enabled", "enabledforreportingbutnotenforced", "disabled"
_SECURITY_DEFAULTS = "Security defaults"
_LEGACY_TYPES = sorted(LEGACY_AUTH_CLIENT_APP_TYPES)  # ["exchangeActiveSync", "other"]

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
    "Security defaults, when on, are reported as covering MFA and legacy authentication "
    "for every user.",
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
            mfa = _evaluate(policies, matches, names, _mfa_problems, "No policy requires MFA for this user")
            legacy = _evaluate(
                policies, matches, names, _legacy_problems, "No policy blocks legacy authentication for this user"
            )
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
    enforced, report_only, reasons = [], [], []
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
        elif state == _REPORT_ONLY_STATE:
            report_only.append(names.plain(policy))
        elif state == _DISABLED:
            reasons.append(f"{label} would cover this user but is turned off")
    if enforced:
        return _result(COVERED, enforced, [])
    if report_only:
        return _result(REPORT_ONLY, report_only, reasons)
    return _result(GAP, [], reasons or [no_policy_reason])


def _scope_problems(policy: ConditionalAccessPolicy) -> list[str]:
    problems = []
    if "All" not in policy.include_applications or policy.include_user_actions:
        problems.append("applies only to some applications")
    if policy.exclude_applications:
        problems.append("excludes some applications")
    if policy.narrowing_conditions:
        problems.append("applies only under conditions: " + ", ".join(policy.narrowing_conditions))
    return problems


def _all_client_types(policy: ConditionalAccessPolicy) -> bool:
    return [t.lower() for t in policy.client_app_types] in ([], ["all"])


def _mfa_problems(policy: ConditionalAccessPolicy) -> list[str] | None:
    controls = {c.lower() for c in policy.grant_controls}
    if "block" in controls or not ("mfa" in controls or policy.has_authentication_strength):
        return None
    problems = _scope_problems(policy)
    if not _all_client_types(policy):
        problems.append("applies only to some client apps")
    if policy.grant_operator != "AND" and controls - {"mfa"}:
        problems.append("allows another control instead of MFA")
    return problems


def _legacy_problems(policy: ConditionalAccessPolicy) -> list[str] | None:
    if "block" not in {c.lower() for c in policy.grant_controls}:
        return None
    if _all_client_types(policy):
        blocked = set(_LEGACY_TYPES)
    else:
        blocked = set(_LEGACY_TYPES) & set(policy.client_app_types)
        if not blocked:
            return None  # blocks only modern clients; not a legacy-auth policy
    problems = _scope_problems(policy)
    missing = [t for t in _LEGACY_TYPES if t not in blocked]
    if missing:
        problems.append(f"blocks only {', '.join(sorted(blocked))}, not {', '.join(missing)}")
    return problems


def _result(status: str, policies: list[str], reasons: list[str]) -> dict[str, Any]:
    return {"status": status, "policies": policies, "reasons": reasons}


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
