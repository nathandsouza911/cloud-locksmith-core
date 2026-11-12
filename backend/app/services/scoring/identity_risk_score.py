from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable

from app.db.models.compliance_result import ComplianceResult
from app.services.attack_path_engine import summarize_attack_paths

logger = logging.getLogger(__name__)

CONTROL_WEIGHTS = {
    "IDENTITY_ADMIN_NO_MFA": 10,
    "IDENTITY_USER_NO_MFA": 7,
    "IDENTITY_ADMIN_COUNT_EXCESS": 7,
    "IDENTITY_OVERPRIVILEGED_USER": 8,
    "IDENTITY_BREAK_GLASS_ACCOUNT": 8,
    "IDENTITY_BREAK_GLASS_USAGE": 10,
    "IDENTITY_UNUSED_ACCOUNT": 5,
    "IDENTITY_GUEST_INVITES_OPEN": 7,
    "IDENTITY_USER_CONSENT_POLICY": 7,
}

MFA_CONTROL_IDS = (
    "IDENTITY_ADMIN_NO_MFA",
    "IDENTITY_USER_NO_MFA",
)
EXTERNAL_CONTROL_IDS = (
    "IDENTITY_GUEST_INVITES_OPEN",
    "IDENTITY_USER_CONSENT_POLICY",
)
GROUP_WEIGHTS = {
    "mfa": 0.30,
    "privileged": 0.25,
    "hygiene": 0.20,
    "external": 0.25,
}
GROUP_CONTROL_IDS = {
    "mfa": set(MFA_CONTROL_IDS),
    "privileged": {"IDENTITY_ADMIN_COUNT_EXCESS", "IDENTITY_OVERPRIVILEGED_USER"},
    "hygiene": {"IDENTITY_UNUSED_ACCOUNT"},
    "external": set(EXTERNAL_CONTROL_IDS),
}


@dataclass(frozen=True)
class _ControlCounts:
    total: int
    failed: int

    @property
    def passed(self) -> int:
        return max(self.total - self.failed, 0)

    @property
    def score(self) -> float:
        if self.total <= 0:
            return 1.0
        return max(0.0, min(1.0, self.passed / self.total))


def _evidence(result: ComplianceResult | object) -> dict:
    evidence = getattr(result, "evidence", None)
    return evidence if isinstance(evidence, dict) else {}


def _resource_key(result: ComplianceResult | object) -> str | None:
    evidence = _evidence(result)
    user_id = evidence.get("user_id")
    if isinstance(user_id, str) and user_id:
        return user_id
    resource_id = getattr(result, "resource_id", None)
    if isinstance(resource_id, str) and resource_id:
        return resource_id
    return None


def _control_rows(
    results: Iterable[ComplianceResult | object],
    control_id: str,
) -> list[ComplianceResult | object]:
    return [result for result in results if getattr(result, "control_id", None) == control_id]


def _control_counts(
    results: Iterable[ComplianceResult | object],
    control_id: str,
) -> _ControlCounts:
    totals: dict[str, bool] = {}
    for result in _control_rows(results, control_id):
        key = _resource_key(result)
        if not key:
            continue
        totals[key] = bool(getattr(result, "passed", False))

    total = len(totals)
    failed = sum(1 for passed in totals.values() if not passed)
    return _ControlCounts(total=total, failed=failed)


def _tenant_control_score(
    results: Iterable[ComplianceResult | object],
    control_id: str,
) -> float | None:
    rows = _control_rows(results, control_id)
    if not rows:
        return None
    latest = rows[-1]
    return 1.0 if bool(getattr(latest, "passed", False)) else 0.0


def weight_for_control(control_id: str) -> int:
    return CONTROL_WEIGHTS.get(control_id, 0)


def clamp_score(score: float | int) -> int:
    return max(0, min(100, int(round(float(score)))))


def severity_for_score(score: float | int) -> str:
    safe_score = clamp_score(score)
    if safe_score >= 80:
        return "GOOD"
    if safe_score >= 60:
        return "MODERATE"
    if safe_score >= 40:
        return "HIGH"
    return "CRITICAL"


def _normalized_active_controls(active_controls: Iterable[str] | None) -> set[str]:
    if active_controls is None:
        return set(CONTROL_WEIGHTS.keys())
    return {control_id for control_id in active_controls if control_id in CONTROL_WEIGHTS}


def _group_is_active(group_name: str, active_controls: set[str]) -> bool:
    return bool(GROUP_CONTROL_IDS[group_name] & active_controls)


def _normalized_weighted_average(parts: list[tuple[float, float]]) -> float:
    active_parts = [(weight, value) for weight, value in parts if weight > 0]
    if not active_parts:
        return 1.0
    total_weight = sum(weight for weight, _value in active_parts)
    if total_weight <= 0:
        return 1.0
    return sum(weight * value for weight, value in active_parts) / total_weight


def _build_group_breakdown(
    results: list[ComplianceResult | object],
    *,
    active_controls: set[str],
) -> tuple[dict, dict]:
    admin_counts = _control_counts(results, "IDENTITY_ADMIN_NO_MFA")
    user_counts = _control_counts(results, "IDENTITY_USER_NO_MFA")
    admin_count_excess_score = _tenant_control_score(results, "IDENTITY_ADMIN_COUNT_EXCESS")
    overprivileged_counts = _control_counts(results, "IDENTITY_OVERPRIVILEGED_USER")
    dormant_counts = _control_counts(results, "IDENTITY_UNUSED_ACCOUNT")

    guest_secure = _tenant_control_score(results, "IDENTITY_GUEST_INVITES_OPEN")
    consent_secure = _tenant_control_score(results, "IDENTITY_USER_CONSENT_POLICY")

    mfa_score = _normalized_weighted_average(
        [
            (0.7 if "IDENTITY_ADMIN_NO_MFA" in active_controls else 0.0, admin_counts.score),
            (0.3 if "IDENTITY_USER_NO_MFA" in active_controls else 0.0, user_counts.score),
        ]
    )
    external_parts = []
    if "IDENTITY_GUEST_INVITES_OPEN" in active_controls:
        external_parts.append((1.0, 1.0 if guest_secure is None else guest_secure))
    if "IDENTITY_USER_CONSENT_POLICY" in active_controls:
        external_parts.append((1.0, 1.0 if consent_secure is None else consent_secure))
    external_score = _normalized_weighted_average(external_parts)

    privileged_parts = []
    if "IDENTITY_ADMIN_COUNT_EXCESS" in active_controls:
        privileged_parts.append((0.4, 1.0 if admin_count_excess_score is None else admin_count_excess_score))
    if "IDENTITY_OVERPRIVILEGED_USER" in active_controls:
        privileged_parts.append((0.6, overprivileged_counts.score))
    privileged_score = _normalized_weighted_average(privileged_parts)

    group_scores = {
        "mfa": mfa_score,
        "privileged": privileged_score,
        "hygiene": dormant_counts.score,
        "external": external_score,
    }

    breakdown = {
        "mfa": {
            "score": round(mfa_score, 4),
            "weight": GROUP_WEIGHTS["mfa"],
            "admin_mfa": round(admin_counts.score, 4),
            "user_mfa": round(user_counts.score, 4),
            "admins_without_mfa": admin_counts.failed,
            "total_admins": admin_counts.total,
            "users_without_mfa": user_counts.failed,
            "total_users": user_counts.total,
        },
        "privileged": {
            "score": round(privileged_score, 4),
            "weight": GROUP_WEIGHTS["privileged"],
            "global_admin_count_excess": 0 if admin_count_excess_score in (None, 1.0) else 1,
            "overprivileged_users": overprivileged_counts.failed,
            "total_users_evaluated": overprivileged_counts.total,
        },
        "hygiene": {
            "score": round(dormant_counts.score, 4),
            "weight": GROUP_WEIGHTS["hygiene"],
            "dormant_accounts": dormant_counts.failed,
            "total_accounts": dormant_counts.total,
        },
        "external": {
            "score": round(external_score, 4),
            "weight": GROUP_WEIGHTS["external"],
            "guest_secure": None if guest_secure is None else int(guest_secure),
            "consent_secure": None if consent_secure is None else int(consent_secure),
        },
    }
    return breakdown, group_scores


def _base_score(group_scores: dict[str, float], *, active_controls: set[str]) -> float:
    active_group_parts = [
        (GROUP_WEIGHTS[group_name], group_scores[group_name])
        for group_name in GROUP_WEIGHTS
        if _group_is_active(group_name, active_controls)
    ]
    normalized = _normalized_weighted_average(active_group_parts)
    return normalized * 100.0


def _attack_path_impact(
    results: list[ComplianceResult | object],
    *,
    active_controls: set[str],
) -> dict:
    failed_controls = {
        getattr(result, "control_id", None)
        for result in results
        if getattr(result, "control_id", None) in active_controls
        and getattr(result, "exposure_status", "ACTIVE") == "ACTIVE"
        and bool(getattr(result, "passed", False)) is False
    }
    failed_controls = {control_id for control_id in failed_controls if isinstance(control_id, str)}
    path_summary = summarize_attack_paths(failed_controls)
    total_paths = int(path_summary.get("total_paths", 0) or 0)
    critical_paths = int(path_summary.get("critical_paths", 0) or 0)
    raw_deduction = (total_paths * 5) + (critical_paths * 10)
    deduction = min(raw_deduction, 20)
    return {
        "deduction": deduction,
        "total_paths": total_paths,
        "critical_paths": critical_paths,
        "paths": path_summary.get("paths", []),
        "affected_controls": sorted(path_summary.get("affected_controls") or []),
        "critical_controls": sorted(path_summary.get("critical_controls") or []),
    }


def _control_breakdown(
    results: list[ComplianceResult | object],
    *,
    active_controls: set[str],
) -> list[dict]:
    items: list[dict] = []
    for control_id in sorted(active_controls):
        if control_id in EXTERNAL_CONTROL_IDS:
            secure = _tenant_control_score(results, control_id)
            passed = 1 if secure == 1.0 else 0
            failed = 1 - passed
            total = 1 if secure is not None else 0
            control_score = 1.0 if total == 0 else float(passed)
        else:
            counts = _control_counts(results, control_id)
            total = counts.total
            failed = counts.failed
            passed = counts.passed
            control_score = counts.score
        items.append(
            {
                "control_id": control_id,
                "score": round(control_score, 4),
                "failed": failed,
                "passed": passed,
                "total": total,
                "weight": weight_for_control(control_id),
            }
        )
    items.sort(key=lambda item: (item["score"], -item["failed"], item["control_id"]))
    return items


def _top_risks(control_breakdown: list[dict], top_n: int) -> list[dict]:
    return [
        {
            "control_id": item["control_id"],
            "score": item["score"],
            "failed": item["failed"],
            "total": item["total"],
        }
        for item in control_breakdown[:top_n]
    ]


def build_risk_summary(
    results: list[ComplianceResult | object],
    *,
    top_n: int = 5,
    active_controls: Iterable[str] | None = None,
) -> dict:
    active_control_ids = _normalized_active_controls(active_controls)
    breakdown, group_scores = _build_group_breakdown(results, active_controls=active_control_ids)
    base_score = _base_score(group_scores, active_controls=active_control_ids)
    attack_path_impact = _attack_path_impact(results, active_controls=active_control_ids)
    score = clamp_score(base_score - attack_path_impact["deduction"])
    control_breakdown = _control_breakdown(results, active_controls=active_control_ids)
    summary = {
        "score": score,
        "severity": severity_for_score(score),
        "base_score": round(base_score, 2),
        "breakdown": breakdown,
        "attack_path_impact": attack_path_impact,
        "control_breakdown": control_breakdown,
        "top_risks": _top_risks(control_breakdown, top_n),
        "active_controls_count": len(active_control_ids),
    }
    logger.info(
        "RISK_SCORE_COMPUTED %s",
        {
            "score": score,
            "base_score": round(base_score, 2),
            "attack_path_deduction": attack_path_impact["deduction"],
            "active_controls_count": len(active_control_ids),
        },
    )
    return summary


def calculate_finding_risk(result: ComplianceResult | object) -> float:
    control_score = 1.0
    if getattr(result, "passed", False) is False:
        control_score = 0.0
    return round((1.0 - control_score) * float(weight_for_control(getattr(result, "control_id", ""))), 2)


def calculate_fix_impact(
    *,
    current_results: list[ComplianceResult | object],
    current_score: int,
    target_result: ComplianceResult | object,
    active_controls: Iterable[str] | None = None,
) -> float:
    simulated_results: list[ComplianceResult | object] = []
    target_id = id(target_result)
    for result in current_results:
        if id(result) == target_id:
            simulated_results.append(
                type(
                    "SimulatedResult",
                    (),
                    {
                        "control_id": getattr(result, "control_id", None),
                        "passed": True,
                        "severity": getattr(result, "severity", None),
                        "evidence": _evidence(result),
                        "resource_id": getattr(result, "resource_id", None),
                        "resource_type": getattr(result, "resource_type", None),
                        "exposure_status": getattr(result, "exposure_status", "ACTIVE"),
                    },
                )()
            )
        else:
            simulated_results.append(result)

    new_score = build_risk_summary(
        simulated_results,
        active_controls=active_controls,
    )["score"]
    return round(max(float(new_score) - float(current_score), 0.0), 2)
