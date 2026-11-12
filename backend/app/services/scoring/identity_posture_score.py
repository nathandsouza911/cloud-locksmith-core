from typing import List
from app.db.models.compliance_result import ComplianceResult
from app.services.scoring.identity_risk_score import (
    build_risk_summary,
    severity_for_score,
    weight_for_control,
)


SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}

BREAK_GLASS_CONTROL_ID = "IDENTITY_BREAK_GLASS_ACCOUNT"


def _latest_result_by_control(results: List[ComplianceResult]) -> dict[str, ComplianceResult]:
    latest: dict[str, ComplianceResult] = {}
    for result in results:
        control_id = getattr(result, "control_id", None)
        if not isinstance(control_id, str) or not control_id:
            continue
        latest[control_id] = result
    return latest


def _control_score(result: ComplianceResult, default_score: float) -> float:
    if getattr(result, "control_id", None) != BREAK_GLASS_CONTROL_ID:
        return max(0.0, min(1.0, float(default_score)))

    if bool(getattr(result, "passed", False)):
        return 1.0

    evidence = getattr(result, "evidence", None)
    if not isinstance(evidence, dict):
        return 0.0

    number_of_accounts_found = evidence.get("number_of_accounts_found")
    if number_of_accounts_found == 1:
        return 0.5

    return 0.0


def calculate_identity_posture_score(
    results: List[ComplianceResult],
) -> dict:
    risk = build_risk_summary(results)
    latest_results = _latest_result_by_control(results)
    deductions = []
    total_weight = 0.0
    earned_weight = 0.0

    for item in risk["control_breakdown"]:
        control_id = item["control_id"]
        weight = float(weight_for_control(control_id))
        if weight <= 0:
            continue
        total_weight += weight

        result = latest_results.get(control_id)
        severity = getattr(result, "severity", "INFO") if result is not None else "INFO"
        control_score = (
            _control_score(result, item.get("score", 1.0))
            if result is not None
            else max(0.0, min(1.0, float(item.get("score", 1.0))))
        )
        earned_points = weight * control_score
        deducted_points = max(weight - earned_points, 0.0)
        earned_weight += earned_points
        deductions.append(
            {
                "control_id": control_id,
                "severity": severity,
                "points": round(deducted_points, 2),
            }
        )

    score = 100 if total_weight <= 0 else max(0, int(round((earned_weight / total_weight) * 100)))

    return {
        "score": score,
        "max_score": 100,
        "deductions": deductions,
        "severity": severity_for_score(score),
        "breakdown": risk.get("breakdown", {}),
        "attack_path_impact": risk.get("attack_path_impact", {}),
    }
