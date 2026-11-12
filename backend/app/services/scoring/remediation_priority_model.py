from datetime import datetime, timezone

from app.services.scoring.identity_risk_score import calculate_finding_risk


SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 50,
    "LOW": 25,
}
ATTACK_PATH_PRIORITY_BOOST = 2


def calculate_age_factor(evaluated_at):
    if evaluated_at is None:
        return 0

    if evaluated_at.tzinfo is None:
        evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)

    hours = (datetime.now(timezone.utc) - evaluated_at).total_seconds() / 3600

    if hours > 168:
        return 100
    if hours > 72:
        return 80
    if hours > 24:
        return 60

    return 30


def effective_severity_for_finding(
    compliance,
    *,
    critical_attack_path_controls: set[str] | None = None,
):
    critical_attack_path_controls = critical_attack_path_controls or set()
    if getattr(compliance, "control_id", None) in critical_attack_path_controls:
        return "CRITICAL"
    return str(getattr(compliance, "severity", "MEDIUM") or "MEDIUM").upper()


def compute_priority_score(
    compliance,
    *,
    attack_path_controls: set[str] | None = None,
    critical_attack_path_controls: set[str] | None = None,
):
    attack_path_controls = attack_path_controls or set()
    effective_severity = effective_severity_for_finding(
        compliance,
        critical_attack_path_controls=critical_attack_path_controls,
    )
    finding_risk = calculate_finding_risk(compliance)
    severity_score = SEVERITY_SCORES.get(effective_severity, 50) / 10
    drift_score = min((compliance.remediation_count_7d or 0) * 1.5, 10)
    age_score = calculate_age_factor(compliance.evaluated_at) / 10
    priority_boost = (
        ATTACK_PATH_PRIORITY_BOOST if getattr(compliance, "control_id", None) in attack_path_controls else 0
    )

    score = finding_risk + severity_score + drift_score + age_score + priority_boost
    return round(score, 2)
