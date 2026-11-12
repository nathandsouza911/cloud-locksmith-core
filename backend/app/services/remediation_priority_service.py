from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.services.attack_path_engine import summarize_attack_paths
from app.services.scoring.remediation_priority_model import compute_priority_score


def get_priority_queue(db: Session, tenant_id: str, limit: int = 25):
    results = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.remediation_status == "APPROVED",
            ComplianceResult.exposure_status == "ACTIVE",
        )
        .all()
    )

    failed_controls = {
        control_id
        for (control_id,) in (
            db.query(ComplianceResult.control_id)
            .filter(
                ComplianceResult.tenant_id == tenant_id,
                ComplianceResult.passed.is_(False),
                ComplianceResult.exposure_status == "ACTIVE",
            )
            .distinct()
            .all()
        )
        if isinstance(control_id, str) and control_id
    }
    attack_path_summary = summarize_attack_paths(failed_controls)
    attack_path_controls = attack_path_summary.get("affected_controls") or set()
    critical_attack_path_controls = attack_path_summary.get("critical_controls") or set()

    prioritized = []

    for r in results:
        priority_score = compute_priority_score(
            r,
            attack_path_controls=attack_path_controls,
            critical_attack_path_controls=critical_attack_path_controls,
        )

        prioritized.append(
            {
                "compliance_result": r,
                "priority_score": priority_score,
            }
        )

    prioritized.sort(
        key=lambda x: x["priority_score"],
        reverse=True,
    )

    return prioritized[:limit]
