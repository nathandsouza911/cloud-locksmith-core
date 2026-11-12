from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.posture_snapshot_service import get_latest_posture_snapshot

router = APIRouter(
    prefix="/api/v1/posture",
    tags=["posture"],
)


@router.get("/score")
def get_posture_score(
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_sync_db),
):
    snapshot = get_latest_posture_snapshot(db, current_tenant.id)
    if snapshot is None:
        return {
            "score": None,
            "severity": None,
            "base_score": None,
            "breakdown": {},
            "attack_path_impact": {"deduction": 0, "paths": []},
            "top_risks": [],
            "control_breakdown": [],
            "timestamp": None,
        }
    posture = snapshot.posture if isinstance(snapshot.posture, dict) else {}
    risk = posture.get("risk", {})
    return {
        "score": posture.get("score", snapshot.security_score),
        "severity": posture.get("score_band") or risk.get("severity"),
        "base_score": risk.get("base_score"),
        "breakdown": risk.get("breakdown", {}),
        "attack_path_impact": risk.get("attack_path_impact", {"deduction": 0, "paths": []}),
        "top_risks": risk.get("top_risks", []),
        "control_breakdown": risk.get("control_breakdown", []),
        "timestamp": snapshot.created_at.isoformat() if snapshot.created_at else None,
    }
