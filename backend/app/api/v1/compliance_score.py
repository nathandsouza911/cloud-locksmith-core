from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.session import get_sync_db
from app.db.models.tenant import Tenant
from app.services.posture_snapshot_service import get_latest_posture_snapshot

router = APIRouter(
    prefix="/compliance/score",
    tags=["Compliance Score"],
)


@router.get("")
def get_identity_posture_score(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    snapshot = get_latest_posture_snapshot(db, current_tenant.id)
    if snapshot is None:
        return {
            "score": None,
            "max_score": 100,
            "deductions": [],
            "severity": None,
            "breakdown": {},
            "attack_path_impact": {"deduction": 0, "paths": []},
        }
    posture = snapshot.posture if isinstance(snapshot.posture, dict) else {}
    return {
        "score": posture.get("score", snapshot.security_score),
        "max_score": 100,
        "deductions": posture.get("deductions", []),
        "severity": posture.get("score_band"),
        "breakdown": posture.get("breakdown", {}),
        "attack_path_impact": posture.get("attack_path_impact", {"deduction": 0, "paths": []}),
        "timestamp": snapshot.created_at.isoformat() if snapshot.created_at else None,
    }
