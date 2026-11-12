from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db

router = APIRouter(
    prefix="/api/v1/posture",
    tags=["posture"],
)


@router.get(
    "/timeline",
    response_model=None,
)
def get_posture_timeline(
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_sync_db),
):
    rows = (
        db.query(PostureSnapshot)
        .filter(PostureSnapshot.tenant_id == current_tenant.id)
        .order_by(PostureSnapshot.created_at.asc(), PostureSnapshot.id.asc())
        .all()
    )

    if not rows:
        return []

    timeline = []
    by_timestamp: dict[str, dict] = {}

    for row in rows:
        timestamp = row.created_at.isoformat() if row.created_at else None
        if not timestamp:
            continue
        by_timestamp[timestamp] = {
            "timestamp": timestamp,
            "score": row.security_score,
        }

    for timestamp in sorted(by_timestamp):
        timeline.append(by_timestamp[timestamp])

    return timeline
