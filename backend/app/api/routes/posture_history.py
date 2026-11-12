from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.dependencies.current_user import get_current_tenant
from app.db.session import get_db
from app.db.models.tenant import Tenant
from app.db.models.posture_snapshot import PostureSnapshot
from app.services.posture_timeline import compute_posture_delta

router = APIRouter(prefix="/posture/history", tags=["posture"])


@router.get("")
async def get_posture_history(
    limit: int = 30,
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    snapshots = (
        (
            await db.execute(
                select(PostureSnapshot)
                .where(PostureSnapshot.tenant_id == current_tenant.id)
                .order_by(PostureSnapshot.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    deltas: dict[int, dict | None] = {}
    for i in range(len(snapshots) - 1):
        delta = compute_posture_delta(snapshots[i + 1].posture, snapshots[i].posture)
        deltas[i] = delta if delta else None

    return [
        {
            "timestamp": s.created_at,
            "security_score": s.security_score,
            "posture": s.posture,
            "delta_from_previous": deltas.get(i),
        }
        for i, s in enumerate(snapshots)
    ]
