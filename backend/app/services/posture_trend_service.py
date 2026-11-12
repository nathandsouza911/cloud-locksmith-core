from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.posture_snapshot import PostureSnapshot


async def get_posture_trend(db: AsyncSession, tenant_id: str):
    result = await db.execute(
        select(PostureSnapshot).where(PostureSnapshot.tenant_id == tenant_id).order_by(PostureSnapshot.created_at)
    )

    snapshots = result.scalars().all()

    trend = []

    for snap in snapshots:
        trend.append(
            {
                "date": snap.created_at,
                "score": snap.security_score,
            }
        )

    return trend
