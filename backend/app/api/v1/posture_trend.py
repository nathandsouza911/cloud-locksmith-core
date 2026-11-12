from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.services.posture_trend_service import get_posture_trend

router = APIRouter(prefix="/api/v1/posture", tags=["Posture Trend"])


@router.get("/trend")
async def posture_trend(
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    trend = await get_posture_trend(db, current_tenant.id)

    return {
        "tenant_id": current_tenant.id,
        "trend": trend,
    }
