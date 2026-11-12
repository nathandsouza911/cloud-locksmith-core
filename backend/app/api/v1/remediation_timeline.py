from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.services.remediation_timeline_service import get_remediation_timeline

router = APIRouter()


@router.get("/remediation-timeline")
async def remediation_timeline(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    timeline = await get_remediation_timeline(db, current_tenant.id, limit)

    return timeline
