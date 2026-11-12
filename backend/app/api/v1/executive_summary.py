from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.services.reports.executive_summary_service import generate_executive_summary

router = APIRouter()


@router.get("/reports/executive-summary")
async def executive_summary(
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    return await generate_executive_summary(db, current_tenant.id)
