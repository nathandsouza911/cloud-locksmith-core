from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.schemas.compliance import RiskFeedItemResponse
from app.services.risk_feed_service import get_risk_feed

router = APIRouter()


@router.get("/risk-feed", response_model=list[RiskFeedItemResponse])
async def risk_feed(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    include_ignored: bool = Query(True),
):
    return await get_risk_feed(
        db,
        current_tenant.id,
        include_ignored=include_ignored,
    )
