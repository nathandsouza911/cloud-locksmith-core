from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.session import get_sync_db
from app.services.msp_risk_service import get_msp_risk_summary

router = APIRouter(prefix="/msp", tags=["MSP"])


@router.get("/fleet-overview")
def fleet_overview(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    return get_msp_risk_summary(current_user.id, db)
