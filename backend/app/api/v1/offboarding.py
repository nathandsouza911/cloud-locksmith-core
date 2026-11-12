from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_tenant_with_fresh_auth,
    require_write_access,
)
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.offboarding.offboarding_execute import execute_offboarding
from app.services.offboarding.offboarding_preview import preview_offboarding


router = APIRouter(
    prefix="/offboarding",
    tags=["One-Click Offboarding"],
)


@router.post("/preview")
async def offboarding_preview(
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    user_id = payload.get("user_id")
    options = payload.get("options", {})
    force = payload.get("force", False)

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    return await preview_offboarding(
        db=db,
        tenant=current_tenant,
        user_id=user_id,
        options=options,
        force=force,
    )


@router.post("/execute")
async def offboarding_execute(
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    user_id = payload.get("user_id")
    options = payload.get("options", {})
    reason = payload.get("reason", "Offboarding")
    force = payload.get("force", False)

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    return await execute_offboarding(
        db=db,
        tenant=current_tenant,
        user_id=user_id,
        options=options,
        reason=reason,
        force=force,
    )
