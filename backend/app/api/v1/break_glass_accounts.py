"""Break-glass account registration (ROADMAP 2.7).

Listing is open to anyone with access to the tenant; registering and removing are
owner-only. The tenant always comes from the session, never from the request body.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    audit_actor,
    get_current_user,
    get_explicit_current_tenant,
    is_tenant_owner,
    require_owner,
)
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.break_glass_registration import (
    BreakGlassRegistrationError,
    list_registered,
    register_existing,
    remove_registered,
)

router = APIRouter(prefix="/api/v1/break-glass/accounts", tags=["Break Glass"])


class RegisterBreakGlassRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    user: str = Field(min_length=1, max_length=256, description="Object ID or user principal name")


def _http_error(exc: BreakGlassRegistrationError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message})


@router.get("")
async def list_break_glass_accounts(
    request: Request,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    return {"accounts": list_registered(db, current_tenant), "can_manage": is_tenant_owner(request)}


@router.post("", status_code=201, dependencies=[Depends(require_owner)])
async def register_break_glass_account(
    payload: RegisterBreakGlassRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
):
    try:
        return await register_existing(db, current_tenant, payload.user, actor=audit_actor(current_user))
    except BreakGlassRegistrationError as exc:
        raise _http_error(exc) from exc


@router.delete("/{account_id}", status_code=204, dependencies=[Depends(require_owner)])
async def remove_break_glass_account(
    account_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
):
    try:
        remove_registered(db, current_tenant, account_id, actor=audit_actor(current_user))
    except BreakGlassRegistrationError as exc:
        raise _http_error(exc) from exc
    return Response(status_code=204)
