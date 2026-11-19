from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from app.db.session import get_sync_db

router = APIRouter(prefix="/session", tags=["Session"])


class SessionContextResponse(BaseModel):
    tenant_id: str | None
    role: str
    is_preview: bool


@router.get("/context", response_model=SessionContextResponse)
def get_session_context(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> SessionContextResponse:
    accesses = db.query(UserTenantAccess).filter(UserTenantAccess.user_id == current_user.id).all()

    # The owned tenant first; otherwise the first tenant the user can reach (preview
    # and legacy rows have no SMB_OWNER access). Only the user's own rows are read.
    access = next(
        (a for a in accesses if a.access_type == TenantAccessType.SMB_OWNER),
        accesses[0] if accesses else None,
    )
    is_preview = any(a.role == UserTenantRole.READ_ONLY or a.role == "READ_ONLY" for a in accesses)

    return SessionContextResponse(
        tenant_id=access.tenant_id if access else None,
        role=current_user.role or "ADMIN",
        is_preview=is_preview,
    )
