from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from app.db.session import get_sync_db

router = APIRouter(prefix="/session", tags=["Session"])


class SessionContextResponse(BaseModel):
    mode: str  # "SMB" | "MSP"
    tenant_id: str | None
    role: str
    is_preview: bool


@router.get("/context", response_model=SessionContextResponse)
def get_session_context(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> SessionContextResponse:
    accesses = db.query(UserTenantAccess).filter(UserTenantAccess.user_id == current_user.id).all()

    if any(a.access_type == TenantAccessType.MSP_MANAGER for a in accesses):
        mode = "MSP"
    elif any(a.access_type is not None for a in accesses):
        # At least one typed row exists and none are MSP_MANAGER → SMB
        mode = "SMB"
    else:
        # Legacy fallback: all access_type values are NULL — read from org.mode
        org = current_user.organization
        org_mode_str = str(getattr(org, "mode", "")).upper()
        mode = "MSP" if "MANAGED" in org_mode_str else "SMB"

    if mode == "SMB":
        smb_access = next(
            (a for a in accesses if a.access_type == TenantAccessType.SMB_OWNER),
            accesses[0] if accesses else None,  # legacy: no typed rows
        )
        tenant_id = smb_access.tenant_id if smb_access else None
    else:
        tenant_id = None  # MSP: frontend selects from fleet

    is_preview = any(a.role == UserTenantRole.READ_ONLY or a.role == "READ_ONLY" for a in accesses)

    return SessionContextResponse(
        mode=mode,
        tenant_id=tenant_id,
        role=current_user.role or "ADMIN",
        is_preview=is_preview,
    )
