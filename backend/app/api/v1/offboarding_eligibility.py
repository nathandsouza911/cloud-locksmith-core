from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.graph_client import fetch_user_memberof_directory_roles


router = APIRouter(
    prefix="/offboarding",
    tags=["One-Click Offboarding"],
)


@router.get("/eligibility/{user_id}")
async def offboarding_eligibility(
    user_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """
    Determines whether a user can be offboarded.
    Global Administrators are blocked unless force=true is used.
    """

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    roles = await fetch_user_memberof_directory_roles(db, current_tenant, user_id)

    is_global_admin = any(r.get("displayName") == "Global Administrator" for r in roles)

    if is_global_admin:
        return {
            "eligible": False,
            "reason": (
                "This user is a Global Administrator. "
                "Offboarding is blocked by default to prevent tenant lockout. "
                "Use force=true to override."
            ),
        }

    return {"eligible": True}
