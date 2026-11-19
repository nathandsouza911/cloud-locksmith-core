from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.overview_service import get_tenant_overview

router = APIRouter(tags=["Overview"])


@router.get("/overview")
def overview(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    # The tenant comes from the session (X-Tenant-ID checked against the user's
    # tenant access), never from a query or path parameter.
    return get_tenant_overview(db, current_tenant)
