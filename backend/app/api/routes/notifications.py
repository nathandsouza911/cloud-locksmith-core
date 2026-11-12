from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies.current_user import get_current_tenant, require_write_access
from app.db.session import get_db
from app.db.models.notification_target import NotificationTarget
from app.db.models.tenant import Tenant

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.post("/register")
async def register_target(
    channel: str,
    destination: str,
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    # tenant_id is never taken from client input — it is derived from the
    # verified tenant context (get_current_tenant), which resolves the
    # X-Tenant-ID header against the caller's own UserTenantAccess row.
    # Accepting a client-supplied tenant_id here would let any OWNER/ADMIN
    # register a notification target for a tenant they don't own.
    target = NotificationTarget(
        tenant_id=current_tenant.id,
        channel=channel,
        destination=destination,
    )
    db.add(target)
    await db.commit()

    return {"status": "registered"}
