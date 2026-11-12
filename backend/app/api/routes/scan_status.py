from fastapi import APIRouter, Depends

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.services.identity_scan_service import is_scan_active

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])


@router.get("/status")
async def get_scan_status(
    current_tenant: Tenant = Depends(get_current_tenant),
):
    in_progress = await is_scan_active(str(current_tenant.id))
    return {
        "tenant_id": current_tenant.id,
        "last_scan_at": current_tenant.last_scan_at,
        "last_scheduler_run": current_tenant.last_scheduler_run,
        "scheduler_failures": current_tenant.scheduler_failures,
        "in_progress": in_progress,
        "has_completed_scan": current_tenant.last_scan_at is not None,
    }
