from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant, get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import get_sync_db
from app.services.identity_scan_service import start_scan_task

router = APIRouter(
    prefix="/api/v1/scan",
    tags=["Identity Scan"],
)


def _tenant_ids_for_user(db: Session, user_id: int | str) -> list[str]:
    rows = db.query(UserTenantAccess.tenant_id).filter(UserTenantAccess.user_id == user_id).all()
    return [tenant_id for (tenant_id,) in rows]


@router.post("/all")
async def trigger_all_tenant_scans(
    current_user: PlatformUser = Depends(get_current_user),
    db: Session = Depends(get_sync_db),
):
    tenant_ids = _tenant_ids_for_user(db, current_user.id)
    if not tenant_ids:
        raise HTTPException(status_code=404, detail="No tenant access found for the current user")

    started: list[str] = []
    skipped: list[dict[str, str]] = []

    for tenant_id in tenant_ids:
        scan_started = await start_scan_task(tenant_id)
        if scan_started:
            started.append(tenant_id)
        else:
            skipped.append(
                {
                    "tenant_id": tenant_id,
                    "reason": "scan_already_running",
                }
            )

    return {
        "status": "scan_started",
        "message": "Scan started successfully",
        "started_tenant_ids": started,
        "skipped": skipped,
    }


@router.post("/identity")
async def trigger_identity_scan(
    request: Request,
    current_tenant: Tenant = Depends(get_current_tenant),
):
    tenant_id = getattr(request.state, "tenant_id", None) or current_tenant.id
    scan_started = await start_scan_task(tenant_id)
    if not scan_started:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Scan already running for this tenant",
                "tenant_id": tenant_id,
            },
        )

    return {
        "status": "scan_started",
        "message": "Scan started successfully",
        "tenant_id": tenant_id,
    }


@router.post("/{tenant_id}")
async def trigger_tenant_scan(
    tenant_id: str,
    current_user: PlatformUser = Depends(get_current_user),
    db: Session = Depends(get_sync_db),
):
    tenant_ids = set(_tenant_ids_for_user(db, current_user.id))
    if tenant_id not in tenant_ids:
        raise HTTPException(status_code=403, detail="Invalid or unauthorized tenant_id")

    scan_started = await start_scan_task(tenant_id)
    if not scan_started:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Scan already running for this tenant",
                "tenant_id": tenant_id,
            },
        )

    return {
        "status": "scan_started",
        "message": "Scan started successfully",
        "tenant_id": tenant_id,
    }
