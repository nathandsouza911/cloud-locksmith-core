from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.alert import Alert
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.utils.datetime import to_naive_utc, utc_now

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/")
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    result = await db.execute(
        select(Alert).where(Alert.tenant_id == current_tenant.id).order_by(Alert.created_at.desc())
    )
    return result.scalars().all()


@router.patch("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    # Ownership check: the alert must belong to the caller's own tenant. An
    # alert ID alone is never trusted — ID + tenant_id match is required
    # before any read or write, per the zero-trust tenant-isolation rule.
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_tenant.id,
        )
    )
    alert = result.scalars().first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.resolved_at = to_naive_utc(utc_now())
    await db.commit()
    await db.refresh(alert)
    return alert
