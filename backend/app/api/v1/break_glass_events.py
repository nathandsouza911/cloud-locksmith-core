from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models.break_glass_usage_event import BreakGlassUsageEvent
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db

router = APIRouter(prefix="/api/v1/break-glass", tags=["Break Glass"])


def _serialize_event(event: BreakGlassUsageEvent) -> dict:
    return {
        "id": event.id,
        "tenant_id": event.tenant_id,
        "user_id": event.user_id,
        "user_principal_name": event.user_principal_name,
        "source_event_id": event.source_event_id,
        "source": event.source,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "ip_address": event.ip_address,
        "location": event.location,
        "status": event.status,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


@router.get("/events")
async def list_break_glass_events(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    events = (
        db.query(BreakGlassUsageEvent)
        .filter(BreakGlassUsageEvent.tenant_id == current_tenant.id)
        .order_by(BreakGlassUsageEvent.timestamp.desc(), BreakGlassUsageEvent.id.desc())
        .all()
    )
    return [_serialize_event(event) for event in events]
