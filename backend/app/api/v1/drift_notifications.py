from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant, get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.drift_notification_service import (
    acknowledge_notification,
    get_summary,
    list_notifications,
)

router = APIRouter(
    prefix="/drift-notifications",
    tags=["Drift Notifications"],
)


# IMPORTANT: /summary must be declared BEFORE /{notification_id}/acknowledge.
# FastAPI resolves path parameters eagerly; placing /summary after a
# parameterised route would cause "summary" to match notification_id.


@router.get("/summary")
def get_drift_notification_summary(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """Return unacknowledged notification counts by severity for the current tenant."""
    return get_summary(db, tenant_id=current_tenant.id)


@router.get("")
def list_drift_notifications(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    include_acknowledged: bool = Query(
        default=False,
        description="When true, also returns notifications acknowledged within the last 7 days.",
    ),
):
    """List drift notifications for the current tenant, newest first."""
    notifications = list_notifications(
        db,
        tenant_id=current_tenant.id,
        include_acknowledged=include_acknowledged,
        limit=limit,
        offset=offset,
    )
    return [_serialize(n) for n in notifications]


@router.post("/{notification_id}/acknowledge")
def acknowledge_drift_notification(
    notification_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Acknowledge a drift notification.

    Idempotent — re-acknowledging an already-acknowledged notification
    updates acknowledged_by and acknowledged_at to the latest values.

    Returns 404 when the notification does not exist or belongs to a
    different tenant (avoids leaking record existence via 403).
    """
    acknowledged_by = current_user.email or str(current_user.id)
    notification = acknowledge_notification(
        db,
        notification_id=notification_id,
        tenant_id=current_tenant.id,
        acknowledged_by=acknowledged_by,
    )
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")

    db.commit()
    db.refresh(notification)
    return _serialize(notification)


def _serialize(n) -> dict:
    return {
        "id": n.id,
        "tenant_id": n.tenant_id,
        "control_id": n.control_id,
        "compliance_result_id": n.compliance_result_id,
        "verification_id": n.verification_id,
        "notification_severity": n.notification_severity,
        "is_repeat_drift": n.is_repeat_drift,
        "previous_status": n.previous_status,
        "affects_readiness_score": n.affects_readiness_score,
        "affects_underwriting_evidence": n.affects_underwriting_evidence,
        "confidence_tier_before": n.confidence_tier_before,
        "summary": n.summary,
        "acknowledged": n.acknowledged,
        "acknowledged_at": n.acknowledged_at,
        "acknowledged_by": n.acknowledged_by,
        "created_at": n.created_at,
    }
