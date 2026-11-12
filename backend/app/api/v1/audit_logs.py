from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.session import get_sync_db
from app.db.models.audit_log import AuditLog
from app.db.models.tenant import Tenant


router = APIRouter(
    prefix="/audit/logs",
    tags=["Audit Logs"],
)


@router.get("")
def list_audit_logs(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    since: Optional[datetime] = Query(default=None, description="Filter logs created at or after this timestamp (UTC)"),
    until: Optional[datetime] = Query(
        default=None, description="Filter logs created at or before this timestamp (UTC)"
    ),
    action: Optional[str] = Query(default=None, description="Filter by exact action type, e.g. OFFBOARDING"),
):
    query = db.query(AuditLog).filter(AuditLog.tenant_id == current_tenant.id)

    if since is not None:
        query = query.filter(AuditLog.created_at >= since)
    if until is not None:
        query = query.filter(AuditLog.created_at <= until)
    if action is not None:
        query = query.filter(AuditLog.action == action)

    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "id": log_entry.id,
            "action": log_entry.action,
            "actor": log_entry.actor,
            "target": log_entry.target,
            "status": log_entry.status,
            "reason": log_entry.reason,
            "details": log_entry.details,
            "created_at": log_entry.created_at,
        }
        for log_entry in logs
    ]
