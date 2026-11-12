from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.db.models.remediation_audit import RemediationAuditLog

router = APIRouter(
    prefix="/remediation/audit",
    tags=["Remediation Audit"],
)


@router.get("/{decision_id}")
def get_audit_timeline(
    decision_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    events = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.tenant_id == current_tenant.id,
            RemediationAuditLog.decision == decision_id,
        )
        .order_by(RemediationAuditLog.created_at.asc())
        .all()
    )

    return [
        {
            "event_type": e.decision,
            "timestamp": e.created_at,
            "metadata": e.explanation_summary,
        }
        for e in events
    ]
