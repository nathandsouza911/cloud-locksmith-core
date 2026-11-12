from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.session import get_sync_db
from app.db.models.audit_log import AuditLog
from app.db.models.tenant import Tenant
from app.services.offboarding.rollback_summary import build_rollback_summary


router = APIRouter(
    prefix="/offboarding",
    tags=["One-Click Offboarding"],
)


@router.get("/{audit_id}/rollback-summary")
def get_rollback_summary(
    audit_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    audit = (
        db.query(AuditLog)
        .filter(
            AuditLog.id == audit_id,
            AuditLog.tenant_id == current_tenant.id,
            AuditLog.action == "OFFBOARDING",
        )
        .first()
    )

    if not audit:
        raise HTTPException(status_code=404, detail="Audit record not found")

    return build_rollback_summary(audit)
