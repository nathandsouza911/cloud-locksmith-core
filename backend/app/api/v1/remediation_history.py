from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation.lifecycle import current_remediation_status
from app.services.remediation.control_registry import get_control_capabilities


router = APIRouter(
    prefix="/remediation",
    tags=["Remediation History"],
)

ROLLBACK_SUPPORTED_CONTROLS = {
    "IDENTITY_UNUSED_ACCOUNT",
    "IDENTITY_OVERPRIVILEGED_USER",
    "IDENTITY_USER_NO_MFA",
    "IDENTITY_ADMIN_NO_MFA",
    "IDENTITY_BREAK_GLASS_ACCOUNT",
    "IDENTITY_GUEST_INVITES_OPEN",
    "IDENTITY_USER_CONSENT_POLICY",
}


@router.get("/history")
def get_remediation_history(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    rows = (
        db.query(
            RemediationAuditLog,
            ComplianceResult,
            RemediationSnapshot,
            User.email,
        )
        .join(
            ComplianceResult,
            ComplianceResult.id == RemediationAuditLog.compliance_result_id,
        )
        .join(
            RemediationSnapshot,
            RemediationSnapshot.compliance_result_id == ComplianceResult.id,
        )
        .outerjoin(
            User,
            (User.tenant_id == ComplianceResult.tenant_id) & (User.external_id == ComplianceResult.resource_id),
        )
        .filter(
            RemediationAuditLog.tenant_id == current_tenant.id,
            RemediationAuditLog.decision == "EXECUTED",
            (RemediationAuditLog.rolled_back.is_(False) | RemediationAuditLog.rolled_back.is_(None)),
            ComplianceResult.tenant_id == current_tenant.id,
            ComplianceResult.control_id.in_(ROLLBACK_SUPPORTED_CONTROLS),
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .all()
    )

    items: list[dict] = []
    for audit, compliance, snapshot, user_email in rows:
        if current_remediation_status(compliance) != "SUCCESS":
            continue

        items.append(
            {
                "compliance_result_id": compliance.id,
                "control_id": compliance.control_id,
                "resource_id": compliance.resource_id,
                "resource_label": user_email
                or (compliance.evidence or {}).get("user_principal_name")
                or compliance.resource_id,
                "status": "SUCCESS",
                "executed_at": audit.created_at.isoformat() if audit.created_at else None,
                "can_rollback": get_control_capabilities(compliance.control_id)["has_rollback"],
                "snapshot_available": snapshot is not None,
            }
        )

    return items
