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
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities
from app.api.v1.remediation_rollback import CA_ENGINE_CONTROLS, _latest_rollback_source


router = APIRouter(
    prefix="/remediation",
    tags=["Remediation History"],
)


@router.get("/history")
def get_remediation_history(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    """Executed, not rolled back remediations that can be rolled back: one row per
    finding (its latest execution), newest first.

    Rollback-capable controls come from the control registry. A hard-coded set here
    left out every Conditional Access control, and an inner join on snapshots listed
    a finding once per snapshot (live run 2026-11-13, L16).
    """
    rollback_controls = [
        control_id for control_id in CONTROL_REGISTRY if get_control_capabilities(control_id)["has_rollback"]
    ]
    rows = (
        db.query(RemediationAuditLog, ComplianceResult, User.email)
        .join(
            ComplianceResult,
            ComplianceResult.id == RemediationAuditLog.compliance_result_id,
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
            ComplianceResult.control_id.in_(rollback_controls),
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .all()
    )

    items: list[dict] = []
    seen: set[int] = set()
    for audit, compliance, user_email in rows:
        if compliance.id in seen or current_remediation_status(compliance) != "SUCCESS":
            continue
        seen.add(compliance.id)
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
                "can_rollback": True,
                "snapshot_available": _snapshot_available(db, current_tenant.id, compliance),
            }
        )

    return items


def _snapshot_available(db: Session, tenant_id: str, compliance: ComplianceResult) -> bool:
    if compliance.control_id in CA_ENGINE_CONTROLS:
        # CA rollback restores the engine's control snapshot (see the rollback route).
        return _latest_rollback_source(db, tenant_id, compliance.control_id) is not None
    return (
        db.query(RemediationSnapshot.id).filter(RemediationSnapshot.compliance_result_id == compliance.id).first()
        is not None
    )
