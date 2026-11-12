import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant_with_fresh_auth, require_write_access
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation.lifecycle import (
    current_remediation_status,
    reconcile_rolled_back_state,
)
from app.services.posture_snapshot_service import create_posture_snapshot
from app.services.ca_policy_engine import rollback_control_dispatch
from app.services.remediation.admin_roles.admin_role_rollback import rollback_admin_roles
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities
from app.services.remediation_executor import RemediationGraphClient
from app.services.remediation.rollback.dormant_account_rollback_executor import (
    DormantAccountRollbackError,
    rollback_dormant_account,
)

router = APIRouter(
    prefix="/remediation",
    tags=["Remediation Rollback"],
)

logger = logging.getLogger(__name__)


@router.post("/rollback/{compliance_result_id}")
@router.post("/{compliance_result_id}/rollback")
async def rollback_remediation(
    compliance_result_id: int,
    payload: dict | None = None,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    payload = payload or {}

    reason = payload.get("reason", "ui-rollback")
    requested_by = payload.get("requested_by", "ui")
    execution_id = payload.get("execution_id")

    compliance = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == current_tenant.id,
        )
        .with_for_update()
        .one_or_none()
    )

    if not compliance:
        raise HTTPException(status_code=404, detail="Compliance result not found")

    if not get_control_capabilities(compliance.control_id)["has_rollback"]:
        raise HTTPException(
            status_code=400,
            detail=f"Rollback not supported for {compliance.control_id}",
        )

    remediation_status = current_remediation_status(compliance)
    if remediation_status != "SUCCESS":
        raise HTTPException(
            status_code=400,
            detail=f"Rollback not allowed from state {remediation_status}",
        )

    is_ca_engine_control = compliance.control_id in {
        "CA_MFA_ALL_USERS",
        "CA_MFA_ADMINS",
        "CA_LEGACY_AUTH_BLOCK",
        "CA_DEVICE_CODE_FLOW_BLOCK",
        "CA_AUTHENTICATION_TRANSFER_BLOCK",
        "CA_GUEST_MFA",
        "CA_BREAK_GLASS_EXCLUSION",
    }

    snapshot = None
    if not is_ca_engine_control:
        snapshot_row = (
            db.query(RemediationSnapshot)
            .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
            .order_by(RemediationSnapshot.created_at.desc())
            .first()
        )

        if not snapshot_row:
            raise HTTPException(
                status_code=400,
                detail="No remediation snapshot found for rollback",
            )

        snapshot = snapshot_row.state
    execution = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.tenant_id == current_tenant.id,
            RemediationAuditLog.decision == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )

    try:
        if compliance.control_id == "IDENTITY_UNUSED_ACCOUNT":
            result = await rollback_dormant_account(
                db=db,
                tenant=current_tenant,
                compliance_result_id=compliance_result_id,
                reason=reason,
                requested_by=requested_by,
            )
        elif compliance.control_id == "IDENTITY_OVERPRIVILEGED_USER":
            result = await rollback_admin_roles(
                db=db,
                tenant=current_tenant,
                snapshot_state=snapshot,
            )
        elif is_ca_engine_control:
            if not execution_id:
                raise HTTPException(
                    status_code=400,
                    detail="execution_id is required for Conditional Access rollback",
                )
            result = await rollback_control_dispatch(
                db=db,
                tenant=current_tenant,
                control_id=compliance.control_id,
                execution_id=str(execution_id),
            )
        else:
            control = CONTROL_REGISTRY.get(compliance.control_id) or {}
            executor = control.get("executor")
            if executor is None or not hasattr(executor, "rollback"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Rollback not supported for {compliance.control_id}",
                )
            await executor.rollback(
                RemediationGraphClient(db=db, tenant=current_tenant),
                snapshot,
            )
            result = {
                "status": "ROLLED_BACK",
                "message": f"Rollback completed for {compliance.control_id}",
            }

        if execution is not None:
            execution.rolled_back = True
            execution.execution_status = "ROLLED_BACK"
            execution.verified = False
            db.add(
                RemediationAuditLog(
                    tenant_id=current_tenant.id,
                    compliance_result_id=compliance.id,
                    control_id=compliance.control_id,
                    resource_type=compliance.resource_type,
                    resource_id=compliance.resource_id,
                    decision="ROLLED_BACK",
                    confidence=1.0,
                    explanation_summary="Rollback executed",
                    explanation_factors={
                        "reason": reason,
                        "requested_by": requested_by,
                    },
                    explanation_risk_note="Manual rollback",
                    rolled_back=True,
                )
            )

        reconcile_rolled_back_state(compliance)
        compliance.passed = False
        compliance.exposure_status = ExposureStatus.ACTIVE.value
        compliance.resolved_at = None
        compliance.resolved_by = None
        db.commit()
        create_posture_snapshot(
            db,
            tenant_id=current_tenant.id,
            reason="rollback",
        )

        return {
            "status": "ROLLED_BACK",
            "compliance_result_id": compliance_result_id,
            **(result or {}),
        }

    except DormantAccountRollbackError as exc:
        # Domain-specific user-facing validation error — message is curated.
        raise HTTPException(status_code=400, detail=str(exc))

    except Exception:
        # Never echo raw exception text or type names to the client; those
        # regularly include internal paths, tenant IDs, and partial token
        # claim dumps. Log server-side only.
        logger.exception(
            "rollback_remediation_internal_error compliance_result_id=%s",
            compliance_result_id,
        )
        return JSONResponse(
            status_code=500,
            content={
                "status": "failed",
                "reason": "internal_error",
            },
        )
