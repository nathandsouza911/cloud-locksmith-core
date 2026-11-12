# app/services/remediation/rollback/rollback_eligibility.py

from sqlalchemy.orm import Session
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.services.remediation.lifecycle import current_remediation_status


def check_rollback_eligibility(
    *,
    db: Session,
    compliance_result_id: int,
    tenant_id: str,
) -> dict:
    """
    Determines whether rollback is allowed for a remediation execution.

    Read-only. No side effects.
    """

    execution = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == tenant_id,
        )
        .one_or_none()
    )

    if not execution:
        return {
            "eligible": False,
            "reason": "Compliance result not found",
        }

    remediation_status = current_remediation_status(execution)
    if remediation_status != "SUCCESS":
        return {
            "eligible": False,
            "reason": f"Rollback not allowed from state {remediation_status}",
        }

    execution_audit = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.tenant_id == tenant_id,
            RemediationAuditLog.decision == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )

    if not execution_audit:
        return {
            "eligible": False,
            "reason": "No executed remediation found",
        }

    if execution_audit.rolled_back:
        return {
            "eligible": False,
            "reason": "Remediation already rolled back",
        }

    if execution_audit.execution_status == "FAILED":
        return {
            "eligible": False,
            "reason": "Remediation execution failed",
        }

    return {
        "eligible": True,
        "reason": None,
        "execution": {
            "control_id": execution_audit.control_id,
            "resource_type": execution_audit.resource_type,
            "resource_id": execution_audit.resource_id,
            "executed_at": execution_audit.created_at,
        },
    }
