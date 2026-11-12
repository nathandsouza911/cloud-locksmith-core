from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.break_glass_safeguards import protected_target_result
from app.services.remediation.lifecycle import (
    BlockReason,
    TransitionEvent,
    can_transition,
    current_exposure_status,
    current_remediation_status,
    normalize_block_reason,
)


TERMINAL_EXECUTION_STATES = {"SUCCESS", "FAILED"}
DIRECT_EXECUTION_STATES = {
    "APPROVED",
}
MAX_EXECUTION_ATTEMPTS = 3


def check_execution_eligibility(
    *,
    db: Session,
    compliance_result_id: int,
    tenant_id: str | None = None,
) -> dict:
    """
    Determines whether remediation execution is allowed.
    Read-only. No side effects.
    """

    compliance = db.get(ComplianceResult, compliance_result_id)

    if not compliance or (tenant_id and compliance.tenant_id != tenant_id):
        return {
            "allowed": False,
            "eligible": False,
            "reason": "Compliance result not found",
            "block_reason": BlockReason.UNKNOWN.value,
        }

    if compliance.passed:
        return {
            "allowed": False,
            "eligible": False,
            "reason": "Finding is already compliant - no remediation required",
            "block_reason": None,
        }

    protected_target = protected_target_result(
        db=db,
        compliance=compliance,
    )
    if protected_target:
        return protected_target

    remediation_status = current_remediation_status(compliance)
    if remediation_status == "FAILED":
        return {
            "allowed": False,
            "eligible": False,
            "reason": "FAILED remediations must be approved before retry",
            "block_reason": None,
        }
    if remediation_status == "BLOCKED":
        block_reason = normalize_block_reason(compliance.block_reason)
        return {
            "allowed": False,
            "eligible": False,
            "reason": f"Remediation is blocked: {block_reason}",
            "block_reason": block_reason,
        }

    if current_exposure_status(compliance) != "ACTIVE":
        return {
            "allowed": False,
            "eligible": False,
            "reason": "Finding is already resolved",
            "block_reason": None,
        }

    if (compliance.execution_attempts or 0) >= MAX_EXECUTION_ATTEMPTS:
        return {
            "allowed": False,
            "eligible": False,
            "reason": "Execution attempt limit reached",
            "block_reason": None,
        }

    if remediation_status not in DIRECT_EXECUTION_STATES:
        return {
            "allowed": False,
            "eligible": False,
            "reason": f"Remediation cannot execute from state {remediation_status}",
            "block_reason": None,
        }

    snapshot_exists = db.query(RemediationSnapshot).filter_by(compliance_result_id=compliance_result_id).first()

    if snapshot_exists:
        return {
            "allowed": False,
            "eligible": False,
            "reason": "Remediation already executed",
            "block_reason": None,
        }

    if remediation_status == "EXECUTING":
        return {
            "allowed": False,
            "eligible": False,
            "reason": "Remediation execution already in progress",
            "block_reason": None,
        }

    allowed, reason, next_state = can_transition(
        TransitionEvent.EXECUTE,
        compliance,
        eligibility_passed=True,
    )
    if not allowed:
        return {
            "allowed": False,
            "eligible": False,
            "reason": reason,
            "block_reason": None,
        }

    return {
        "allowed": True,
        "eligible": True,
        "reason": None,
        "block_reason": None,
        "execution": {
            "control_id": compliance.control_id,
            "resource_type": compliance.resource_type,
            "resource_id": compliance.resource_id,
            "decision": remediation_status,
            "next_state": next_state,
        },
    }


MAX_REMEDIATIONS_7D = 2


def is_execution_allowed(result):
    if result.drift_lock:
        return False, "Control is drift locked"

    if result.remediation_count_7d >= MAX_REMEDIATIONS_7D:
        return False, "Remediation limit reached"

    return True, None
