# app/services/remediation/verification/verify_execution.py

from app.utils.datetime import to_naive_utc, utc_now

from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.services.remediation.verification.engine import verification_engine


async def verify_execution(
    *,
    db: Session,
    tenant,
    compliance_result_id: int,
) -> dict:
    """Verify the current enforcement state of a remediation execution.

    Routes through verification_engine.verify_once() which:
    - Runs the per-control adapter (fail-closed)
    - Creates/updates the RemediationVerification lifecycle row
    - Appends VerificationEvent history

    The return shape is unchanged from Phase B.
    """
    compliance_result = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == str(tenant.id),
        )
        .one_or_none()
    )
    if not compliance_result:
        return {
            "success": False,
            "details": {"reason": "Compliance result not found"},
            "verification_supported": False,
            "verified_at": None,
        }

    execution = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.decision == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )

    if not execution:
        return {
            "success": False,
            "details": {"reason": "Remediation not executed"},
            "verification_supported": False,
            "verified_at": None,
        }

    if execution.rolled_back:
        return {
            "success": False,
            "details": {"reason": "Remediation was rolled back"},
            "verification_supported": False,
            "verified_at": execution.verified_at if execution.verified else None,
        }

    # verify_once handles lifecycle creation and state transitions.
    result, _lifecycle = await verification_engine.verify_once(
        execution.control_id,
        db=db,
        tenant=tenant,
        compliance_result=compliance_result,
        execution_id=execution.id,
    )

    if result is None:
        return {
            "success": False,
            "details": {"reason": f"No verifier for control {execution.control_id}"},
            "verification_supported": False,
            "verified_at": execution.verified_at if execution.verified else None,
        }

    # Preserve legacy audit log stamp (Phase B behavior — unchanged).
    if result.success and not execution.verified:
        execution.verified = True
        execution.verified_at = to_naive_utc(utc_now())
        db.commit()

    return {
        "success": result.success,
        "details": result.to_legacy_dict()["details"],
        "verification_supported": True,
        "verified_at": execution.verified_at if execution.verified else None,
    }
