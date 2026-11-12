import logging
from app.utils.datetime import to_naive_utc, utc_now

from app.db.session import SyncSessionLocal
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.services.remediation.lifecycle import (
    TransitionEvent,
    current_exposure_status,
    current_remediation_status,
    transition,
)
from app.core.metrics import increment
from app.services.posture_snapshot_service import create_posture_snapshot
from app.services.remediation.verification.engine import verification_engine

logger = logging.getLogger(__name__)


async def run_verification_job():
    db = SyncSessionLocal()

    try:
        logger.info("verification_job_started")

        findings = db.query(ComplianceResult).filter(ComplianceResult.remediation_status == "SUCCESS").all()

        logger.info("verification_job_findings count=%s", len(findings))

        for finding in findings:
            tenant = db.get(Tenant, finding.tenant_id)
            if not tenant:
                continue

            try:
                latest_execution = (
                    db.query(RemediationAuditLog)
                    .filter(
                        RemediationAuditLog.compliance_result_id == finding.id,
                        RemediationAuditLog.execution_status == "EXECUTED",
                    )
                    .order_by(RemediationAuditLog.created_at.desc())
                    .first()
                )
                if latest_execution is None:
                    # No executed audit log yet — cannot create lifecycle row without execution_id.
                    continue

                result, _lifecycle = await verification_engine.verify_confirmed(
                    finding.control_id,
                    db=db,
                    tenant=tenant,
                    compliance_result=finding,
                    execution_id=latest_execution.id,
                )

                if result is None:
                    # control does not support verification — skip silently
                    continue

                if result.success:
                    finding.last_verified_at = to_naive_utc(utc_now())
                    db.commit()
                    logger.info("verification_passed finding_id=%s", finding.id)

                else:
                    logger.warning("drift_detected finding_id=%s", finding.id)
                    increment("drift_detected")
                    if (
                        current_remediation_status(finding) == "SUCCESS"
                        and current_exposure_status(finding) == "ACTIVE"
                    ):
                        transition(
                            TransitionEvent.DRIFT_DETECTED,
                            finding,
                            drift_detected=True,
                        )
                        db.commit()
                        create_posture_snapshot(
                            db,
                            tenant_id=tenant.id,
                            reason="drift",
                        )
                        logger.info("drift_requeued finding_id=%s", finding.id)

            except Exception:
                logger.exception("verification_error finding_id=%s", finding.id)

        logger.info("verification_job_complete")

    finally:
        db.close()
