from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.services.remediation_audit_service import log_audit_event
from app.services.remediation.lifecycle import TransitionEvent, transition
from app.utils.datetime import to_naive_utc, utc_now

logger = logging.getLogger(__name__)


def _fetch_tenant_auth_for_recovery(db: Session, tenant_id: str) -> Any | None:
    """
    Load stored Graph OAuth record for a tenant to enable Graph-state reconciliation.
    Returns None if auth is unavailable (tenant offboarded, tokens expired, etc.).
    """
    try:
        from app.db.models.tenant_oauth import TenantOAuth

        record = db.query(TenantOAuth).filter(TenantOAuth.tenant_id == tenant_id).one_or_none()
        return record
    except Exception:
        logger.warning("crash_recovery_auth_fetch_failed tenant_id=%s", tenant_id, exc_info=True)
        return None


async def _graph_confirms_remediation(tenant_auth: Any, row: ComplianceResult) -> bool:
    # Graph CA service not available — fail closed conservatively.
    # TODO: implement Graph state check when graph_ca_service is available
    # (fetch_ca_policies_for_tenant does not yet exist in graph_ca_service).
    logger.info(
        "crash_recovery_graph_check_skipped row_id=%s reason=graph_ca_service_unavailable",
        row.id,
    )
    return False


def recover_stuck_executions(db: Session) -> dict:
    """
    On startup, reconcile all EXECUTING rows against actual Graph state.

    For each stuck row:
    1. If Graph confirms the mutation succeeded → mark COMPLETED.
    2. Otherwise → mark FAILED (fail-closed).

    Returns a summary dict for structured logging.
    """
    stuck_rows = db.query(ComplianceResult).filter(ComplianceResult.remediation_status == "EXECUTING").all()

    if not stuck_rows:
        return {"processed": 0, "failed": 0, "verified_complete": 0}

    processed = 0
    failed = 0
    verified_complete = 0

    for row in stuck_rows:
        tenant_auth = _fetch_tenant_auth_for_recovery(db, str(row.tenant_id))
        graph_confirmed = False

        if tenant_auth is not None:
            try:
                graph_confirmed = asyncio.run(_graph_confirms_remediation(tenant_auth, row))
            except RuntimeError:
                # asyncio.run() raises RuntimeError if called from within a running
                # event loop. Fail closed in that case.
                graph_confirmed = False
            except Exception:
                logger.warning(
                    "crash_recovery_async_check_failed row_id=%s",
                    row.id,
                    exc_info=True,
                )
                graph_confirmed = False

        if graph_confirmed:
            transition(TransitionEvent.SUCCESS, row)
            row.execution_finished_at = to_naive_utc(utc_now())
            log_audit_event(
                db=db,
                tenant_id=row.tenant_id,
                compliance_result_id=row.id,
                control_id=row.control_id,
                resource_type="USER",
                resource_id=(
                    row.evidence.get("user_id") if row.evidence and "user_id" in row.evidence else row.tenant_id
                ),
                event_type="COMPLETED",
                confidence=0.9,
                metadata={"reason": "crash_recovery_graph_confirmed"},
            )
            verified_complete += 1
        else:
            transition(TransitionEvent.FAILURE, row)
            row.execution_finished_at = to_naive_utc(utc_now())
            log_audit_event(
                db=db,
                tenant_id=row.tenant_id,
                compliance_result_id=row.id,
                control_id=row.control_id,
                resource_type="USER",
                resource_id=(
                    row.evidence.get("user_id") if row.evidence and "user_id" in row.evidence else row.tenant_id
                ),
                event_type="FAILED",
                confidence=0.0,
                metadata={
                    "reason": "crash_recovery",
                    "graph_confirmed": False,
                    "auth_available": tenant_auth is not None,
                },
            )
            failed += 1

        processed += 1

    db.commit()
    return {"processed": processed, "failed": failed, "verified_complete": verified_complete}


def recover_campaign_jobs(db: Session) -> dict:
    """On startup, reclaim any campaign scheduled jobs with expired leases.

    This handles the crash window between claim and execution: if the
    process died after claiming a job (CLAIMED or EXECUTING) but before
    completing it, the lease will have expired. This function returns
    those jobs to PENDING so the scheduler loop picks them up on the
    next tick.

    Returns a summary dict for structured logging.
    """
    from app.jobs.campaign_job_manager import recover_expired_leases

    result = recover_expired_leases(db)
    db.commit()
    return result
