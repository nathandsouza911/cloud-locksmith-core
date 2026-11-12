"""Campaign scheduler job — executes approved campaigns whose scheduled_at has passed.

SECURITY: Scheduled execution calls execute_campaign() directly, which
re-verifies ALL security gates at execution time:
  - approved_plan_hash presence (CRITICAL-C3)
  - per-task plan binding (assert_within_approved_plan)
  - per-task SAFE control check (assert_controls_safe)
  - tenant resolution (tenant must still exist)
No bypass path exists — scheduling is deferred execution, not pre-authorized execution.

DURABILITY: Campaign execution is tracked in campaign_scheduled_jobs.
The job moves through PENDING → CLAIMED → EXECUTING → COMPLETED | FAILED.
If this process crashes after claiming a job, the lease expires and
recover_campaign_jobs() returns the job to PENDING for retry.
"""

from __future__ import annotations

import asyncio
import logging

from app.db.session import SyncSessionLocal
from app.jobs.campaign_job_manager import (
    claim_due_jobs,
    mark_completed,
    mark_executing,
    mark_failed,
    recover_expired_leases,
)
from app.realtime.event_bus import get_event_bus
from app.realtime.event_models import make_event
from app.services.remediation.fleet.campaign_orchestrator import execute_campaign

logger = logging.getLogger(__name__)


async def run_campaign_scheduler() -> None:
    """Discover and execute all campaigns whose scheduled job is due."""
    db = SyncSessionLocal()
    try:
        # Phase 1: recover any jobs whose leases expired since last tick.
        recovery = recover_expired_leases(db)
        if recovery["reclaimed"] or recovery["permanently_failed"]:
            db.commit()
            logger.warning(
                "campaign_scheduler_lease_recovery reclaimed=%s permanently_failed=%s",
                recovery["reclaimed"],
                recovery["permanently_failed"],
            )

        # Phase 2: atomically claim all jobs due for execution.
        claimed = claim_due_jobs(db)
        if claimed:
            db.commit()

        # Phase 3: execute each claimed job.
        for job in claimed:
            logger.info(
                "campaign_scheduler_firing campaign_id=%s job_id=%s attempt=%s",
                job.campaign_id,
                job.id,
                job.attempts,
            )
            try:
                asyncio.get_event_loop().create_task(
                    get_event_bus().publish(
                        make_event(
                            "ScheduledJobClaimed",
                            str(job.organization_id),
                            {
                                "job_id": str(job.id),
                                "campaign_id": str(job.campaign_id),
                            },
                        )
                    )
                )
            except Exception:
                pass
            try:
                mark_executing(db, job)
                db.commit()

                await execute_campaign(db=db, campaign_id=job.campaign_id)

                mark_completed(db, job)
                db.commit()
                try:
                    asyncio.get_event_loop().create_task(
                        get_event_bus().publish(
                            make_event(
                                "ScheduledJobExecuted",
                                str(job.organization_id),
                                {
                                    "job_id": str(job.id),
                                    "campaign_id": str(job.campaign_id),
                                },
                            )
                        )
                    )
                except Exception:
                    pass
                logger.info(
                    "campaign_scheduler_completed campaign_id=%s job_id=%s",
                    job.campaign_id,
                    job.id,
                )
            except Exception as exc:
                try:
                    mark_failed(db, job, str(exc))
                    db.commit()
                    try:
                        asyncio.get_event_loop().create_task(
                            get_event_bus().publish(
                                make_event(
                                    "ScheduledJobFailed",
                                    str(job.organization_id),
                                    {
                                        "job_id": str(job.id),
                                        "campaign_id": str(job.campaign_id),
                                        "error": str(exc)[:300],
                                    },
                                )
                            )
                        )
                    except Exception:
                        pass
                except Exception:
                    logger.exception("campaign_scheduler_failed_to_record_failure job_id=%s", job.id)
                logger.exception(
                    "campaign_scheduler_execute_failed campaign_id=%s job_id=%s",
                    job.campaign_id,
                    job.id,
                )
    finally:
        db.close()
