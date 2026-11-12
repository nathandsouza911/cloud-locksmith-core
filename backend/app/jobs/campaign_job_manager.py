"""Campaign scheduled job lifecycle manager.

Provides atomic claim, state transitions, and lease recovery for the
campaign_scheduled_jobs table. All functions take an open SQLAlchemy
Session and flush (not commit) — callers control transaction boundaries.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models.campaign_scheduled_job import CampaignScheduledJob, JobState
from app.realtime.event_bus import get_event_bus
from app.realtime.event_models import make_event
from app.utils.datetime import utc_now

LEASE_DURATION_SECONDS = 600
MAX_JOB_ATTEMPTS = 3
WORKER_ID = f"{socket.gethostname()}-{os.getpid()}"


def create_job(
    db: Session,
    campaign_id: uuid.UUID,
    organization_id: uuid.UUID,
    scheduled_at: datetime,
) -> CampaignScheduledJob:
    """Create a PENDING job record for a newly scheduled campaign.

    Raises IntegrityError if a job for this campaign_id already exists
    (enforced by the unique constraint on campaign_id).
    """
    job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=campaign_id,
        organization_id=organization_id,
        scheduled_at=scheduled_at,
        state=JobState.PENDING.value,
        attempts=0,
        max_attempts=MAX_JOB_ATTEMPTS,
    )
    db.add(job)
    db.flush()
    try:
        asyncio.get_event_loop().create_task(
            get_event_bus().publish(
                make_event(
                    "ScheduledJobCreated",
                    str(job.organization_id),
                    {
                        "job_id": str(job.id),
                        "campaign_id": str(job.campaign_id),
                        "scheduled_at": job.scheduled_at.isoformat() if job.scheduled_at else None,
                    },
                )
            )
        )
    except Exception:
        pass
    return job


def delete_pending_job(db: Session, campaign_id: uuid.UUID) -> bool:
    """Delete the PENDING job for a campaign (called on schedule cancel).

    Returns True if a row was deleted.
    Does not delete CLAIMED/EXECUTING/COMPLETED/FAILED jobs — in-flight
    jobs cannot be cancelled via the API.
    """
    deleted = (
        db.query(CampaignScheduledJob)
        .filter(
            CampaignScheduledJob.campaign_id == campaign_id,
            CampaignScheduledJob.state == JobState.PENDING.value,
        )
        .delete(synchronize_session="fetch")
    )
    db.flush()
    return deleted > 0


def claim_due_jobs(db: Session) -> list[CampaignScheduledJob]:
    """Atomically claim all PENDING jobs whose scheduled_at has passed.

    Uses SELECT FOR UPDATE SKIP LOCKED to prevent two workers from
    claiming the same job. Returns the list of claimed jobs; their
    state is CLAIMED and lease fields are populated.

    Caller must commit after this returns for the claims to be durable.
    """
    due = (
        db.query(CampaignScheduledJob)
        .filter(
            CampaignScheduledJob.state == JobState.PENDING.value,
            CampaignScheduledJob.scheduled_at <= utc_now(),
        )
        .with_for_update(skip_locked=True)
        .all()
    )

    lease_expiry = utc_now() + timedelta(seconds=LEASE_DURATION_SECONDS)
    for job in due:
        job.state = JobState.CLAIMED.value
        job.lease_owner = WORKER_ID
        job.lease_expires_at = lease_expiry
        job.attempts += 1

    if due:
        db.flush()

    return due


def mark_executing(db: Session, job: CampaignScheduledJob) -> None:
    """Advance job from CLAIMED to EXECUTING once execute_campaign() is called."""
    job.state = JobState.EXECUTING.value
    job.execution_started_at = utc_now()
    db.flush()


def mark_completed(db: Session, job: CampaignScheduledJob) -> None:
    """Mark job COMPLETED after successful execute_campaign() return."""
    job.state = JobState.COMPLETED.value
    job.execution_completed_at = utc_now()
    job.lease_owner = None
    job.lease_expires_at = None
    db.flush()


def mark_failed(db: Session, job: CampaignScheduledJob, reason: str) -> None:
    """Mark job FAILED after execute_campaign() raises an exception."""
    job.state = JobState.FAILED.value
    job.execution_completed_at = utc_now()
    job.failure_reason = reason[:500]
    job.lease_owner = None
    job.lease_expires_at = None
    db.flush()


def recover_expired_leases(db: Session) -> dict:
    """Find CLAIMED/EXECUTING jobs with expired leases and recover them.

    Jobs below max_attempts return to PENDING for retry.
    Jobs at max_attempts are permanently FAILED.

    Uses SKIP LOCKED so concurrent recovery workers don't conflict.
    Caller must commit after this returns.
    """
    abandoned = (
        db.query(CampaignScheduledJob)
        .filter(
            CampaignScheduledJob.state.in_([JobState.CLAIMED.value, JobState.EXECUTING.value]),
            CampaignScheduledJob.lease_expires_at < utc_now(),
        )
        .with_for_update(skip_locked=True)
        .all()
    )

    reclaimed = 0
    permanently_failed = 0

    for job in abandoned:
        if job.attempts >= job.max_attempts:
            job.state = JobState.FAILED.value
            job.failure_reason = f"max_attempts_exhausted after {job.attempts} attempts"
            job.lease_owner = None
            job.lease_expires_at = None
            permanently_failed += 1
        else:
            job.state = JobState.PENDING.value
            job.lease_owner = None
            job.lease_expires_at = None
            reclaimed += 1
            try:
                asyncio.get_event_loop().create_task(
                    get_event_bus().publish(
                        make_event(
                            "ScheduledJobRecovered",
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

    if abandoned:
        db.flush()

    return {"reclaimed": reclaimed, "permanently_failed": permanently_failed}
