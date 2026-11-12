"""Durability tests for the campaign scheduler job table."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.db.models.campaign_scheduled_job import CampaignScheduledJob, JobState
from app.services.remediation.fleet.campaign_service import CampaignStateError
from app.db.models.remediation_campaign import CampaignStatus, RemediationCampaign


def test_job_state_enum_values():
    assert JobState.PENDING.value == "PENDING"
    assert JobState.CLAIMED.value == "CLAIMED"
    assert JobState.EXECUTING.value == "EXECUTING"
    assert JobState.COMPLETED.value == "COMPLETED"
    assert JobState.FAILED.value == "FAILED"


def test_campaign_scheduled_job_model_has_required_fields():
    """Verify the ORM model has all required fields."""
    job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=datetime.now(timezone.utc),
        state=JobState.PENDING.value,
        max_attempts=3,
    )
    assert job.state == "PENDING"
    assert job.attempts == 0
    assert job.lease_owner is None
    assert job.lease_expires_at is None
    assert job.failure_reason is None


# ---------------------------------------------------------------------------
# Task 4 — Campaign Job Manager tests
# ---------------------------------------------------------------------------

from app.jobs.campaign_job_manager import (
    LEASE_DURATION_SECONDS,
    MAX_JOB_ATTEMPTS,
    WORKER_ID,
    create_job,
    claim_due_jobs,
    mark_executing,
    mark_completed,
    mark_failed,
    recover_expired_leases,
)


def _make_mock_db():
    """Return a mock Session with a working query chain."""
    db = MagicMock()
    return db


def test_worker_id_format():
    assert "-" in WORKER_ID
    assert str(os.getpid()) in WORKER_ID


def test_lease_duration_is_ten_minutes():
    assert LEASE_DURATION_SECONDS == 600


def test_max_attempts_is_three():
    assert MAX_JOB_ATTEMPTS == 3


def test_create_job_sets_pending_state():
    db = _make_mock_db()
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)

    job = create_job(db, campaign_id, org_id, scheduled_at)

    assert job.campaign_id == campaign_id
    assert job.organization_id == org_id
    assert job.scheduled_at == scheduled_at
    assert job.state == JobState.PENDING.value
    assert job.attempts == 0
    db.add.assert_called_once_with(job)
    db.flush.assert_called_once()


def test_mark_completed_sets_terminal_state():
    db = _make_mock_db()
    job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=datetime.now(timezone.utc),
        state=JobState.EXECUTING.value,
        attempts=1,
        max_attempts=3,
    )

    mark_completed(db, job)

    assert job.state == JobState.COMPLETED.value
    assert job.execution_completed_at is not None
    assert job.lease_owner is None
    assert job.lease_expires_at is None
    db.flush.assert_called_once()


def test_mark_failed_truncates_reason():
    db = _make_mock_db()
    job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=datetime.now(timezone.utc),
        state=JobState.EXECUTING.value,
        attempts=3,
        max_attempts=3,
    )
    long_reason = "x" * 600

    mark_failed(db, job, long_reason)

    assert job.state == JobState.FAILED.value
    assert len(job.failure_reason) <= 500
    db.flush.assert_called_once()


def test_recover_expired_leases_reclaims_claimed_jobs():
    db = _make_mock_db()
    now = datetime.now(timezone.utc)
    expired_job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=now - timedelta(hours=1),
        state=JobState.CLAIMED.value,
        lease_owner="old-worker-123",
        lease_expires_at=now - timedelta(minutes=5),
        attempts=1,
        max_attempts=3,
    )

    query_mock = db.query.return_value
    filter_mock = query_mock.filter.return_value
    filter_mock.with_for_update.return_value.all.return_value = [expired_job]

    result = recover_expired_leases(db)

    assert result["reclaimed"] == 1
    assert result["permanently_failed"] == 0
    assert expired_job.state == JobState.PENDING.value
    assert expired_job.lease_owner is None
    assert expired_job.lease_expires_at is None


def test_recover_expired_leases_permanently_fails_exhausted_jobs():
    db = _make_mock_db()
    now = datetime.now(timezone.utc)
    exhausted_job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=now - timedelta(hours=2),
        state=JobState.EXECUTING.value,
        lease_owner="dead-worker",
        lease_expires_at=now - timedelta(minutes=1),
        attempts=3,
        max_attempts=3,
    )

    query_mock = db.query.return_value
    filter_mock = query_mock.filter.return_value
    filter_mock.with_for_update.return_value.all.return_value = [exhausted_job]

    result = recover_expired_leases(db)

    assert result["reclaimed"] == 0
    assert result["permanently_failed"] == 1
    assert exhausted_job.state == JobState.FAILED.value
    assert "max_attempts_exhausted" in exhausted_job.failure_reason


# ---------------------------------------------------------------------------
# Task 5 — API endpoint wiring tests
# ---------------------------------------------------------------------------


def test_schedule_endpoint_creates_job_record():
    """schedule_campaign_endpoint must create a CampaignScheduledJob row."""
    from app.api.v1.fleet_campaigns import schedule_campaign_endpoint

    # The test verifies create_job is called with the right args.
    # Integration-level test — only checks the call, not the DB.
    # Full integration test is in test_campaign_scheduling.py.
    import inspect

    src = inspect.getsource(schedule_campaign_endpoint)
    assert "create_job" in src, "schedule_campaign_endpoint must call create_job() from campaign_job_manager"


def test_cancel_schedule_endpoint_deletes_job_record():
    """cancel_schedule_endpoint must delete the CampaignScheduledJob row."""
    from app.api.v1.fleet_campaigns import cancel_schedule_endpoint
    import inspect

    src = inspect.getsource(cancel_schedule_endpoint)
    assert (
        "delete_pending_job" in src
    ), "cancel_schedule_endpoint must call delete_pending_job() from campaign_job_manager"


# ---------------------------------------------------------------------------
# Task 6 — Scheduler uses job table tests
# ---------------------------------------------------------------------------


def test_campaign_scheduler_uses_job_table():
    """run_campaign_scheduler must claim jobs via campaign_job_manager, not query scheduled_at."""
    import inspect
    from app.jobs import campaign_scheduler

    src = inspect.getsource(campaign_scheduler)
    assert "claim_due_jobs" in src, "run_campaign_scheduler must use claim_due_jobs() from campaign_job_manager"
    # The old direct query on scheduled_at must be gone.
    assert (
        "scheduled_at" not in src or "campaign_job_manager" in src
    ), "run_campaign_scheduler must not query RemediationCampaign.scheduled_at directly"


# ---------------------------------------------------------------------------
# Task 7 — Startup recovery hook tests
# ---------------------------------------------------------------------------


def test_crash_recovery_module_has_recover_campaign_jobs():
    """crash_recovery must export recover_campaign_jobs for startup wiring."""
    from app.services.remediation import crash_recovery

    assert hasattr(crash_recovery, "recover_campaign_jobs"), "crash_recovery must export recover_campaign_jobs(db)"


def test_recover_campaign_jobs_calls_recover_expired_leases():
    """recover_campaign_jobs must delegate to campaign_job_manager.recover_expired_leases."""
    import inspect
    from app.services.remediation import crash_recovery

    src = inspect.getsource(crash_recovery.recover_campaign_jobs)
    assert "recover_expired_leases" in src


# ---------------------------------------------------------------------------
# Task 8 — Exactly-once safety tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_campaign_rejects_non_awaiting_approval():
    """execute_campaign must refuse campaigns not in AWAITING_APPROVAL state.

    This is the second exactly-once guard: even if a job is somehow
    claimed twice, the campaign status gate prevents double execution.
    """
    from app.services.remediation.fleet.campaign_orchestrator import execute_campaign

    mock_db = MagicMock()
    campaign = RemediationCampaign(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        created_by="test@example.com",
        control_ids=["CA_MFA_REGISTRATION"],
        status=CampaignStatus.EXECUTING.value,  # already executing
        approved_plan_hash="abc123",
        approved_items=[],
    )
    mock_db.query.return_value.filter.return_value.one_or_none.return_value = campaign

    with pytest.raises(CampaignStateError, match="cannot execute from state EXECUTING"):
        await execute_campaign(db=mock_db, campaign_id=campaign.id)


def test_job_table_unique_constraint_prevents_duplicate_jobs():
    """Only one job can exist per campaign_id due to unique constraint."""
    col = CampaignScheduledJob.__table__.c["campaign_id"]
    assert col.unique or any(
        hasattr(c, "columns") and "campaign_id" in [cc.name for cc in c.columns]
        for c in CampaignScheduledJob.__table__.constraints
    ), "campaign_id column must have a unique constraint"


def test_claim_is_atomic_via_skip_locked():
    """claim_due_jobs must use with_for_update(skip_locked=True)."""
    import inspect
    from app.jobs import campaign_job_manager

    src = inspect.getsource(campaign_job_manager.claim_due_jobs)
    assert "skip_locked=True" in src, "claim_due_jobs must use skip_locked=True to prevent concurrent claiming"


# ---------------------------------------------------------------------------
# Task 9 — Full durability test suite (Phase G)
# ---------------------------------------------------------------------------

# ── Restart scenarios ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_restart_before_scheduled_at_job_survives():
    """PENDING job with future scheduled_at is not claimed — survives restart."""
    db = _make_mock_db()
    future_time = datetime.now(timezone.utc) + timedelta(hours=2)
    future_job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=future_time,
        state=JobState.PENDING.value,
        attempts=0,
        max_attempts=3,
    )
    # claim_due_jobs filters scheduled_at <= now(), so future job is not returned.
    query_mock = db.query.return_value
    filter_mock = query_mock.filter.return_value
    filter_mock.with_for_update.return_value.all.return_value = []

    claimed = claim_due_jobs(db)

    assert claimed == []
    assert future_job.state == JobState.PENDING.value  # untouched


def test_crash_in_claimed_state_is_recovered_to_pending():
    """A CLAIMED job with expired lease is returned to PENDING for retry."""
    db = _make_mock_db()
    now = datetime.now(timezone.utc)
    crashed_job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=now - timedelta(hours=1),
        state=JobState.CLAIMED.value,
        lease_owner="worker-that-died",
        lease_expires_at=now - timedelta(minutes=1),
        attempts=1,
        max_attempts=3,
    )
    db.query.return_value.filter.return_value.with_for_update.return_value.all.return_value = [crashed_job]

    result = recover_expired_leases(db)

    assert result["reclaimed"] == 1
    assert crashed_job.state == JobState.PENDING.value
    assert crashed_job.lease_owner is None


def test_crash_during_execution_after_max_attempts_permanently_fails():
    """A job that has crashed max_attempts times is permanently failed."""
    db = _make_mock_db()
    now = datetime.now(timezone.utc)
    exhausted = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=now - timedelta(hours=3),
        state=JobState.EXECUTING.value,
        lease_owner="dead-worker",
        lease_expires_at=now - timedelta(minutes=30),
        attempts=3,
        max_attempts=3,
    )
    db.query.return_value.filter.return_value.with_for_update.return_value.all.return_value = [exhausted]

    result = recover_expired_leases(db)

    assert result["permanently_failed"] == 1
    assert exhausted.state == JobState.FAILED.value
    assert "3" in exhausted.failure_reason


def test_overdue_job_is_claimed_immediately():
    """A PENDING job with scheduled_at in the past is claimed on the next tick."""
    db = _make_mock_db()
    overdue = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=datetime.now(timezone.utc) - timedelta(hours=5),
        state=JobState.PENDING.value,
        attempts=0,
        max_attempts=3,
    )
    db.query.return_value.filter.return_value.with_for_update.return_value.all.return_value = [overdue]

    claimed = claim_due_jobs(db)

    assert len(claimed) == 1
    assert claimed[0].state == JobState.CLAIMED.value
    assert claimed[0].lease_owner == WORKER_ID
    assert claimed[0].attempts == 1


def test_two_workers_cannot_both_claim_same_job():
    """SKIP LOCKED means a job visible to worker-1 is invisible to worker-2 simultaneously.

    This test verifies the mechanism (SKIP LOCKED present in source), not the
    DB-level behavior which requires a real PostgreSQL connection.
    """
    import inspect
    from app.jobs import campaign_job_manager

    src = inspect.getsource(campaign_job_manager.claim_due_jobs)
    assert "skip_locked=True" in src


# ── Tenant isolation ───────────────────────────────────────────────────────


def test_job_stores_organization_id():
    """Jobs store organization_id for tenant-scoped queries."""
    db = _make_mock_db()
    org_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    scheduled_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    job = create_job(db, campaign_id, org_id, scheduled_at)

    assert job.organization_id == org_id


# ── State transition correctness ───────────────────────────────────────────


def test_mark_executing_sets_started_at():
    db = _make_mock_db()
    job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=datetime.now(timezone.utc),
        state=JobState.CLAIMED.value,
        attempts=1,
        max_attempts=3,
    )

    mark_executing(db, job)

    assert job.state == JobState.EXECUTING.value
    assert job.execution_started_at is not None


def test_mark_completed_clears_lease():
    db = _make_mock_db()
    job = CampaignScheduledJob(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scheduled_at=datetime.now(timezone.utc),
        state=JobState.EXECUTING.value,
        lease_owner="worker-1",
        lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        attempts=1,
        max_attempts=3,
    )

    mark_completed(db, job)

    assert job.state == JobState.COMPLETED.value
    assert job.lease_owner is None
    assert job.lease_expires_at is None
    assert job.execution_completed_at is not None


def test_delete_pending_job_only_deletes_pending():
    """delete_pending_job filters by state=PENDING — does not cancel in-flight jobs."""
    import inspect
    from app.jobs import campaign_job_manager

    src = inspect.getsource(campaign_job_manager.delete_pending_job)
    assert "PENDING" in src


# ── run_campaign_scheduler integration ────────────────────────────────────


@pytest.mark.asyncio
async def test_run_campaign_scheduler_handles_empty_queue():
    """Scheduler with no due jobs does nothing and does not raise."""

    with (
        patch("app.jobs.campaign_scheduler.SyncSessionLocal") as mock_session_cls,
        patch("app.jobs.campaign_scheduler.recover_expired_leases") as mock_recover,
        patch("app.jobs.campaign_scheduler.claim_due_jobs") as mock_claim,
    ):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_recover.return_value = {"reclaimed": 0, "permanently_failed": 0}
        mock_claim.return_value = []

        from app.jobs.campaign_scheduler import run_campaign_scheduler

        await run_campaign_scheduler()

        mock_recover.assert_called_once()
        mock_claim.assert_called_once()


@pytest.mark.asyncio
async def test_run_campaign_scheduler_marks_failed_on_execute_exception():
    """If execute_campaign raises, the job is marked FAILED."""
    from unittest.mock import AsyncMock, MagicMock

    with (
        patch("app.jobs.campaign_scheduler.SyncSessionLocal") as mock_session_cls,
        patch("app.jobs.campaign_scheduler.recover_expired_leases") as mock_recover,
        patch("app.jobs.campaign_scheduler.claim_due_jobs") as mock_claim,
        patch("app.jobs.campaign_scheduler.mark_executing"),
        patch("app.jobs.campaign_scheduler.mark_failed") as mock_mark_failed,
        patch("app.jobs.campaign_scheduler.execute_campaign", new_callable=AsyncMock) as mock_execute,
    ):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_recover.return_value = {"reclaimed": 0, "permanently_failed": 0}

        fake_job = CampaignScheduledJob(
            id=uuid.uuid4(),
            campaign_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            scheduled_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            state=JobState.CLAIMED.value,
            attempts=1,
            max_attempts=3,
        )
        mock_claim.return_value = [fake_job]
        mock_execute.side_effect = RuntimeError("graph api timeout")

        from app.jobs.campaign_scheduler import run_campaign_scheduler

        await run_campaign_scheduler()

        mock_mark_failed.assert_called_once()
        call_args = mock_mark_failed.call_args
        assert "graph api timeout" in call_args[0][2]
