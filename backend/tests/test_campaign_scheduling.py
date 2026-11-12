"""Phase 4 TDD — Campaign Scheduling.

Tests: SC-1 (schedule approved campaign), SC-2 (cannot schedule unapproved),
SC-3 (cancel schedule), SC-4 (scheduler picks up due campaigns),
SC-5 (scheduled_at visible in status), SC-6 (execution re-verifies all gates).

CRITICAL: scheduled execution must still verify plan hash, SAFE controls,
tenant access, and approval snapshot — no gate can be bypassed.
"""

import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_service import (
    approve_campaign,
    create_campaign_plan,
    get_campaign_status,
)
from app.utils.datetime import utc_now
from app.api.v1.fleet_campaigns import (
    ScheduleBody,
    schedule_campaign_endpoint,
    cancel_schedule_endpoint,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _user(org_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=org_id or uuid.uuid4(),
    )


def _seed(db, user, tenant_ids=("t1",)):
    for t in tenant_ids:
        db.add(UserTenantAccess(user_id=user.id, tenant_id=t, role="ADMIN"))
        db.add(
            ComplianceResult(
                tenant_id=t,
                control_id=SAFE_CONTROL,
                resource_id="user-1",
                resource_type="USER",
                passed=False,
                exposure_status=ExposureStatus.ACTIVE,
            )
        )
    db.commit()


def _build_approved_campaign(db, user):
    campaign = create_campaign_plan(
        db,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1"],
    )
    approve_campaign(
        db,
        campaign_id=campaign.id,
        approved_by=user.email,
        expected_plan_hash=campaign.plan_hash,
    )
    db.refresh(campaign)
    return campaign


# ---------------------------------------------------------------------------
# SC-1: Schedule an approved campaign sets scheduled_at
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_schedule_approved_campaign(db_session):
    """SC-1: Scheduling an approved campaign sets scheduled_at on the campaign."""
    user = _user()
    _seed(db_session, user)
    campaign = _build_approved_campaign(db_session, user)

    future = (utc_now() + timedelta(hours=2)).isoformat()
    result = await schedule_campaign_endpoint(
        campaign_id=str(campaign.id),
        body=ScheduleBody(scheduled_at=future),
        db=db_session,
        current_user=user,
    )
    assert result["scheduled_at"] is not None


# ---------------------------------------------------------------------------
# SC-2: Cannot schedule an unapproved campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cannot_schedule_unapproved_campaign(db_session):
    """SC-2: Scheduling fails if campaign has no approved_plan_hash."""
    user = _user()
    _seed(db_session, user)
    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1"],
    )

    future = (utc_now() + timedelta(hours=1)).isoformat()
    with pytest.raises(HTTPException) as exc:
        await schedule_campaign_endpoint(
            campaign_id=str(campaign.id),
            body=ScheduleBody(scheduled_at=future),
            db=db_session,
            current_user=user,
        )
    assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# SC-3: Cancel schedule clears scheduled_at
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_schedule_clears_scheduled_at(db_session):
    """SC-3: Canceling a schedule clears scheduled_at — campaign remains AWAITING_APPROVAL."""
    user = _user()
    _seed(db_session, user)
    campaign = _build_approved_campaign(db_session, user)

    future = (utc_now() + timedelta(hours=2)).isoformat()
    await schedule_campaign_endpoint(
        campaign_id=str(campaign.id),
        body=ScheduleBody(scheduled_at=future),
        db=db_session,
        current_user=user,
    )

    result = await cancel_schedule_endpoint(campaign_id=str(campaign.id), db=db_session, current_user=user)
    assert result["scheduled_at"] is None
    assert result["status"] == "AWAITING_APPROVAL"


# ---------------------------------------------------------------------------
# SC-4: Scheduler picks up due campaigns
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scheduler_picks_up_due_campaigns(db_session):
    """SC-4: run_campaign_scheduler executes campaigns whose scheduled_at has passed."""
    from app.jobs.campaign_scheduler import run_campaign_scheduler

    user = _user()
    _seed(db_session, user)
    campaign = _build_approved_campaign(db_session, user)

    # Set scheduled_at in the past so it's due now. The scheduler works from durable
    # campaign_scheduled_jobs rows, so create the job the schedule endpoint would create.
    from app.jobs.campaign_job_manager import create_job

    campaign.scheduled_at = utc_now() - timedelta(minutes=1)
    db_session.commit()
    create_job(db_session, campaign.id, campaign.organization_id, campaign.scheduled_at)
    db_session.commit()
    campaign_id = str(campaign.id)  # the scheduler closes the session, detaching `campaign`

    mock_execute = AsyncMock()
    with (
        patch("app.jobs.campaign_scheduler.execute_campaign", mock_execute),
        patch("app.jobs.campaign_scheduler.SyncSessionLocal", return_value=db_session),
    ):
        await run_campaign_scheduler()

    mock_execute.assert_called_once()
    call_kwargs = mock_execute.call_args.kwargs
    assert str(call_kwargs["campaign_id"]) == campaign_id


# ---------------------------------------------------------------------------
# SC-5: scheduled_at appears in campaign status response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scheduled_at_in_status_response(db_session):
    """SC-5: get_campaign_status includes scheduled_at field."""
    user = _user()
    _seed(db_session, user)
    campaign = _build_approved_campaign(db_session, user)

    future = (utc_now() + timedelta(hours=1)).isoformat()
    await schedule_campaign_endpoint(
        campaign_id=str(campaign.id),
        body=ScheduleBody(scheduled_at=future),
        db=db_session,
        current_user=user,
    )

    status = get_campaign_status(db_session, campaign_id=campaign.id)
    assert "scheduled_at" in status
    assert status["scheduled_at"] is not None
