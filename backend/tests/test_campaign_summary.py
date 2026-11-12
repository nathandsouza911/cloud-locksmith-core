"""Tests: Completion Summary Card — get_campaign_status exposes timing and rollback fields.

RED → GREEN cycle:

S1 — get_campaign_status includes started_at field
S2 — get_campaign_status includes completed_at field
S3 — get_campaign_status includes tenants_affected count
S4 — get_campaign_status includes tasks_executed and tasks_failed counts
S5 — rollback_available is True when at least one EXECUTED task has has_rollback
"""

import uuid
from datetime import datetime, timezone


from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (  # noqa: F401
    CampaignStatus,
    CampaignTenantTask,
    RemediationCampaign,
    TaskStatus,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_service import (
    create_campaign_plan,
    get_campaign_status,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _setup(db):
    user_id = uuid.uuid4()
    db.add(UserTenantAccess(user_id=user_id, tenant_id="t1", role="ADMIN"))
    db.add(
        ComplianceResult(
            tenant_id="t1",
            control_id=SAFE_CONTROL,
            resource_id="user-1",
            resource_type="USER",
            passed=False,
            exposure_status=ExposureStatus.ACTIVE,
        )
    )
    db.commit()
    campaign = create_campaign_plan(
        db,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1"],
    )
    return campaign


# ── S1/S2 — started_at / completed_at fields ────────────────────────────────


def test_status_includes_started_at(db_session):
    campaign = _setup(db_session)
    now = datetime.now(timezone.utc)
    # Manually set started_at to simulate execution start
    db_campaign = db_session.query(RemediationCampaign).filter(RemediationCampaign.id == campaign.id).one()
    db_campaign.started_at = now
    db_session.commit()

    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert "started_at" in result
    assert result["started_at"] is not None


def test_status_includes_completed_at(db_session):
    campaign = _setup(db_session)
    now = datetime.now(timezone.utc)
    db_campaign = db_session.query(RemediationCampaign).filter(RemediationCampaign.id == campaign.id).one()
    db_campaign.completed_at = now
    db_session.commit()

    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert "completed_at" in result
    assert result["completed_at"] is not None


# ── S3 — tenants_affected ────────────────────────────────────────────────────


def test_status_includes_tenants_affected(db_session):
    campaign = _setup(db_session)
    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert "tenants_affected" in result
    assert result["tenants_affected"] == 1


# ── S4 — tasks_executed / tasks_failed ───────────────────────────────────────


def test_status_includes_tasks_executed_and_failed(db_session):
    campaign = _setup(db_session)
    # Manually set task statuses to simulate a completed campaign
    task = db_session.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).first()
    task.status = TaskStatus.EXECUTED.value
    db_session.commit()

    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert "tasks_executed" in result
    assert "tasks_failed" in result
    assert result["tasks_executed"] == 1
    assert result["tasks_failed"] == 0


# ── S5 — rollback_available ───────────────────────────────────────────────────


def test_status_rollback_available_true_when_executed_with_rollback(db_session):
    campaign = _setup(db_session)
    task = db_session.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).first()
    task.status = TaskStatus.EXECUTED.value
    db_session.commit()

    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert "rollback_available" in result
    # IDENTITY_UNUSED_ACCOUNT has has_rollback=True
    assert result["rollback_available"] is True


def test_status_rollback_available_false_when_no_executed_tasks(db_session):
    campaign = _setup(db_session)
    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert result["rollback_available"] is False
