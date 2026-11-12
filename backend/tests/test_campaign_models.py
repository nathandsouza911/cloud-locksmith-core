"""Persistence tests for the bulk-remediation campaign models."""

import uuid

from app.db.models.remediation_campaign import (
    CampaignStatus,
    CampaignTenantTask,
    RemediationCampaign,
    TaskStatus,
)


def test_campaign_persists_with_tasks(db_session):
    campaign = RemediationCampaign(
        organization_id=uuid.uuid4(),
        created_by="msp-admin@example.com",
        control_ids=["IDENTITY_UNUSED_ACCOUNT"],
        status=CampaignStatus.PLAN.value,
    )
    db_session.add(campaign)
    db_session.flush()

    task = CampaignTenantTask(
        campaign_id=campaign.id,
        tenant_id="tenant-1",
        compliance_result_id=10,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        status=TaskStatus.PLANNED.value,
    )
    db_session.add(task)
    db_session.commit()

    loaded = db_session.query(RemediationCampaign).filter_by(id=campaign.id).one()
    assert loaded.status == CampaignStatus.PLAN.value
    assert loaded.control_ids == ["IDENTITY_UNUSED_ACCOUNT"]

    tasks = db_session.query(CampaignTenantTask).filter_by(campaign_id=campaign.id).all()
    assert len(tasks) == 1
    assert tasks[0].tenant_id == "tenant-1"
    assert tasks[0].status == TaskStatus.PLANNED.value


def test_campaign_defaults(db_session):
    campaign = RemediationCampaign(
        organization_id=uuid.uuid4(),
        created_by="msp-admin@example.com",
        control_ids=["IDENTITY_UNUSED_ACCOUNT"],
    )
    db_session.add(campaign)
    db_session.commit()

    assert campaign.status == CampaignStatus.PLAN.value
    assert campaign.dry_run is False
    assert campaign.approved_plan_hash is None
