"""Service-level tests: plan generation, tenant isolation, and approval binding."""

import uuid

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.models.remediation_campaign import CampaignStatus
from app.services.remediation.fleet.campaign_plan import (
    CampaignScopeError,
    UnsafeControlError,
)
from app.services.remediation.fleet.campaign_service import (
    CampaignTenantIsolationError,
    approve_campaign,
    create_campaign_plan,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"
GUARDED_CONTROL = "IDENTITY_ADMIN_COUNT_EXCESS"  # still GUARDED — no auto executor


def _grant(db, user_id, tenant_id):
    db.add(UserTenantAccess(user_id=user_id, tenant_id=tenant_id, role="ADMIN"))


def _failing_finding(db, tenant_id, control_id=SAFE_CONTROL, resource_id="user-1"):
    cr = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_id=resource_id,
        resource_type="USER",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE,
    )
    db.add(cr)
    db.flush()
    return cr


def _seed(db, user_id):
    _grant(db, user_id, "t1")
    _grant(db, user_id, "t2")
    f1 = _failing_finding(db, "t1")
    f2 = _failing_finding(db, "t2")
    db.commit()
    return f1, f2


def test_create_plan_builds_tasks_for_failing_findings(db_session):
    user_id = uuid.uuid4()
    f1, f2 = _seed(db_session, user_id)

    campaign = create_campaign_plan(
        db_session,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    assert campaign.status == CampaignStatus.AWAITING_APPROVAL.value
    assert campaign.plan_hash is not None
    finding_ids = {t.compliance_result_id for t in campaign_tasks(db_session, campaign)}
    assert finding_ids == {f1.id, f2.id}


def test_create_plan_rejects_non_safe_control(db_session):
    user_id = uuid.uuid4()
    _seed(db_session, user_id)
    with pytest.raises(UnsafeControlError):
        create_campaign_plan(
            db_session,
            organization_id=uuid.uuid4(),
            user_id=user_id,
            created_by="msp@example.com",
            control_ids=[SAFE_CONTROL, GUARDED_CONTROL],
            target_tenant_ids=["t1"],
        )


def test_create_plan_rejects_tenant_outside_fleet(db_session):
    user_id = uuid.uuid4()
    _seed(db_session, user_id)
    # "t3" is never granted to this user.
    with pytest.raises(CampaignTenantIsolationError):
        create_campaign_plan(
            db_session,
            organization_id=uuid.uuid4(),
            user_id=user_id,
            created_by="msp@example.com",
            control_ids=[SAFE_CONTROL],
            target_tenant_ids=["t1", "t3"],
        )


def test_approve_with_correct_hash_binds_plan(db_session):
    user_id = uuid.uuid4()
    _seed(db_session, user_id)
    campaign = create_campaign_plan(
        db_session,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    approved = approve_campaign(
        db_session,
        campaign_id=campaign.id,
        approved_by="boss@example.com",
        expected_plan_hash=campaign.plan_hash,
    )

    assert approved.approved_plan_hash == campaign.plan_hash
    assert approved.approved_by == "boss@example.com"
    assert approved.approved_at is not None
    assert len(approved.approved_items) == 2


def test_approve_with_stale_hash_is_rejected(db_session):
    user_id = uuid.uuid4()
    _seed(db_session, user_id)
    campaign = create_campaign_plan(
        db_session,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    with pytest.raises(CampaignScopeError):
        approve_campaign(
            db_session,
            campaign_id=campaign.id,
            approved_by="boss@example.com",
            expected_plan_hash="deadbeef",  # not the plan the operator reviewed
        )


# helper imported lazily to keep the failing import at the top meaningful
def campaign_tasks(db, campaign):
    from app.db.models.remediation_campaign import CampaignTenantTask

    return db.query(CampaignTenantTask).filter_by(campaign_id=campaign.id).all()
