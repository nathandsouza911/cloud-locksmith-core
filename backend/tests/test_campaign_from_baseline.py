"""Tests for create_campaign_plan_from_baseline — the fleet-wide baseline-apply entry point."""

import uuid

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.msp_security_baseline import BaselineConfig
from app.db.models.remediation_campaign import CampaignTenantTask
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_service import (
    CampaignTenantIsolationError,
    NoSafeBaselineControlsError,
    create_campaign_plan_from_baseline,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"
GUARDED_CONTROL = "IDENTITY_ADMIN_COUNT_EXCESS"  # not SAFE — no auto executor


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


def _active_baseline(db, organization_id, controls):
    db.add(
        BaselineConfig(
            organization_id=str(organization_id),
            baseline_name="Test Baseline",
            controls=controls,
            is_active=True,
        )
    )
    db.commit()


def _campaign_finding_ids(db, campaign) -> set[int]:
    return {
        t.compliance_result_id
        for t in db.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).all()
    }


def test_targets_whole_fleet_when_target_tenant_ids_omitted(db_session):
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    _active_baseline(db_session, org_id, [SAFE_CONTROL])
    _grant(db_session, user_id, "t1")
    _grant(db_session, user_id, "t2")
    f1 = _failing_finding(db_session, "t1")
    f2 = _failing_finding(db_session, "t2")
    db_session.commit()

    campaign = create_campaign_plan_from_baseline(
        db_session,
        organization_id=org_id,
        user_id=user_id,
        created_by="msp@example.com",
    )

    assert campaign.control_ids == [SAFE_CONTROL]
    assert _campaign_finding_ids(db_session, campaign) == {f1.id, f2.id}


def test_explicit_target_tenant_ids_still_enforces_fleet_isolation(db_session):
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    _active_baseline(db_session, org_id, [SAFE_CONTROL])
    _grant(db_session, user_id, "t1")
    db_session.commit()

    with pytest.raises(CampaignTenantIsolationError):
        create_campaign_plan_from_baseline(
            db_session,
            organization_id=org_id,
            user_id=user_id,
            created_by="msp@example.com",
            target_tenant_ids=["t1", "t-not-granted"],
        )


def test_explicit_target_tenant_ids_scopes_the_campaign(db_session):
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    _active_baseline(db_session, org_id, [SAFE_CONTROL])
    _grant(db_session, user_id, "t1")
    _grant(db_session, user_id, "t2")
    f1 = _failing_finding(db_session, "t1")
    _failing_finding(db_session, "t2")
    db_session.commit()

    campaign = create_campaign_plan_from_baseline(
        db_session,
        organization_id=org_id,
        user_id=user_id,
        created_by="msp@example.com",
        target_tenant_ids=["t1"],
    )

    assert _campaign_finding_ids(db_session, campaign) == {f1.id}


def test_non_safe_baseline_controls_are_excluded_not_attempted(db_session):
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    _active_baseline(db_session, org_id, [SAFE_CONTROL, GUARDED_CONTROL])
    _grant(db_session, user_id, "t1")
    db_session.commit()

    campaign = create_campaign_plan_from_baseline(
        db_session,
        organization_id=org_id,
        user_id=user_id,
        created_by="msp@example.com",
        target_tenant_ids=["t1"],
    )

    assert campaign.control_ids == [SAFE_CONTROL]
    assert GUARDED_CONTROL not in campaign.control_ids


def test_baseline_with_no_safe_controls_raises(db_session):
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    _active_baseline(db_session, org_id, [GUARDED_CONTROL])
    _grant(db_session, user_id, "t1")
    db_session.commit()

    with pytest.raises(NoSafeBaselineControlsError):
        create_campaign_plan_from_baseline(
            db_session,
            organization_id=org_id,
            user_id=user_id,
            created_by="msp@example.com",
            target_tenant_ids=["t1"],
        )
