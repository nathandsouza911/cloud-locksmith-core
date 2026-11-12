"""Phase 2 TDD — Audit Trail Visibility.

Tests: AU-E1 (audit_log_id populated), AU-A1 through AU-A3 (API endpoint).
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (
    CampaignTenantTask,
    TaskStatus,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_service import (
    approve_campaign,
    create_campaign_plan,
)
from app.api.v1.fleet_campaigns import (
    CreateCampaignBody,
    create_campaign_endpoint,
    get_campaign_audit_endpoint,
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


# ---------------------------------------------------------------------------
# AU-E1 — audit_log_id populated after task execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_log_id_populated_after_execution(db_session):
    """AU-E1: CampaignTenantTask.audit_log_id is set after successful execution."""
    from app.services.remediation.fleet.campaign_orchestrator import execute_campaign
    from app.db.models.remediation_audit import RemediationAuditLog

    user = _user()
    _seed(db_session, user)

    # Build and approve campaign
    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1"],
    )
    plan_hash = campaign.plan_hash
    approve_campaign(
        db_session,
        campaign_id=campaign.id,
        approved_by=user.email,
        expected_plan_hash=plan_hash,
    )

    # Write a RemediationAuditLog entry for the finding so execute_fn can link to it
    finding = db_session.query(ComplianceResult).filter(ComplianceResult.tenant_id == "t1").first()
    audit_entry = RemediationAuditLog(
        tenant_id="t1",
        compliance_result_id=finding.id,
        control_id=SAFE_CONTROL,
        resource_type="USER",
        resource_id="user-1",
        decision="EXECUTED",
        confidence=1.0,
        explanation_summary="Executed by campaign",
        explanation_factors={},
        explanation_risk_note="",
        execution_status="EXECUTED",
    )
    db_session.add(audit_entry)
    db_session.commit()
    db_session.refresh(audit_entry)

    # Mock execute_fn so task succeeds
    mock_execute = AsyncMock(return_value={"status": "success"})

    fake_tenant = MagicMock()
    fake_tenant.id = "t1"

    await execute_campaign(
        db=db_session,
        campaign_id=campaign.id,
        execute_fn=mock_execute,
        tenant_resolver=lambda db, tid: fake_tenant,
        acquire_lock=lambda **kw: None,
        release_lock=lambda **kw: None,
    )

    task = db_session.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).first()
    assert task.status == TaskStatus.EXECUTED.value
    assert task.audit_log_id is not None


# ---------------------------------------------------------------------------
# AU-A1 — audit endpoint returns entries for campaign tasks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_endpoint_returns_entries(db_session):
    """AU-A1: GET /fleet/campaigns/{id}/audit returns audit entries for tasks."""
    user = _user()
    _seed(db_session, user)

    body = CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=user)
    campaign_id = created["campaign_id"]

    result = await get_campaign_audit_endpoint(campaign_id=campaign_id, db=db_session, current_user=user)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# AU-A2 — audit endpoint enforces organization isolation (404 for cross-org)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_endpoint_cross_org_returns_404(db_session):
    """AU-A2: Cross-org user cannot access audit trail (ownership enforced as 404)."""
    owner = _user()
    _seed(db_session, owner)

    body = CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=owner)
    campaign_id = created["campaign_id"]

    attacker = _user()
    with pytest.raises(HTTPException) as exc:
        await get_campaign_audit_endpoint(campaign_id=campaign_id, db=db_session, current_user=attacker)
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# AU-A3 — audit endpoint returns 404 for nonexistent campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_endpoint_nonexistent_campaign_returns_404(db_session):
    """AU-A3: Audit endpoint returns 404 for a campaign that doesn't exist."""
    user = _user()
    with pytest.raises(HTTPException) as exc:
        await get_campaign_audit_endpoint(campaign_id=str(uuid.uuid4()), db=db_session, current_user=user)
    assert exc.value.status_code == 404
