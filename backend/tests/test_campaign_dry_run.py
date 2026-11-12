"""Tests: Dry Run Diff Output — executor preview() + orchestrator dry_run path.

RED → GREEN cycle:

DR1 — GuestInvitesExecutor.preview() returns changes dict
DR2 — UserConsentExecutor.preview() returns changes dict
DR3 — execute_campaign with dry_run=True records preview results without calling execute_fn
DR4 — dry_run task result_json is set to the preview output
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (  # noqa: F401
    CampaignStatus,
    CampaignTenantTask,
    RemediationCampaign,
    TaskStatus,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.tenant_identity_execute import (
    GuestInvitesExecutor,
    UserConsentExecutor,
)


# ── DR1 — GuestInvitesExecutor.preview() ────────────────────────────────────


@pytest.mark.asyncio
async def test_guest_invites_preview_returns_changes():
    executor = GuestInvitesExecutor()
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value={"allowInvitesFrom": "everyone"})
    result = await executor.preview(mock_client, {})
    assert "changes" in result
    assert isinstance(result["changes"], list)
    assert len(result["changes"]) > 0
    change = result["changes"][0]
    assert "field" in change or "action" in change
    # Should describe the desired allowInvitesFrom setting
    assert "allowInvitesFrom" in str(result)


# ── DR2 — UserConsentExecutor.preview() ─────────────────────────────────────


@pytest.mark.asyncio
async def test_user_consent_preview_returns_changes():
    executor = UserConsentExecutor()
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(
        return_value={
            "defaultUserRolePermissions": {
                "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
            }
        }
    )
    result = await executor.preview(mock_client, {})
    assert "changes" in result
    assert isinstance(result["changes"], list)
    assert len(result["changes"]) > 0
    # Should describe removing user consent grants
    assert "permissionGrantPoliciesAssigned" in str(result)


# ── DR3 — execute_campaign dry_run does NOT call execute_fn ────────────────


@pytest.mark.asyncio
async def test_dry_run_campaign_does_not_call_execute_fn(db_session):
    """When campaign.dry_run=True, the orchestrator should call preview, not execute_fn."""
    from app.services.remediation.fleet.campaign_service import (
        create_campaign_plan,
        approve_campaign,
    )
    from app.services.remediation.fleet.campaign_orchestrator import execute_campaign

    user_id = uuid.uuid4()
    db_session.add(UserTenantAccess(user_id=user_id, tenant_id="t1", role="ADMIN"))
    db_session.add(
        ComplianceResult(
            tenant_id="t1",
            control_id="IDENTITY_UNUSED_ACCOUNT",
            resource_id="user-1",
            resource_type="USER",
            passed=False,
            exposure_status=ExposureStatus.ACTIVE,
            evidence={"user_id": "user-1"},
        )
    )
    db_session.commit()

    campaign = create_campaign_plan(
        db_session,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=["IDENTITY_UNUSED_ACCOUNT"],
        target_tenant_ids=["t1"],
        dry_run=True,
    )
    campaign = approve_campaign(
        db_session,
        campaign_id=campaign.id,
        expected_plan_hash=campaign.plan_hash,
        approved_by="msp@example.com",
    )

    mock_execute_fn = AsyncMock()
    mock_acquire_lock = MagicMock()
    mock_release_lock = MagicMock()

    mock_tenant = SimpleNamespace(id="t1", organization=None)
    preview_result = {"changes": [{"action": "DISABLE_USER", "user_id": "user-1"}]}

    mock_executor = AsyncMock()
    mock_executor.preview = AsyncMock(return_value=preview_result)

    with (
        patch(
            "app.services.remediation.fleet.campaign_orchestrator.CONTROL_REGISTRY",
            {"IDENTITY_UNUSED_ACCOUNT": {"executor": mock_executor}},
        ),
        patch(
            "app.services.remediation.fleet.campaign_orchestrator.RemediationGraphClient",
            return_value=AsyncMock(),
        ),
    ):
        result = await execute_campaign(
            db=db_session,
            campaign_id=campaign.id,
            execute_fn=mock_execute_fn,
            tenant_resolver=lambda db, tid: mock_tenant,
            acquire_lock=mock_acquire_lock,
            release_lock=mock_release_lock,
        )

    mock_execute_fn.assert_not_called()
    assert result.status == CampaignStatus.COMPLETED.value


# ── DR4 — dry_run task gets preview result in result_json ───────────────────


@pytest.mark.asyncio
async def test_dry_run_task_result_json_set(db_session):
    """Each task's result_json should contain the preview output when dry_run=True."""
    from app.services.remediation.fleet.campaign_service import (
        create_campaign_plan,
        approve_campaign,
    )
    from app.services.remediation.fleet.campaign_orchestrator import execute_campaign

    user_id = uuid.uuid4()
    db_session.add(UserTenantAccess(user_id=user_id, tenant_id="t1", role="ADMIN"))
    db_session.add(
        ComplianceResult(
            tenant_id="t1",
            control_id="IDENTITY_UNUSED_ACCOUNT",
            resource_id="user-1",
            resource_type="USER",
            passed=False,
            exposure_status=ExposureStatus.ACTIVE,
            evidence={"user_id": "user-1"},
        )
    )
    db_session.commit()

    campaign = create_campaign_plan(
        db_session,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=["IDENTITY_UNUSED_ACCOUNT"],
        target_tenant_ids=["t1"],
        dry_run=True,
    )
    campaign = approve_campaign(
        db_session,
        campaign_id=campaign.id,
        expected_plan_hash=campaign.plan_hash,
        approved_by="msp@example.com",
    )

    preview_result = {"changes": [{"action": "DISABLE_USER", "user_id": "user-1"}]}
    mock_execute_fn = AsyncMock()
    mock_tenant = SimpleNamespace(id="t1", organization=None)
    mock_executor = AsyncMock()
    mock_executor.preview = AsyncMock(return_value=preview_result)

    with (
        patch(
            "app.services.remediation.fleet.campaign_orchestrator.CONTROL_REGISTRY",
            {"IDENTITY_UNUSED_ACCOUNT": {"executor": mock_executor}},
        ),
        patch(
            "app.services.remediation.fleet.campaign_orchestrator.RemediationGraphClient",
            return_value=AsyncMock(),
        ),
    ):
        await execute_campaign(
            db=db_session,
            campaign_id=campaign.id,
            execute_fn=mock_execute_fn,
            tenant_resolver=lambda db, tid: mock_tenant,
            acquire_lock=MagicMock(),
            release_lock=MagicMock(),
        )

    task = db_session.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).first()
    assert task.status == TaskStatus.EXECUTED.value
    assert task.result_json == preview_result
