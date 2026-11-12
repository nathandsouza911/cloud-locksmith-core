"""Tests: IDENTITY_USER_CONSENT_POLICY promoted to SAFE and usable in campaigns.

RED → GREEN cycle:

U1 — is_safe_control returns True for IDENTITY_USER_CONSENT_POLICY
U2 — assert_controls_safe passes for IDENTITY_USER_CONSENT_POLICY
U3 — create_campaign_plan accepts IDENTITY_USER_CONSENT_POLICY control
U4 — campaign orchestrator rollback dispatches to user_consent rollback
U5 — rollback_user_consent restores prior snapshot from RemediationSnapshot
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (  # noqa: F401 — ensures table registered with Base.metadata
    CampaignStatus,
    RemediationCampaign,
    CampaignTenantTask,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_plan import (
    assert_controls_safe,
    is_safe_control,
)
from app.services.remediation.fleet.campaign_service import create_campaign_plan

USER_CONSENT_CONTROL = "IDENTITY_USER_CONSENT_POLICY"
SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


# ── U1 — is_safe_control ─────────────────────────────────────────────────────


def test_user_consent_is_safe_control():
    assert is_safe_control(USER_CONSENT_CONTROL) is True


# ── U2 — assert_controls_safe ────────────────────────────────────────────────


def test_assert_controls_safe_passes_for_user_consent():
    assert_controls_safe([USER_CONSENT_CONTROL])


def test_assert_controls_safe_passes_mixed_with_user_consent():
    assert_controls_safe([SAFE_CONTROL, USER_CONSENT_CONTROL])


# ── U3 — create_campaign_plan accepts the control ────────────────────────────


def test_create_campaign_plan_accepts_user_consent(db_session):
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    db_session.add(UserTenantAccess(user_id=user_id, tenant_id="t1", role="ADMIN"))
    db_session.add(
        ComplianceResult(
            tenant_id="t1",
            control_id=USER_CONSENT_CONTROL,
            resource_id="t1",
            resource_type="TENANT",
            passed=False,
            exposure_status=ExposureStatus.ACTIVE,
        )
    )
    db_session.commit()

    campaign = create_campaign_plan(
        db_session,
        organization_id=org_id,
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[USER_CONSENT_CONTROL],
        target_tenant_ids=["t1"],
    )
    assert campaign.status == CampaignStatus.AWAITING_APPROVAL.value
    tasks = db_session.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).all()
    assert len(tasks) == 1
    assert tasks[0].control_id == USER_CONSENT_CONTROL


# ── U4 — orchestrator rollback dispatches to user_consent rollback ───────────


@pytest.mark.asyncio
async def test_rollback_dispatches_user_consent():
    """_default_rollback_fn should call rollback_user_consent for IDENTITY_USER_CONSENT_POLICY."""
    from app.services.remediation.fleet.campaign_orchestrator import _default_rollback_fn

    with patch(
        "app.services.remediation.rollback.tenant_identity_rollback_executor.rollback_user_consent"
    ) as mock_rollback:
        mock_rollback.return_value = None
        _default_rollback_fn(
            db=MagicMock(),
            compliance_result_id=42,
            tenant=MagicMock(),
            control_id=USER_CONSENT_CONTROL,
        )
        mock_rollback.assert_called_once()


# ── U5 — rollback_user_consent reads snapshot and calls executor ─────────────


@pytest.mark.asyncio
async def test_rollback_user_consent_uses_snapshot(db_session):
    """rollback_user_consent should read RemediationSnapshot.state and call executor.rollback."""
    from app.db.models.remediation_snapshot import RemediationSnapshot
    from app.services.remediation.rollback.tenant_identity_rollback_executor import (
        rollback_user_consent,
    )

    finding = ComplianceResult(
        tenant_id="t1",
        control_id=USER_CONSENT_CONTROL,
        resource_id="t1",
        resource_type="TENANT",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE,
    )
    db_session.add(finding)
    db_session.flush()

    prior_snapshot = {
        "authorization_policy": {
            "defaultUserRolePermissions": {
                "permissionGrantPoliciesAssigned": ["managePermissionGrantsForSelf.microsoft-user-default-legacy"],
            },
        },
    }
    snap = RemediationSnapshot(
        compliance_result_id=finding.id,
        state=prior_snapshot,
    )
    db_session.add(snap)
    db_session.commit()

    mock_adapter = AsyncMock()
    mock_adapter.patch = AsyncMock()

    with patch(
        "app.services.remediation.rollback.tenant_identity_rollback_executor.get_identity_provider_adapter",
        return_value=mock_adapter,
    ):
        tenant = SimpleNamespace(id="t1")
        await rollback_user_consent(
            db=db_session,
            tenant=tenant,
            compliance_result_id=finding.id,
        )

    mock_adapter.patch.assert_called_once()
