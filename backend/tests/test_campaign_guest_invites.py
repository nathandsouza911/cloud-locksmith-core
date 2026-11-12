"""Tests: IDENTITY_GUEST_INVITES_OPEN promoted to SAFE and usable in campaigns.

RED → GREEN cycle:

G1 — is_safe_control returns True for IDENTITY_GUEST_INVITES_OPEN
G2 — assert_controls_safe passes for IDENTITY_GUEST_INVITES_OPEN
G3 — create_campaign_plan accepts IDENTITY_GUEST_INVITES_OPEN control
G4 — campaign orchestrator rollback dispatches to guest_invites rollback
G5 — rollback_guest_invites restores prior snapshot from RemediationSnapshot
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

GUEST_INVITES_CONTROL = "IDENTITY_GUEST_INVITES_OPEN"
SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


# ── G1 — is_safe_control ─────────────────────────────────────────────────────


def test_guest_invites_is_safe_control():
    assert is_safe_control(GUEST_INVITES_CONTROL) is True


# ── G2 — assert_controls_safe ────────────────────────────────────────────────


def test_assert_controls_safe_passes_for_guest_invites():
    # Must not raise
    assert_controls_safe([GUEST_INVITES_CONTROL])


def test_assert_controls_safe_passes_mixed_safe_controls():
    assert_controls_safe([SAFE_CONTROL, GUEST_INVITES_CONTROL])


# ── G3 — create_campaign_plan accepts the control ────────────────────────────


def test_create_campaign_plan_accepts_guest_invites(db_session):
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    db_session.add(UserTenantAccess(user_id=user_id, tenant_id="t1", role="ADMIN"))
    db_session.add(
        ComplianceResult(
            tenant_id="t1",
            control_id=GUEST_INVITES_CONTROL,
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
        control_ids=[GUEST_INVITES_CONTROL],
        target_tenant_ids=["t1"],
    )
    assert campaign.status == CampaignStatus.AWAITING_APPROVAL.value
    tasks = db_session.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).all()
    assert len(tasks) == 1
    assert tasks[0].control_id == GUEST_INVITES_CONTROL


# ── G4 — orchestrator rollback dispatches to guest_invites rollback ──────────


@pytest.mark.asyncio
async def test_rollback_dispatches_guest_invites():
    """_default_rollback_fn should call rollback_guest_invites for IDENTITY_GUEST_INVITES_OPEN."""
    from app.services.remediation.fleet.campaign_orchestrator import _default_rollback_fn

    with patch(
        "app.services.remediation.rollback.tenant_identity_rollback_executor.rollback_guest_invites"
    ) as mock_rollback:
        mock_rollback.return_value = None
        _default_rollback_fn(
            db=MagicMock(),
            compliance_result_id=42,
            tenant=MagicMock(),
            control_id=GUEST_INVITES_CONTROL,
        )
        mock_rollback.assert_called_once()


# ── G5 — rollback_guest_invites reads snapshot and calls executor ─────────────


@pytest.mark.asyncio
async def test_rollback_guest_invites_uses_snapshot(db_session):
    """rollback_guest_invites should read RemediationSnapshot.state and call executor.rollback."""
    from app.db.models.remediation_snapshot import RemediationSnapshot
    from app.db.models.compliance_result import ComplianceResult, ExposureStatus
    from app.services.remediation.rollback.tenant_identity_rollback_executor import (
        rollback_guest_invites,
    )

    finding = ComplianceResult(
        tenant_id="t1",
        control_id=GUEST_INVITES_CONTROL,
        resource_id="t1",
        resource_type="TENANT",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE,
    )
    db_session.add(finding)
    db_session.flush()

    prior_snapshot = {
        "authorization_policy": {"allowInvitesFrom": "everyone"},
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
        await rollback_guest_invites(
            db=db_session,
            tenant=tenant,
            compliance_result_id=finding.id,
        )

    # Verify the rollback called patch with the prior allowInvitesFrom
    mock_adapter.patch.assert_called_once_with(
        "/policies/authorizationPolicy",
        {"allowInvitesFrom": "everyone"},
    )
