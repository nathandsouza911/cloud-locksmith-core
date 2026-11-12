from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.identity_scan_service import run_extended_controls

TENANT_ID = "ca-test-tenant-123"
ALL_CA_CONTROLS = frozenset(
    {
        "CA_MFA_ALL_USERS",
        "CA_MFA_ADMINS",
        "CA_LEGACY_AUTH_BLOCK",
        "CA_DEVICE_CODE_FLOW_BLOCK",
        "CA_AUTHENTICATION_TRANSFER_BLOCK",
        "CA_GUEST_MFA",
    }
)


def _ctx(policies: list[dict] | None) -> TenantGraphContext:
    return TenantGraphContext(
        tenant_id=TENANT_ID,
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=policies,
        break_glass_accounts=[],
    )


def _full_policy_set() -> list[dict]:
    """Minimal policies that pass all extended CA checks."""
    return [
        {
            "id": "policy-mfa-all",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"builtInControls": ["mfa"]},
        },
        {
            "id": "policy-block-legacy",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "clientAppTypes": ["exchangeActiveSync", "other"],
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"builtInControls": ["block"]},
        },
        {
            "id": "policy-block-device-code",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
                "authenticationFlows": {"transferMethods": ["deviceCodeFlow"]},
            },
            "grantControls": None,
        },
        {
            "id": "policy-block-auth-transfer",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
                "authenticationFlows": {"transferMethods": ["authenticationTransfer"]},
            },
            "grantControls": {"builtInControls": ["block"]},
        },
        {
            "id": "policy-guest-mfa",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeGuestsOrExternalUsers": {
                        "externalTenants": {"membershipKind": "all"},
                        "guestOrExternalUserTypes": (
                            "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,"
                            "b2bDirectConnectUser,otherExternalUser,serviceProvider"
                        ),
                    }
                },
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"builtInControls": ["mfa"]},
        },
    ]


def test_run_executes_all_checks():
    ctx = _ctx(_full_policy_set())
    mock_db = AsyncMock()
    saved_control_ids = []

    async def capture_upsert(**kwargs):
        saved_control_ids.append(kwargs["control_id"])
        return AsyncMock()

    async def _run():
        with patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            side_effect=capture_upsert,
        ):
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS)

    asyncio.run(_run())
    assert set(saved_control_ids) == ALL_CA_CONTROLS


def test_results_aggregated_correctly():
    ctx = _ctx(_full_policy_set())
    mock_db = AsyncMock()
    upsert_calls: list[dict] = []

    async def capture_upsert(**kwargs):
        upsert_calls.append(kwargs)
        return AsyncMock()

    async def _run():
        with patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            side_effect=capture_upsert,
        ):
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS)

    asyncio.run(_run())

    for call_kwargs in upsert_calls:
        assert call_kwargs["tenant_id"] == TENANT_ID
        assert call_kwargs["resource_type"] == "TENANT"
        assert call_kwargs["resource_id"] == TENANT_ID
        assert "passed" in call_kwargs
        assert "severity" in call_kwargs
        assert "evidence" in call_kwargs


def test_check_failure_does_not_stop_others():
    ctx = _ctx(_full_policy_set())
    mock_db = AsyncMock()
    saved_control_ids = []

    async def capture_upsert(**kwargs):
        saved_control_ids.append(kwargs["control_id"])
        return AsyncMock()

    async def exploding_check(*, ctx):
        raise RuntimeError("Simulated check crash")

    async def _run():
        with (
            patch(
                "app.services.identity_scan_service._safe_upsert_control_result",
                side_effect=capture_upsert,
            ),
            patch(
                "app.services.identity_scan_service.detect_ca_mfa_all_users",
                side_effect=exploding_check,
            ),
        ):
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS)

    asyncio.run(_run())

    assert "CA_MFA_ALL_USERS" not in saved_control_ids
    remaining = ALL_CA_CONTROLS - {"CA_MFA_ALL_USERS"}
    assert remaining.issubset(set(saved_control_ids))


def test_controls_outside_baseline_are_skipped():
    ctx = _ctx(_full_policy_set())
    mock_db = AsyncMock()
    saved_control_ids = []

    async def capture_upsert(**kwargs):
        saved_control_ids.append(kwargs["control_id"])
        return AsyncMock()

    partial_baseline = {"CA_MFA_ALL_USERS", "CA_MFA_ADMINS"}

    async def _run():
        with patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            side_effect=capture_upsert,
        ):
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=partial_baseline)

    asyncio.run(_run())
    assert set(saved_control_ids).issubset(partial_baseline)


def test_no_upserts_when_policies_fetch_failed():
    ctx = _ctx(None)
    mock_db = AsyncMock()

    async def _run():
        with patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            new_callable=AsyncMock,
        ) as mock_upsert:
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS)
            mock_upsert.assert_not_called()

    asyncio.run(_run())
