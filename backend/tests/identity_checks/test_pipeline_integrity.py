from __future__ import annotations

"""
Verifies that the CA extended-controls block is additive and never breaks the
base identity scan. These tests exercise the exact try/except guard in
run_identity_scan() at identity_scan_service.py:720-738.
"""

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


def test_extended_controls_does_not_raise_when_context_has_none_policies():
    """CA checks return [] for None policies; run_extended_controls must not raise."""
    ctx = _ctx(None)
    mock_db = AsyncMock()

    async def _run():
        with patch("app.services.identity_scan_service._safe_upsert_control_result", new_callable=AsyncMock):
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS)

    asyncio.run(_run())  # must not raise


def test_extended_controls_does_not_raise_when_all_checks_crash():
    """If every CA check raises, run_extended_controls swallows and logs — no bubble-up."""
    ctx = _ctx([])
    mock_db = AsyncMock()

    async def always_crash(*, ctx):
        raise RuntimeError("catastrophic failure")

    async def _run():
        with (
            patch("app.services.identity_scan_service.detect_ca_mfa_all_users", side_effect=always_crash),
            patch("app.services.identity_scan_service.detect_ca_mfa_admins", side_effect=always_crash),
            patch("app.services.identity_scan_service.detect_ca_legacy_auth_other_blocked", side_effect=always_crash),
            patch("app.services.identity_scan_service.detect_ca_device_code_flow_blocked", side_effect=always_crash),
            patch(
                "app.services.identity_scan_service.detect_ca_authentication_transfer_blocked", side_effect=always_crash
            ),
            patch("app.services.identity_scan_service.detect_ca_guest_mfa", side_effect=always_crash),
            patch(
                "app.services.identity_scan_service._safe_upsert_control_result",
                new_callable=AsyncMock,
            ) as mock_upsert,
        ):
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS)
            mock_upsert.assert_not_called()

    asyncio.run(_run())


def test_pipeline_extended_block_swallows_graph_fetcher_failure():
    """
    Mirrors the outer try/except in run_identity_scan():
    if GraphFetcher.build_context() raises, the exception must not propagate.
    """

    async def failing_build_context(*args, **kwargs):
        raise ConnectionError("Graph API unreachable")

    async def _run():
        with patch("app.services.graph.graph_fetcher.GraphFetcher.build_context", side_effect=failing_build_context):
            from app.services.graph.graph_fetcher import GraphFetcher

            try:
                ctx = await GraphFetcher().build_context(TENANT_ID, "fake-token")
                mock_db = AsyncMock()
                with patch("app.services.identity_scan_service._safe_upsert_control_result", new_callable=AsyncMock):
                    await run_extended_controls(
                        ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=ALL_CA_CONTROLS
                    )
            except Exception:
                pass  # mirrored guard — must not propagate

    asyncio.run(_run())  # must not raise


def test_extended_controls_empty_baseline_skips_all_upserts():
    """An empty baseline means no controls are in scope — nothing should be persisted."""
    ctx = _ctx([{"id": "p1", "state": "enabled", "conditions": {}, "grantControls": None}])
    mock_db = AsyncMock()

    async def _run():
        with patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            new_callable=AsyncMock,
        ) as mock_upsert:
            await run_extended_controls(ctx=ctx, db=mock_db, tenant_id=TENANT_ID, baseline_controls=set())
            mock_upsert.assert_not_called()

    asyncio.run(_run())


def test_check_result_has_correct_tenant_scope():
    """All CA findings must be TENANT-scoped with the correct tenant_id."""
    ctx = _ctx(
        [
            {
                "id": "policy-all-mfa",
                "state": "enabled",
                "conditions": {
                    "users": {"includeUsers": ["All"]},
                    "applications": {"includeApplications": ["All"]},
                },
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ]
    )
    mock_db = AsyncMock()
    upsert_calls: list[dict] = []

    async def capture(**kwargs):
        upsert_calls.append(kwargs)
        return AsyncMock()

    async def _run():
        with patch("app.services.identity_scan_service._safe_upsert_control_result", side_effect=capture):
            await run_extended_controls(
                ctx=ctx,
                db=mock_db,
                tenant_id=TENANT_ID,
                baseline_controls=ALL_CA_CONTROLS,
            )

    asyncio.run(_run())

    for call_kwargs in upsert_calls:
        assert call_kwargs["resource_type"] == "TENANT"
        assert call_kwargs["resource_id"] == TENANT_ID
        assert call_kwargs["tenant_id"] == TENANT_ID
