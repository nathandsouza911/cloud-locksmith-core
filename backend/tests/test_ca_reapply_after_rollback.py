"""A CA fix can be applied again after it was rolled back (live run 2026-11-13, L21).

Rollback restores the tenant and empties the control state's managed policy ids,
but keeps its mode / rollout / version. On the next apply the requested settings
matched the state, the engine compared "its" policy with the tenant, found none and
reported drift_detected; with auto-remediation off it returned without applying.
The executors then reported that unknown status as SUCCESS with verified=False, and
the finding failed with the reason "SUCCESS".
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import ca_policy_engine as engine

BREAK_GLASS = ["bg-1", "bg-2"]


def _state(managed_policy_ids):
    return MagicMock(
        mode="audit",
        rollout_phase="full",
        rollout_percentage=100,
        target_group_id=None,
        policy_version=1,
        status="active",
        managed_policy_ids=managed_policy_ids,
    )


def _apply_with_state(state):
    tenant = MagicMock(id="tenant-1", provider="microsoft")
    created = {"id": "new-policy", "displayName": "CLX-LEGACY-AUTH-BLOCK-v1"}
    apply_policy = AsyncMock(return_value={"action": "created", "policy": created, "policy_id": "new-policy"})
    graph = MagicMock()
    graph.list_conditional_access_policies = AsyncMock(return_value=[])
    with (
        patch("app.services.remediation_executor.RemediationGraphClient", return_value=graph),
        patch.object(engine, "list_break_glass_user_ids", return_value=BREAK_GLASS),
        patch.object(engine, "_validate_break_glass_accounts", new=AsyncMock()),
        patch.object(engine, "check_conditional_access_license", new=AsyncMock(return_value=True)),
        patch.object(engine, "get_control_state", new=AsyncMock(return_value=state)),
        patch.object(engine, "create_snapshot", new=AsyncMock(return_value=MagicMock(id=7))),
        patch.object(engine, "apply_policy", new=apply_policy),
        patch.object(engine, "verify_exact_state", new=AsyncMock()),
        patch.object(engine, "calculate_affected_users", new=AsyncMock(return_value=0)),
        patch.object(engine, "create_or_update_control_state", new=AsyncMock(return_value=_state(["new-policy"]))),
        patch.object(engine, "_record_control_execution", return_value=MagicMock(id="exec-1")),
        patch.object(engine.settings, "ENABLE_AUTO_REMEDIATION", False),
    ):
        result = asyncio.run(
            engine._apply_control_unlocked(
                db=MagicMock(), tenant=tenant, control_id="CA_LEGACY_AUTH_BLOCK", mode="audit", rollout_phase="full"
            )
        )
    return result, apply_policy


def test_reapply_after_rollback_creates_the_policy():
    result, apply_policy = _apply_with_state(_state([]))
    apply_policy.assert_awaited()
    assert result["status"] == "success"


def test_a_missing_managed_policy_is_still_reported_as_drift():
    result, apply_policy = _apply_with_state(_state(["policy-that-was-deleted-outside-the-product"]))
    apply_policy.assert_not_awaited()
    assert result["status"] == "drift_detected"


@pytest.mark.parametrize(
    "executor_path, executor_name",
    [
        ("app.services.remediation.ca_mfa_policy_execute", "CAMFAPolicyExecutor"),
        ("app.services.remediation.ca_block_policy_execute", "CABlockPolicyExecutor"),
    ],
)
@pytest.mark.parametrize("engine_status", ["drift_detected", "something_new"])
def test_executors_do_not_report_unknown_engine_statuses_as_success(executor_path, executor_name, engine_status):
    import importlib

    module = importlib.import_module(executor_path)
    executor = getattr(module, executor_name)(
        "CA_LEGACY_AUTH_BLOCK" if executor_name == "CAMFAPolicyExecutor" else "CA_DEVICE_CODE_FLOW_BLOCK"
    )
    graph_client = MagicMock()
    graph_client.tenant = MagicMock(id="tenant-1")
    engine_result = {"status": engine_status, "verified": False}
    with (
        patch(
            "app.services.remediation.preflight.engine.run_preflight",
            new=AsyncMock(return_value=MagicMock(all_passed=True)),
        ),
        patch("app.services.ca_policy_engine.apply_control", new=AsyncMock(return_value=engine_result)),
    ):
        result = asyncio.run(executor.execute(graph_client, {}))
    assert result["status"] == engine_status
