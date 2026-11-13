"""Device-code-flow and authentication-transfer fixes follow the finding's mode and
run the break-glass preflight (live run 2026-11-13, defect L13).

CABlockPolicyExecutor hard-coded mode="enforced" and ran no preflight, so through
the approval workflow these two fixes were enforced at once, for all users except
break-glass, without the preflight every other CA fix runs. They now behave like
CAMFAPolicyExecutor: report-only unless the finding's mode is ENFORCED, and blocked
when the preflight fails.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.remediation.ca_block_policy_execute import CABlockPolicyExecutor
from app.services.remediation.preflight.checks.break_glass_check import BreakGlassPresenceCheck
from app.services.remediation.preflight.registry import get_checks_for_control

CONTROLS = ["CA_DEVICE_CODE_FLOW_BLOCK", "CA_AUTHENTICATION_TRANSFER_BLOCK"]


def _execute(control_id: str, evidence: dict, *, preflight_passes: bool = True):
    graph_client = MagicMock()
    graph_client.tenant = MagicMock(id="tenant-1")
    report = MagicMock(all_passed=preflight_passes, operator_summary="no break-glass")
    report.to_dict.return_value = {}
    apply = AsyncMock(return_value={"status": "success", "verified": True, "verification_scope": "report_only"})
    preflight = AsyncMock(return_value=report)
    with (
        patch("app.services.remediation.preflight.engine.run_preflight", new=preflight),
        patch("app.services.ca_policy_engine.apply_control", new=apply),
    ):
        result = asyncio.run(CABlockPolicyExecutor(control_id).execute(graph_client, evidence))
    return result, apply, preflight


@pytest.mark.parametrize("control_id", CONTROLS)
def test_audit_finding_creates_a_report_only_policy(control_id):
    _, apply, _ = _execute(control_id, {"enforcement_mode": "AUDIT"})
    assert str(apply.await_args.kwargs["mode"]).lower() == "audit"


@pytest.mark.parametrize("control_id", CONTROLS)
def test_missing_mode_defaults_to_report_only(control_id):
    _, apply, _ = _execute(control_id, {})
    assert str(apply.await_args.kwargs["mode"]).lower() == "audit"


@pytest.mark.parametrize("control_id", CONTROLS)
def test_enforced_finding_is_enforced(control_id):
    _, apply, _ = _execute(control_id, {"enforcement_mode": "ENFORCED"})
    assert str(apply.await_args.kwargs["mode"]).lower() == "enforced"


@pytest.mark.parametrize("control_id", CONTROLS)
def test_failed_preflight_blocks_before_any_change(control_id):
    result, apply, preflight = _execute(control_id, {}, preflight_passes=False)
    preflight.assert_awaited()
    apply.assert_not_awaited()
    assert result["status"] == "blocked"
    assert result["reason"] == "preflight_failed"


@pytest.mark.parametrize("control_id", CONTROLS)
def test_break_glass_check_is_registered(control_id):
    assert any(isinstance(check, BreakGlassPresenceCheck) for check in get_checks_for_control(control_id))
