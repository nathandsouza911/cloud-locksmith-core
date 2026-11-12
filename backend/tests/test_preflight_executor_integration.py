"""Wave 3B Phase 2 — Executor integration tests: pre-flight gate in CAMFAPolicyExecutor.

Proves:
  A. Blocking pre-flight failure prevents execution — no apply_control called
  B. No CA mutation when pre-flight blocks
  C. All pre-flight passed → apply_control IS called
  D. Blocked result has correct structure and preflight_report embedded
  E. Non-blocking pre-flight failure does not block execution
  F. Tenant lock still preserved when pre-flight blocks
  G. Break-glass check in pre-flight propagates correctly
  H. run_preflight raises or encounters graph error → execution blocked
  I. Executor purity check still passes after pre-flight wiring
  J. CA_MFA_ADMINS, CA_MFA_ALL_USERS, CA_LEGACY_AUTH_BLOCK all go through pre-flight
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_MFA_ADMINS = "CA_MFA_ADMINS"
_MFA_ALL_USERS = "CA_MFA_ALL_USERS"
_LEGACY_AUTH = "CA_LEGACY_AUTH_BLOCK"
_WAVE3B_CONTROLS = [_MFA_ADMINS, _MFA_ALL_USERS, _LEGACY_AUTH]

# Patch targets: deferred imports inside execute() must be patched at their
# SOURCE module, not on ca_mfa_policy_execute (which has no module-level attribute).
_PREFLIGHT_PATCH = "app.services.remediation.preflight.engine.run_preflight"
_APPLY_CONTROL_PATCH = "app.services.ca_policy_engine.apply_control"


def _run(coro):
    return asyncio.run(coro)


def _graph_client(*, tenant_id: str = "tenant-xyz"):
    gc = MagicMock()
    gc.db = MagicMock()
    gc.tenant = MagicMock()
    gc.tenant.id = tenant_id
    gc.list_conditional_access_policies = AsyncMock(return_value=[])
    gc.delete_conditional_access_policy = AsyncMock(return_value={})
    gc.create_conditional_access_policy = AsyncMock(return_value={"id": "new-pol"})
    return gc


def _executor(control_id: str):
    from app.services.remediation.ca_mfa_policy_execute import CAMFAPolicyExecutor

    return CAMFAPolicyExecutor(control_id)


def _passing_report(control_id: str):
    from app.services.remediation.preflight.base import PreFlightReport

    return PreFlightReport(control_id=control_id, tenant_id="tenant-xyz", all_passed=True)


def _blocking_report(control_id: str):
    from app.services.remediation.preflight.base import PreFlightReport, PreFlightResult

    result = PreFlightResult(
        check_id="admin_mfa_registration",
        check_name="Admin MFA Registration Check",
        blocking=True,
        passed=False,
        summary="1 admin has no MFA methods.",
        evidence={"no_mfa_accounts": [{"user_id": "u1"}]},
    )
    return PreFlightReport(
        control_id=control_id,
        tenant_id="tenant-xyz",
        all_passed=False,
        results=[result],
    )


# ══════════════════════════════════════════════════════════════════════════════
# A + B. Blocking pre-flight prevents apply_control
# ══════════════════════════════════════════════════════════════════════════════


class TestPreFlightBlocksPreventsExecution:
    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_blocked_preflight_returns_blocked_status(self, ctrl):
        executor = _executor(ctrl)
        gc = _graph_client()
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(return_value=_blocking_report(ctrl)),
        ):
            result = _run(executor.execute(gc, evidence={}))
        assert result["status"] == "blocked"
        assert result["reason"] == "preflight_failed"

    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_blocked_preflight_does_not_call_apply_control(self, ctrl):
        executor = _executor(ctrl)
        gc = _graph_client()
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=_blocking_report(ctrl)),
            ),
            patch(_APPLY_CONTROL_PATCH) as mock_apply,
        ):
            _run(executor.execute(gc, evidence={}))
        mock_apply.assert_not_called()

    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_blocked_preflight_no_ca_mutation_on_graph_client(self, ctrl):
        """No CA policy creation or deletion when pre-flight blocks."""
        executor = _executor(ctrl)
        gc = _graph_client()
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(return_value=_blocking_report(ctrl)),
        ):
            _run(executor.execute(gc, evidence={}))
        gc.create_conditional_access_policy.assert_not_called()
        gc.delete_conditional_access_policy.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# C. Passing pre-flight calls apply_control
# ══════════════════════════════════════════════════════════════════════════════


class TestPassingPreFlightAllowsExecution:
    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_passing_preflight_calls_apply_control(self, ctrl):
        executor = _executor(ctrl)
        gc = _graph_client()
        apply_result = {"status": "success", "snapshot_id": "snap-1", "verified": True}
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=_passing_report(ctrl)),
            ),
            patch(
                _APPLY_CONTROL_PATCH,
                new=AsyncMock(return_value=apply_result),
            ) as mock_apply,
        ):
            result = _run(executor.execute(gc, evidence={}))
        mock_apply.assert_called_once()
        assert result["status"] == "SUCCESS"

    def test_passing_preflight_default_mode_is_audit(self):
        """Mode defaults to audit when evidence has no enforcement_mode."""
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        apply_result = {"status": "success", "snapshot_id": "s1", "verified": True}
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=_passing_report(_MFA_ADMINS)),
            ),
            patch(
                _APPLY_CONTROL_PATCH,
                new=AsyncMock(return_value=apply_result),
            ) as mock_apply,
        ):
            _run(executor.execute(gc, evidence={}))
        call_kwargs = mock_apply.call_args.kwargs
        assert call_kwargs["mode"] == "audit"

    def test_passing_preflight_enforced_mode_from_evidence(self):
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        apply_result = {"status": "success", "snapshot_id": "s1", "verified": True}
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=_passing_report(_MFA_ADMINS)),
            ),
            patch(
                _APPLY_CONTROL_PATCH,
                new=AsyncMock(return_value=apply_result),
            ) as mock_apply,
        ):
            _run(executor.execute(gc, evidence={"enforcement_mode": "enforced"}))
        call_kwargs = mock_apply.call_args.kwargs
        assert call_kwargs["mode"] == "enforced"


# ══════════════════════════════════════════════════════════════════════════════
# D. Blocked result structure
# ══════════════════════════════════════════════════════════════════════════════


class TestBlockedResultStructure:
    def test_blocked_result_contains_preflight_report(self):
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        report = _blocking_report(_MFA_ADMINS)
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(return_value=report),
        ):
            result = _run(executor.execute(gc, evidence={}))
        assert "preflight_report" in result
        assert result["preflight_report"]["all_passed"] is False

    def test_blocked_result_has_operator_summary(self):
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        report = _blocking_report(_MFA_ADMINS)
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(return_value=report),
        ):
            result = _run(executor.execute(gc, evidence={}))
        assert "message" in result
        assert result["message"]  # non-empty operator summary

    def test_blocked_result_status_is_blocked(self):
        executor = _executor(_LEGACY_AUTH)
        gc = _graph_client()
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(return_value=_blocking_report(_LEGACY_AUTH)),
        ):
            result = _run(executor.execute(gc, evidence={}))
        assert result["status"] == "blocked"
        assert result["reason"] == "preflight_failed"


# ══════════════════════════════════════════════════════════════════════════════
# E. Non-blocking failure does not block
# ══════════════════════════════════════════════════════════════════════════════


class TestNonBlockingFailureAllowsExecution:
    def test_nonblocking_failure_in_report_still_passes(self):
        """Report with only non-blocking failures has all_passed=True → execution proceeds."""
        from app.services.remediation.preflight.base import PreFlightReport, PreFlightResult

        non_blocking_fail = PreFlightResult(
            check_id="admin_impact_summary",
            check_name="Admin Impact Summary",
            blocking=False,
            passed=False,
            summary="Impact summary unavailable.",
            evidence={},
        )
        report = PreFlightReport(
            control_id=_MFA_ADMINS,
            tenant_id="tenant-xyz",
            all_passed=True,  # non-blocking fails don't block
            results=[non_blocking_fail],
        )
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        apply_result = {"status": "success", "snapshot_id": "s1", "verified": True}
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=report),
            ),
            patch(
                _APPLY_CONTROL_PATCH,
                new=AsyncMock(return_value=apply_result),
            ) as mock_apply,
        ):
            result = _run(executor.execute(gc, evidence={}))
        mock_apply.assert_called_once()
        assert result["status"] == "SUCCESS"


# ══════════════════════════════════════════════════════════════════════════════
# F. Tenant lock preserved
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantLockPreserved:
    def test_ca_engine_lock_error_propagates_when_preflight_passes(self):
        """When pre-flight passes but apply_control raises ControlEngineError
        (e.g. concurrent mutation lock held), the error propagates unchanged."""
        from app.services.ca_policy_engine import ControlEngineError

        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=_passing_report(_MFA_ADMINS)),
            ),
            patch(
                _APPLY_CONTROL_PATCH,
                new=AsyncMock(side_effect=ControlEngineError("concurrent CA mutation running")),
            ),
        ):
            with pytest.raises(ControlEngineError, match="concurrent CA mutation"):
                _run(executor.execute(gc, evidence={}))


# ══════════════════════════════════════════════════════════════════════════════
# G. Break-glass check in pre-flight
# ══════════════════════════════════════════════════════════════════════════════


class TestBreakGlassPreFlightCheck:
    def test_no_break_glass_in_preflight_blocks_execution(self):
        """Break-glass check is wired into the registry — absence blocks execution."""
        from app.services.remediation.preflight.base import PreFlightReport, PreFlightResult

        bg_fail_result = PreFlightResult(
            check_id="break_glass_presence",
            check_name="Break-Glass Account Presence Check",
            blocking=True,
            passed=False,
            summary="No break-glass accounts registered.",
            evidence={},
        )
        report = PreFlightReport(
            control_id=_MFA_ADMINS,
            tenant_id="tenant-xyz",
            all_passed=False,
            results=[bg_fail_result],
        )
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(return_value=report),
        ):
            result = _run(executor.execute(gc, evidence={}))
        assert result["status"] == "blocked"

    def test_break_glass_check_is_first_in_registry(self):
        """Break-glass check runs before admin MFA check in CA_MFA_ADMINS."""
        from app.services.remediation.preflight.checks.break_glass_check import (
            BreakGlassPresenceCheck,
        )
        from app.services.remediation.preflight.registry import get_checks_for_control

        checks = get_checks_for_control("CA_MFA_ADMINS")
        assert isinstance(checks[0], BreakGlassPresenceCheck)


# ══════════════════════════════════════════════════════════════════════════════
# H. run_preflight error → blocked (fail closed)
# ══════════════════════════════════════════════════════════════════════════════


class TestPreFlightGraphError:
    def test_exception_in_run_preflight_propagates(self):
        """If run_preflight itself raises (e.g. import error), the caller sees it.
        This is distinct from check-level errors which are caught by the engine."""
        executor = _executor(_MFA_ADMINS)
        gc = _graph_client()
        with patch(
            _PREFLIGHT_PATCH,
            new=AsyncMock(side_effect=RuntimeError("registry import failed")),
        ):
            with pytest.raises(RuntimeError, match="registry import failed"):
                _run(executor.execute(gc, evidence={}))


# ══════════════════════════════════════════════════════════════════════════════
# I. Executor purity check passes after pre-flight wiring
# ══════════════════════════════════════════════════════════════════════════════


class TestExecutorPurityAfterPreflightWiring:
    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_executor_purity_check_passes(self, ctrl):
        from app.services.remediation_executor import _ensure_executor_purity

        executor = _executor(ctrl)
        # Must not raise RemediationExecutionError
        _ensure_executor_purity(executor, ctrl)

    def test_execute_method_does_not_contain_forbidden_graph_calls(self):
        """The execute() method must not directly call graph helpers."""
        import inspect

        executor = _executor(_MFA_ADMINS)
        source = inspect.getsource(executor.execute)
        forbidden = {"graph_get", "graph_post", "graph_patch", "graph_delete", "httpx."}
        for token in forbidden:
            assert token not in source, f"execute() contains forbidden pattern: {token!r}"


# ══════════════════════════════════════════════════════════════════════════════
# J. All Wave 3B controls use pre-flight
# ══════════════════════════════════════════════════════════════════════════════


class TestAllWave3BControlsUsePreflight:
    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_control_has_preflight_checks_registered(self, ctrl):
        from app.services.remediation.preflight.registry import get_checks_for_control

        checks = get_checks_for_control(ctrl)
        assert len(checks) > 0, f"{ctrl}: no pre-flight checks registered"

    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_control_has_at_least_one_blocking_check(self, ctrl):
        from app.services.remediation.preflight.registry import get_checks_for_control

        checks = get_checks_for_control(ctrl)
        blocking_checks = [c for c in checks if c.blocking]
        assert len(blocking_checks) > 0, f"{ctrl}: no blocking checks registered — pre-flight has no teeth"

    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_break_glass_is_blocking_check_for_all_controls(self, ctrl):
        from app.services.remediation.preflight.checks.break_glass_check import (
            BreakGlassPresenceCheck,
        )
        from app.services.remediation.preflight.registry import get_checks_for_control

        checks = get_checks_for_control(ctrl)
        bg_checks = [c for c in checks if isinstance(c, BreakGlassPresenceCheck)]
        assert len(bg_checks) == 1, f"{ctrl}: expected exactly 1 BreakGlassPresenceCheck, got {len(bg_checks)}"
        assert bg_checks[0].blocking is True

    @pytest.mark.parametrize("ctrl", _WAVE3B_CONTROLS)
    def test_preflight_run_preflight_is_called_during_execute(self, ctrl):
        """run_preflight is always called, regardless of evidence content."""
        executor = _executor(ctrl)
        gc = _graph_client()
        passing = _passing_report(ctrl)
        apply_result = {"status": "success", "snapshot_id": "s1", "verified": True}
        with (
            patch(
                _PREFLIGHT_PATCH,
                new=AsyncMock(return_value=passing),
            ) as mock_pf,
            patch(
                _APPLY_CONTROL_PATCH,
                new=AsyncMock(return_value=apply_result),
            ),
        ):
            _run(executor.execute(gc, evidence={}))
        mock_pf.assert_called_once()
        call_kwargs = mock_pf.call_args.kwargs
        assert call_kwargs["control_id"] == ctrl
        assert call_kwargs["tenant_id"] == "tenant-xyz"
