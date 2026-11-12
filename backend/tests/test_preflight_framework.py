"""Wave 3B Phase 2 — Pre-flight framework unit tests.

Tests the generic infrastructure:
  A. PreFlightResult and PreFlightReport dataclasses
  B. PreFlightEngine: pass/fail aggregation, fail-closed on exception
  C. run_preflight(): delegates to registry, empty registry = all_passed
  D. Registry: get_checks_for_control, registered_control_ids
  E. PreFlightCheck ABC: _pass / _fail helpers
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from app.services.remediation.preflight.base import (
    PreFlightCheck,
    PreFlightReport,
    PreFlightResult,
)
from app.services.remediation.preflight.engine import PreFlightEngine, run_preflight
from app.services.remediation.preflight.registry import (
    get_checks_for_control,
    registered_control_ids,
)


# ── Concrete stub checks ──────────────────────────────────────────────────────


class _AlwaysPass(PreFlightCheck):
    check_id = "stub_always_pass"
    check_name = "Always Pass"
    blocking = True

    async def run(self, *, graph_client, tenant_id, evidence):
        return self._pass("Passed.", {"ok": True})


class _AlwaysFail(PreFlightCheck):
    check_id = "stub_always_fail"
    check_name = "Always Fail"
    blocking = True

    async def run(self, *, graph_client, tenant_id, evidence):
        return self._fail("Failed.", {"ok": False})


class _NonBlockingFail(PreFlightCheck):
    check_id = "stub_nonblocking_fail"
    check_name = "Non-Blocking Fail"
    blocking = False

    async def run(self, *, graph_client, tenant_id, evidence):
        return self._fail("Non-blocking warning.", {})


class _RaisesException(PreFlightCheck):
    check_id = "stub_raises"
    check_name = "Raises Exception"
    blocking = True

    async def run(self, *, graph_client, tenant_id, evidence):
        raise RuntimeError("unexpected graph error")


def _gc():
    gc = MagicMock()
    gc.tenant = MagicMock()
    gc.tenant.id = "tenant-123"
    return gc


# ══════════════════════════════════════════════════════════════════════════════
# A. PreFlightResult
# ══════════════════════════════════════════════════════════════════════════════


class TestPreFlightResult:
    def test_passed_result(self):
        r = PreFlightResult(
            check_id="x",
            check_name="X",
            blocking=True,
            passed=True,
            summary="ok",
            evidence={"n": 1},
        )
        assert r.passed is True
        assert r.blocking is True
        assert r.evidence == {"n": 1}

    def test_failed_result(self):
        r = PreFlightResult(
            check_id="y",
            check_name="Y",
            blocking=False,
            passed=False,
            summary="nope",
        )
        assert r.passed is False
        assert r.blocking is False
        assert r.evidence == {}


# ══════════════════════════════════════════════════════════════════════════════
# B. PreFlightReport
# ══════════════════════════════════════════════════════════════════════════════


class TestPreFlightReport:
    def _pass_result(self, check_id="p"):
        return PreFlightResult(
            check_id=check_id,
            check_name="P",
            blocking=True,
            passed=True,
            summary="ok",
        )

    def _fail_result(self, check_id="f", blocking=True):
        return PreFlightResult(
            check_id=check_id,
            check_name="F",
            blocking=blocking,
            passed=False,
            summary="fail",
        )

    def test_all_passed_true_when_no_blocking_failures(self):
        report = PreFlightReport(
            control_id="CA_MFA_ADMINS",
            tenant_id="t1",
            all_passed=True,
            results=[self._pass_result()],
        )
        assert report.all_passed is True
        assert report.blocking_failures == []

    def test_blocking_failures_property(self):
        report = PreFlightReport(
            control_id="CA_MFA_ADMINS",
            tenant_id="t1",
            all_passed=False,
            results=[
                self._pass_result("p1"),
                self._fail_result("f1", blocking=True),
                self._fail_result("f2", blocking=False),  # non-blocking — not in blocking_failures
            ],
        )
        assert len(report.blocking_failures) == 1
        assert report.blocking_failures[0].check_id == "f1"

    def test_operator_summary_all_passed(self):
        report = PreFlightReport(
            control_id="CA_MFA_ADMINS",
            tenant_id="t1",
            all_passed=True,
            results=[self._pass_result()],
        )
        summary = report.operator_summary
        assert "passed" in summary.lower()
        assert "CA_MFA_ADMINS" in summary

    def test_operator_summary_with_blocking_failure(self):
        report = PreFlightReport(
            control_id="CA_MFA_ADMINS",
            tenant_id="t1",
            all_passed=False,
            results=[self._fail_result("admin_mfa_registration")],
        )
        summary = report.operator_summary
        assert "BLOCKED" in summary
        assert "admin_mfa_registration" in summary

    def test_to_dict_structure(self):
        report = PreFlightReport(
            control_id="CA_MFA_ADMINS",
            tenant_id="t1",
            all_passed=False,
            results=[self._fail_result("x")],
            execution_id="exec-1",
        )
        d = report.to_dict()
        assert d["control_id"] == "CA_MFA_ADMINS"
        assert d["tenant_id"] == "t1"
        assert d["execution_id"] == "exec-1"
        assert d["all_passed"] is False
        assert len(d["results"]) == 1
        assert len(d["blocking_failures"]) == 1
        assert "operator_summary" in d

    def test_to_dict_result_fields(self):
        r = PreFlightResult(
            check_id="z",
            check_name="Z",
            blocking=True,
            passed=False,
            summary="bad",
            evidence={"key": "val"},
        )
        report = PreFlightReport(control_id="C", tenant_id="t", all_passed=False, results=[r])
        result_dict = report.to_dict()["results"][0]
        assert result_dict["check_id"] == "z"
        assert result_dict["check_name"] == "Z"
        assert result_dict["blocking"] is True
        assert result_dict["passed"] is False
        assert result_dict["summary"] == "bad"
        assert result_dict["evidence"] == {"key": "val"}


# ══════════════════════════════════════════════════════════════════════════════
# C. PreFlightEngine
# ══════════════════════════════════════════════════════════════════════════════


class TestPreFlightEngine:
    async def _run(self, checks):
        engine = PreFlightEngine(checks=checks)
        return await engine.run(
            graph_client=_gc(),
            control_id="CA_MFA_ADMINS",
            tenant_id="tenant-123",
            evidence={},
        )

    def test_no_checks_returns_all_passed(self):
        report = asyncio.run(self._run([]))
        assert report.all_passed is True
        assert report.results == []

    def test_single_passing_check(self):
        report = asyncio.run(self._run([_AlwaysPass()]))
        assert report.all_passed is True
        assert len(report.results) == 1
        assert report.results[0].passed is True

    def test_single_blocking_failure(self):
        report = asyncio.run(self._run([_AlwaysFail()]))
        assert report.all_passed is False
        assert len(report.blocking_failures) == 1

    def test_non_blocking_failure_does_not_block(self):
        report = asyncio.run(self._run([_NonBlockingFail()]))
        assert report.all_passed is True  # no BLOCKING failures
        assert len(report.results) == 1
        assert report.results[0].passed is False  # check did fail

    def test_mixed_pass_and_blocking_fail(self):
        report = asyncio.run(self._run([_AlwaysPass(), _AlwaysFail()]))
        assert report.all_passed is False
        assert len(report.results) == 2

    def test_exception_on_blocking_check_produces_blocking_failure(self):
        """Fail closed: unhandled exception in a blocking check → block."""
        report = asyncio.run(self._run([_RaisesException()]))
        assert report.all_passed is False
        assert len(report.blocking_failures) == 1
        assert "RuntimeError" in report.blocking_failures[0].summary

    def test_exception_propagates_as_failed_result_not_raised(self):
        """Engine must not raise — exception is captured as a failed result."""
        report = asyncio.run(self._run([_RaisesException()]))
        assert len(report.results) == 1
        assert report.results[0].passed is False

    def test_all_checks_run_even_after_first_failure(self):
        """Engine runs all checks sequentially, not short-circuiting."""
        report = asyncio.run(self._run([_AlwaysFail(), _AlwaysPass()]))
        assert len(report.results) == 2

    def test_report_carries_control_and_tenant_ids(self):
        async def _inner():
            engine = PreFlightEngine(checks=[_AlwaysPass()])
            return await engine.run(
                graph_client=_gc(),
                control_id="CA_LEGACY_AUTH_BLOCK",
                tenant_id="my-tenant",
                evidence={},
                execution_id="exec-42",
            )

        report = asyncio.run(_inner())
        assert report.control_id == "CA_LEGACY_AUTH_BLOCK"
        assert report.tenant_id == "my-tenant"
        assert report.execution_id == "exec-42"


# ══════════════════════════════════════════════════════════════════════════════
# D. run_preflight() entry point
# ══════════════════════════════════════════════════════════════════════════════


class TestRunPreflight:
    def test_unknown_control_returns_all_passed(self):
        """Controls not in registry pass through without checks."""

        async def _run():
            return await run_preflight(
                graph_client=_gc(),
                control_id="CA_GUEST_MFA",  # not in preflight registry
                tenant_id="t1",
                evidence={},
            )

        report = asyncio.run(_run())
        assert report.all_passed is True
        assert report.results == []

    def test_registered_control_runs_checks(self):
        """Registered controls have checks that actually run."""
        from unittest.mock import patch

        async def _mock_run_preflight():
            return await run_preflight(
                graph_client=_gc(),
                control_id="CA_MFA_ADMINS",
                tenant_id="t1",
                evidence={},
            )

        # We can't run real checks without Graph — but we can verify that
        # the registry is consulted and checks are attempted.
        with patch(
            "app.services.remediation.preflight.registry.get_checks_for_control",
            return_value=[_AlwaysPass()],
        ):
            report = asyncio.run(_mock_run_preflight())
        assert report.all_passed is True


# ══════════════════════════════════════════════════════════════════════════════
# E. Registry
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistry:
    def test_ca_mfa_admins_has_checks(self):
        checks = get_checks_for_control("CA_MFA_ADMINS")
        assert len(checks) > 0

    def test_ca_mfa_all_users_has_checks(self):
        checks = get_checks_for_control("CA_MFA_ALL_USERS")
        assert len(checks) > 0

    def test_ca_legacy_auth_block_has_checks(self):
        checks = get_checks_for_control("CA_LEGACY_AUTH_BLOCK")
        assert len(checks) > 0

    def test_unknown_control_returns_empty_list(self):
        assert get_checks_for_control("IDENTITY_USER_NO_MFA") == []
        assert get_checks_for_control("CA_GUEST_MFA") == []
        assert get_checks_for_control("DOES_NOT_EXIST") == []

    def test_get_checks_returns_copy(self):
        checks_a = get_checks_for_control("CA_MFA_ADMINS")
        checks_b = get_checks_for_control("CA_MFA_ADMINS")
        assert checks_a is not checks_b  # fresh list each time

    def test_registered_control_ids_contains_wave3b_controls(self):
        ids = registered_control_ids()
        assert "CA_MFA_ADMINS" in ids
        assert "CA_MFA_ALL_USERS" in ids
        assert "CA_LEGACY_AUTH_BLOCK" in ids

    def test_registered_control_ids_excludes_non_preflight_controls(self):
        ids = registered_control_ids()
        assert "IDENTITY_USER_NO_MFA" not in ids
        assert "CA_GUEST_MFA" not in ids

    def test_ca_mfa_admins_break_glass_check_is_first(self):
        from app.services.remediation.preflight.checks.break_glass_check import (
            BreakGlassPresenceCheck,
        )

        checks = get_checks_for_control("CA_MFA_ADMINS")
        assert isinstance(checks[0], BreakGlassPresenceCheck)

    def test_ca_legacy_auth_block_check_order(self):
        from app.services.remediation.preflight.checks.break_glass_check import (
            BreakGlassPresenceCheck,
        )
        from app.services.remediation.preflight.checks.legacy_auth_check import (
            LegacyAuthUsageScanCheck,
            LegacyAuthUsageSummaryCheck,
        )

        checks = get_checks_for_control("CA_LEGACY_AUTH_BLOCK")
        assert isinstance(checks[0], BreakGlassPresenceCheck)
        assert isinstance(checks[1], LegacyAuthUsageScanCheck)
        assert isinstance(checks[2], LegacyAuthUsageSummaryCheck)

    def test_all_registered_checks_have_required_attributes(self):
        for ctrl_id in registered_control_ids():
            for check in get_checks_for_control(ctrl_id):
                assert isinstance(check.check_id, str) and check.check_id
                assert isinstance(check.check_name, str) and check.check_name
                assert isinstance(check.blocking, bool)

    def test_blocking_checks_are_before_nonblocking_checks(self):
        """Ordering invariant: blocking checks precede non-blocking ones."""
        for ctrl_id in registered_control_ids():
            checks = get_checks_for_control(ctrl_id)
            seen_nonblocking = False
            for check in checks:
                if not check.blocking:
                    seen_nonblocking = True
                if seen_nonblocking and check.blocking:
                    pytest.fail(
                        f"{ctrl_id}: blocking check {check.check_id!r} comes after "
                        f"a non-blocking check — re-order so blocking checks run first"
                    )


# ══════════════════════════════════════════════════════════════════════════════
# F. PreFlightCheck ABC helpers
# ══════════════════════════════════════════════════════════════════════════════


class TestPreFlightCheckHelpers:
    def test_fail_helper_sets_passed_false(self):
        check = _AlwaysFail()
        result = check._fail("error msg", {"k": "v"})
        assert result.passed is False
        assert result.blocking is True
        assert result.summary == "error msg"
        assert result.evidence == {"k": "v"}

    def test_pass_helper_sets_passed_true(self):
        check = _AlwaysPass()
        result = check._pass("all good", {"k": "v"})
        assert result.passed is True
        assert result.blocking is True
        assert result.summary == "all good"

    def test_fail_helper_default_evidence_empty_dict(self):
        check = _AlwaysFail()
        result = check._fail("msg")
        assert result.evidence == {}

    def test_pass_helper_default_evidence_empty_dict(self):
        check = _AlwaysPass()
        result = check._pass("msg")
        assert result.evidence == {}

    def test_check_id_and_name_propagated_from_class(self):
        check = _AlwaysPass()
        result = check._pass("ok")
        assert result.check_id == "stub_always_pass"
        assert result.check_name == "Always Pass"

    def test_nonblocking_check_fail_has_blocking_false(self):
        check = _NonBlockingFail()
        result = check._fail("warning")
        assert result.blocking is False
