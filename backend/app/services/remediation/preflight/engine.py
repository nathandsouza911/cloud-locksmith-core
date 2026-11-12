"""Pre-flight engine: orchestrates checks for a single control execution.

run_preflight() is the public entry point called by CAMFAPolicyExecutor.execute()
before any CA mutation occurs. The engine:

  1. Resolves the check list for the control from the registry.
  2. Logs structured pre-flight start.
  3. Runs each check sequentially; any unhandled exception on a blocking
     check produces a failed blocking result (fail closed).
  4. Aggregates results into a PreFlightReport.
  5. Logs structured pre-flight completion with blocking-failure list.

Security invariant: if ANY blocking check fails or raises, the returned
report.all_passed is False and the caller MUST abort execution.

Audit trail: pre-flight events are recorded as structured log entries
(not RemediationAuditLog) because the executor does not have access to
compliance_result_id at this level. The block result returned to the
execution service will trigger that service's own audit call.
"""

from __future__ import annotations

import logging

from app.services.remediation.preflight.base import (
    PreFlightCheck,
    PreFlightReport,
    PreFlightResult,
)

logger = logging.getLogger(__name__)


class PreFlightEngine:
    """Runs an ordered list of PreFlightChecks and returns a PreFlightReport."""

    def __init__(self, checks: list[PreFlightCheck]) -> None:
        self._checks = checks

    async def run(
        self,
        *,
        graph_client,
        control_id: str,
        tenant_id: str,
        evidence: dict,
        execution_id: str | None = None,
    ) -> PreFlightReport:
        logger.info(
            "preflight_start control_id=%s tenant_id=%s check_count=%s checks=%s",
            control_id,
            tenant_id,
            len(self._checks),
            [c.check_id for c in self._checks],
        )

        results: list[PreFlightResult] = []
        for check in self._checks:
            try:
                result = await check.run(
                    graph_client=graph_client,
                    tenant_id=tenant_id,
                    evidence=evidence,
                )
            except Exception as exc:
                # Safety net — individual checks are responsible for catching
                # their own exceptions, but if one slips through, fail closed
                # on blocking checks.
                result = PreFlightResult(
                    check_id=check.check_id,
                    check_name=check.check_name,
                    blocking=check.blocking,
                    passed=False,
                    summary=(f"Check raised unexpected error: " f"{type(exc).__name__}: {exc}"),
                    evidence={
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                logger.exception(
                    "preflight_check_unhandled_exception check_id=%s " "control_id=%s tenant_id=%s",
                    check.check_id,
                    control_id,
                    tenant_id,
                )
            results.append(result)

        blocking_failures = [r for r in results if r.blocking and not r.passed]
        all_passed = not blocking_failures

        report = PreFlightReport(
            control_id=control_id,
            tenant_id=tenant_id,
            all_passed=all_passed,
            results=results,
            execution_id=execution_id,
        )

        logger.info(
            "preflight_complete control_id=%s tenant_id=%s all_passed=%s " "total_checks=%s blocking_failures=%s",
            control_id,
            tenant_id,
            all_passed,
            len(results),
            [r.check_id for r in blocking_failures],
        )

        return report


async def run_preflight(
    *,
    graph_client,
    control_id: str,
    tenant_id: str,
    evidence: dict,
    execution_id: str | None = None,
) -> PreFlightReport:
    """Run all registered pre-flight checks for a control.

    Returns a PreFlightReport. Caller MUST check report.all_passed before
    proceeding. If False, at least one blocking check failed and CA execution
    must be aborted — no policy may be created or modified.

    If no checks are registered for the control, returns an all_passed=True
    report with no results (safe default for controls outside the registry).
    """
    from app.services.remediation.preflight.registry import get_checks_for_control

    checks = get_checks_for_control(control_id)
    engine = PreFlightEngine(checks=checks)
    return await engine.run(
        graph_client=graph_client,
        control_id=control_id,
        tenant_id=tenant_id,
        evidence=evidence,
        execution_id=execution_id,
    )
