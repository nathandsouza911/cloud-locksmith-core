"""Pre-flight check framework: abstract base class and result types.

Design contract:
  - PreFlightCheck.run() MUST NOT raise — all errors are caught internally
    and returned as failed PreFlightResult. The engine adds a second safety
    net (catch-all around each check invocation), but individual checks
    must be defensive.
  - blocking=True  → a failed check BLOCKS execution.
  - blocking=False → informational only; execution continues regardless.

Security invariant (fail closed):
  Any exception from a blocking check, whether in run() or in the engine's
  outer try/except, produces a failed PreFlightResult with blocking=True.
  This means an unexpected Graph error on a blocking check is always a block,
  never a pass-through.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class PreFlightResult:
    check_id: str
    check_name: str
    blocking: bool
    passed: bool
    summary: str
    evidence: dict = field(default_factory=dict)


@dataclass
class PreFlightReport:
    control_id: str
    tenant_id: str
    all_passed: bool
    results: list[PreFlightResult] = field(default_factory=list)
    execution_id: str | None = None

    @property
    def blocking_failures(self) -> list[PreFlightResult]:
        return [r for r in self.results if r.blocking and not r.passed]

    @property
    def operator_summary(self) -> str:
        if self.all_passed:
            checks_run = len(self.results)
            return f"All {checks_run} pre-flight check(s) passed for {self.control_id}. " "Execution is permitted."
        lines = [f"Pre-flight checks BLOCKED execution of {self.control_id}:"]
        for failure in self.blocking_failures:
            lines.append(f"  [{failure.check_id}] {failure.summary}")
        non_blocking = [r for r in self.results if not r.blocking and not r.passed]
        if non_blocking:
            lines.append("Non-blocking warnings:")
            for w in non_blocking:
                lines.append(f"  [{w.check_id}] {w.summary}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "all_passed": self.all_passed,
            "results": [
                {
                    "check_id": r.check_id,
                    "check_name": r.check_name,
                    "blocking": r.blocking,
                    "passed": r.passed,
                    "summary": r.summary,
                    "evidence": r.evidence,
                }
                for r in self.results
            ],
            "blocking_failures": [
                {
                    "check_id": r.check_id,
                    "summary": r.summary,
                    "evidence": r.evidence,
                }
                for r in self.blocking_failures
            ],
            "operator_summary": self.operator_summary,
        }


class PreFlightCheck(ABC):
    """Abstract base for all pre-flight checks.

    Subclasses MUST define class-level attributes:
      check_id   — machine identifier, snake_case (e.g. "break_glass_presence")
      check_name — human-readable label (e.g. "Break-Glass Account Presence")
      blocking   — True if a FAIL on this check must block CA execution

    run() must never raise. Catch all exceptions and return a failed
    PreFlightResult. The engine wraps each invocation in an additional
    try/except as a safety net, but checks are responsible for their own
    error handling first.
    """

    check_id: str
    check_name: str
    blocking: bool

    @abstractmethod
    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult: ...

    def _fail(self, summary: str, evidence: dict | None = None) -> PreFlightResult:
        return PreFlightResult(
            check_id=self.check_id,
            check_name=self.check_name,
            blocking=self.blocking,
            passed=False,
            summary=summary,
            evidence=evidence or {},
        )

    def _pass(self, summary: str, evidence: dict | None = None) -> PreFlightResult:
        return PreFlightResult(
            check_id=self.check_id,
            check_name=self.check_name,
            blocking=self.blocking,
            passed=True,
            summary=summary,
            evidence=evidence or {},
        )
