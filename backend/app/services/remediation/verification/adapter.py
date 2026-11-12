"""VerificationAdapter contract and LegacyFunctionAdapter migration wrapper.

The VerificationAdapter ABC is the single contract all control verifiers must
satisfy going forward. LegacyFunctionAdapter wraps any existing
``(*, db, tenant, compliance_result) -> dict`` verifier function so it
participates in the engine without any changes to the original function.

Future controls should subclass VerificationAdapter directly and implement
read_state / evaluate / build_evidence as separate concerns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class VerificationResult:
    """Structured output from any VerificationAdapter.run() call."""

    success: bool
    reason: str | None
    evidence: dict
    control_id: str

    def to_legacy_dict(self) -> dict:
        """Return the dict shape the existing callers (verify_execution,
        remediation_verification job) already understand."""
        return {
            "success": self.success,
            "details": {
                "reason": self.reason,
                "evidence": self.evidence,
            },
        }


class VerificationAdapter(ABC):
    """Contract for every verifiable control.

    Minimal implementation: override only run().
    Full implementation: override read_state / evaluate / build_evidence
    and let run() call them in sequence (for new controls).
    """

    @abstractmethod
    async def run(
        self,
        *,
        db: Any,
        tenant: Any,
        compliance_result: Any,
    ) -> VerificationResult:
        """Execute verification and return a structured result.

        Must be fail-closed: raise rather than returning success=True
        when the provider state cannot be confidently read.
        """

    async def read_state(self, *, graph_client: Any, compliance_result: Any) -> dict:
        """Read current enforcement state from the identity provider.

        Override in new adapters. Not called by LegacyFunctionAdapter.
        """
        raise NotImplementedError(f"{type(self).__name__} does not implement read_state")

    async def evaluate(self, *, state: dict, compliance_result: Any) -> bool:
        """Pure evaluation: given the provider state, return pass/fail.

        Override in new adapters. No side effects allowed here.
        """
        raise NotImplementedError(f"{type(self).__name__} does not implement evaluate")

    def build_evidence(self, *, state: dict, success: bool) -> dict:
        """Build a structured evidence dict from the provider state.

        Override in new adapters. Used by run() in the base implementation.
        """
        raise NotImplementedError(f"{type(self).__name__} does not implement build_evidence")


class LegacyFunctionAdapter(VerificationAdapter):
    """Wraps an existing ``(*, db, tenant, compliance_result) -> dict`` verifier.

    Used during migration so every currently-registered verifier participates
    in the engine without any changes to its implementation.
    """

    def __init__(self, verifier_fn, *, control_id: str):
        self._fn = verifier_fn
        self._control_id = control_id

    async def run(
        self,
        *,
        db: Any,
        tenant: Any,
        compliance_result: Any,
    ) -> VerificationResult:
        raw = await self._fn(db=db, tenant=tenant, compliance_result=compliance_result)
        details = raw.get("details") or {}
        return VerificationResult(
            success=bool(raw.get("success")),
            reason=details.get("reason"),
            evidence=details.get("evidence") or {},
            control_id=self._control_id,
        )
