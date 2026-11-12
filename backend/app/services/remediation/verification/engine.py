"""VerificationEngine — single entry point for all verification operations.

Phase C adds lifecycle-aware methods:
  verify_once()      — single-pass check; writes PENDING→PROVISIONAL lifecycle state
  verify_confirmed() — multi-read confirmation; advances to CONFIRMED when threshold met

The existing run() method is unchanged and still usable for callers that
do not yet require lifecycle tracking.
"""

from __future__ import annotations

import uuid
from datetime import timezone
from typing import TYPE_CHECKING, Any

from app.services.remediation.verification.adapter import VerificationResult
from app.services.remediation.verification.adapter_registry import get_adapter
from app.services.remediation.verification.lifecycle_state import VerificationStatus
from app.services.remediation.verification.lifecycle_store import (
    advance_verification_state,
    get_or_create_for_execution,
    record_recheck,
)
from app.utils.datetime import utc_now

if TYPE_CHECKING:
    from app.db.models.verification_lifecycle import RemediationVerification


class VerificationEngine:
    """Dispatches verification runs to per-control adapters.

    Stateless and thread-safe (shared singleton pattern).
    """

    async def run(
        self,
        control_id: str,
        *,
        db: Any,
        tenant: Any,
        compliance_result: Any,
    ) -> VerificationResult | None:
        """Run verification for ``control_id``.

        Returns None if the control does not support verification.
        Raises on provider errors (fail-closed).
        """
        adapter = get_adapter(control_id)
        if adapter is None:
            return None
        return await adapter.run(db=db, tenant=tenant, compliance_result=compliance_result)

    async def verify_once(
        self,
        control_id: str,
        *,
        db: Any,
        tenant: Any,
        compliance_result: Any,
        execution_id: uuid.UUID,
    ) -> tuple[VerificationResult | None, RemediationVerification | None]:
        """Single verification pass with lifecycle tracking.

        Success path:  PENDING → PENDING_PROPAGATION → VERIFIED_PROVISIONAL
                       DRIFT_DETECTED → VERIFIED_PROVISIONAL  (drift recovery)
        Failure path:  PENDING_PROPAGATION / INDETERMINATE → FAILED
                       VERIFIED_PROVISIONAL / VERIFIED_CONFIRMED → DRIFT_DETECTED
        """
        result = await self.run(control_id, db=db, tenant=tenant, compliance_result=compliance_result)
        if result is None:
            return None, None

        verification, _ = get_or_create_for_execution(
            db,
            execution_id=execution_id,
            tenant_id=str(tenant.id),
            compliance_result_id=compliance_result.id,
            control_id=control_id,
        )

        current = VerificationStatus(verification.status)

        # Always start by marking that a check is in flight.
        if current == VerificationStatus.PENDING:
            advance_verification_state(
                db,
                verification=verification,
                new_status=VerificationStatus.PENDING_PROPAGATION,
                reason="Verification check initiated",
            )
            current = VerificationStatus.PENDING_PROPAGATION

        if result.success:
            _on_success_once(db, verification, current, result.evidence)
        else:
            _on_failure(db, verification, current, result.reason)

        return result, verification

    async def verify_confirmed(
        self,
        control_id: str,
        *,
        db: Any,
        tenant: Any,
        compliance_result: Any,
        execution_id: uuid.UUID,
    ) -> tuple[VerificationResult | None, RemediationVerification | None]:
        """Verification pass with multi-read confirmation tracking.

        On success: advances to VERIFIED_CONFIRMED when
          verification_count >= settings.VERIFICATION_CONFIRMATION_READS
          AND elapsed since first_verified_at >= settings.VERIFICATION_CONFIRMATION_DELAY_SECONDS.
          Otherwise stays / advances to VERIFIED_PROVISIONAL.

        On failure: same as verify_once.
        """
        from app.config import settings

        result = await self.run(control_id, db=db, tenant=tenant, compliance_result=compliance_result)
        if result is None:
            return None, None

        verification, _ = get_or_create_for_execution(
            db,
            execution_id=execution_id,
            tenant_id=str(tenant.id),
            compliance_result_id=compliance_result.id,
            control_id=control_id,
        )

        current = VerificationStatus(verification.status)

        if current == VerificationStatus.PENDING:
            advance_verification_state(
                db,
                verification=verification,
                new_status=VerificationStatus.PENDING_PROPAGATION,
                reason="Verification check initiated",
            )
            current = VerificationStatus.PENDING_PROPAGATION

        if result.success:
            was_provisional = current == VerificationStatus.VERIFIED_PROVISIONAL

            if was_provisional:
                # Check threshold BEFORE the success advance so we only call one
                # of {record_recheck, advance_verification_state} — not both.
                # +1 because this call will be the incrementing operation.
                reads_needed = settings.VERIFICATION_CONFIRMATION_READS
                delay_needed = settings.VERIFICATION_CONFIRMATION_DELAY_SECONDS
                fva = verification.first_verified_at
                threshold_met = False
                if fva is not None:
                    if fva.tzinfo is None:
                        fva = fva.replace(tzinfo=timezone.utc)
                    elapsed = (utc_now() - fva).total_seconds()
                    threshold_met = (verification.verification_count + 1) >= reads_needed and elapsed >= delay_needed

                if threshold_met:
                    # Go directly to CONFIRMED — advance_verification_state
                    # handles the single count increment; calling _on_success_once
                    # first would have caused a double-increment.
                    advance_verification_state(
                        db,
                        verification=verification,
                        new_status=VerificationStatus.VERIFIED_CONFIRMED,
                        reason=f"Confirmed after {verification.verification_count + 1} reads",
                        evidence=result.evidence,
                    )
                else:
                    # Not yet confirmed — just record a regular recheck.
                    _on_success_once(db, verification, current, result.evidence)
            else:
                _on_success_once(db, verification, current, result.evidence)
        else:
            _on_failure(db, verification, current, result.reason)

        return result, verification


# ---------------------------------------------------------------------------
# Internal helpers shared by verify_once and verify_confirmed
# ---------------------------------------------------------------------------


def _on_success_once(
    db: Any,
    verification: Any,
    current: VerificationStatus,
    evidence: dict,
) -> None:
    """Advance state on a successful check for states where transition is defined."""
    if current in (
        VerificationStatus.PENDING_PROPAGATION,
        VerificationStatus.INDETERMINATE,
        VerificationStatus.DRIFT_DETECTED,
    ):
        advance_verification_state(
            db,
            verification=verification,
            new_status=VerificationStatus.VERIFIED_PROVISIONAL,
            reason="Verification passed",
            evidence=evidence,
        )
    elif current == VerificationStatus.VERIFIED_PROVISIONAL:
        # No state transition — increment count and record the re-check.
        record_recheck(db, verification=verification, evidence=evidence)
    elif current == VerificationStatus.VERIFIED_CONFIRMED:
        # Stay confirmed — just refresh timestamps.
        record_recheck(db, verification=verification, evidence=evidence)
    # FAILED is terminal: no action on success (should not be called, but safe to ignore).


def _on_failure(
    db: Any,
    verification: Any,
    current: VerificationStatus,
    reason: str | None,
) -> None:
    """Advance state on a failed check."""
    if current in (
        VerificationStatus.VERIFIED_PROVISIONAL,
        VerificationStatus.VERIFIED_CONFIRMED,
    ):
        advance_verification_state(
            db,
            verification=verification,
            new_status=VerificationStatus.DRIFT_DETECTED,
            reason=reason or "Verification failed — drift detected",
        )
    elif current in (
        VerificationStatus.PENDING_PROPAGATION,
        VerificationStatus.INDETERMINATE,
    ):
        advance_verification_state(
            db,
            verification=verification,
            new_status=VerificationStatus.FAILED,
            reason=reason or "Verification failed",
        )
    elif current == VerificationStatus.DRIFT_DETECTED:
        # Drift persists — update last_checked_at without transitioning.
        now = utc_now()
        verification.last_checked_at = now
        verification.updated_at = now
    # FAILED is terminal — no action.


# Module-level singleton. Import and use directly:
#   from app.services.remediation.verification.engine import verification_engine
verification_engine = VerificationEngine()
