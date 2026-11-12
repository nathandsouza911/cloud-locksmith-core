"""CRUD operations for the verification lifecycle tables.

All writes go through these functions so the state machine invariants
are enforced in a single place.
"""

from __future__ import annotations

import logging
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
from app.services.remediation.verification.lifecycle_state import (
    VerificationStatus,
    VerificationStateMachine,
)
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)


def get_or_create_for_execution(
    db: Session,
    *,
    execution_id: uuid.UUID,
    tenant_id: str,
    compliance_result_id: int,
    control_id: str,
) -> tuple[RemediationVerification, bool]:
    """Return (row, created). Creates a PENDING row + creation event if missing."""
    # CRITICAL: execution_id column is String(36); must coerce UUID to str for SQLite.
    eid_str = str(execution_id)
    existing = db.query(RemediationVerification).filter(RemediationVerification.execution_id == eid_str).one_or_none()
    if existing is not None:
        return existing, False

    row = RemediationVerification(
        execution_id=eid_str,
        tenant_id=tenant_id,
        compliance_result_id=compliance_result_id,
        control_id=control_id,
        status=VerificationStatus.PENDING.value,
        verification_count=0,
        evidence_json={},
    )
    db.add(row)
    db.flush()  # Populate row.id without committing the transaction.

    _append_event(
        db,
        verification_id=row.id,
        previous_status=None,
        new_status=VerificationStatus.PENDING.value,
        reason="Verification lifecycle initialized",
        evidence={},
    )
    return row, True


def advance_verification_state(
    db: Session,
    *,
    verification: RemediationVerification,
    new_status: VerificationStatus,
    reason: Optional[str] = None,
    evidence: Optional[dict] = None,
) -> VerificationEvent:
    """Transition ``verification`` to ``new_status``.

    Raises InvalidVerificationTransition when the move is not in the allowed matrix.
    Updates timestamps and verification_count on success.
    """
    from_status = VerificationStatus(verification.status)
    VerificationStateMachine.assert_transition(from_status, new_status)

    now = utc_now()
    previous = verification.status
    verification.status = new_status.value
    verification.updated_at = now
    verification.last_checked_at = now

    if new_status in (VerificationStatus.VERIFIED_PROVISIONAL, VerificationStatus.VERIFIED_CONFIRMED):
        if verification.first_verified_at is None:
            verification.first_verified_at = now
        verification.last_verified_at = now
        verification.verification_count = (verification.verification_count or 0) + 1

    if evidence is not None:
        verification.evidence_json = evidence

    event = _append_event(
        db,
        verification_id=verification.id,
        previous_status=previous,
        new_status=new_status.value,
        reason=reason,
        evidence=evidence or {},
    )

    # Create a durable DriftNotification for regression events. Wrapped in
    # try/except so that a notification failure never blocks the state write.
    if new_status == VerificationStatus.DRIFT_DETECTED:
        verification.drift_count = (verification.drift_count or 0) + 1
        try:
            from app.db.models.compliance_result import ComplianceResult
            from app.services.drift_notification_service import create_drift_notification

            compliance_result = (
                db.query(ComplianceResult)
                .filter(
                    ComplianceResult.id == verification.compliance_result_id,
                    # CRITICAL: must scope to tenant — compliance_result_id is a
                    # sequential integer; filtering by id alone would be a
                    # cross-tenant data exposure risk.
                    ComplianceResult.tenant_id == verification.tenant_id,
                )
                .one_or_none()
            )
            if compliance_result is not None:
                create_drift_notification(
                    db,
                    verification=verification,
                    event=event,
                    compliance_result=compliance_result,
                )
        except Exception:
            logger.exception(
                "drift_notification_creation_failed verification_id=%s — fail-open",
                verification.id,
            )

    return event


def record_recheck(
    db: Session,
    *,
    verification: RemediationVerification,
    evidence: Optional[dict] = None,
) -> None:
    """Record a successful re-check within the same state (no transition).

    Use when the engine verifies a VERIFIED_PROVISIONAL control successfully
    but has not yet met the confirmation threshold — the state stays
    VERIFIED_PROVISIONAL but the count and timestamps advance.
    """
    now = utc_now()
    verification.last_verified_at = now
    verification.last_checked_at = now
    verification.updated_at = now
    verification.verification_count = (verification.verification_count or 0) + 1
    if evidence is not None:
        verification.evidence_json = evidence

    _append_event(
        db,
        verification_id=verification.id,
        previous_status=verification.status,
        new_status=verification.status,  # Same — no transition
        reason="Re-check passed (confirmation pending)",
        evidence=evidence or {},
    )


def get_current_for_compliance_result(
    db: Session,
    compliance_result_id: int,
    tenant_id: str,
) -> Optional[RemediationVerification]:
    """Return the most recently created lifecycle row for a compliance result.

    tenant_id is mandatory to prevent cross-tenant data exposure via guessable
    sequential compliance_result_id values.

    Returns None if no lifecycle row exists yet (pre-Phase C executions).
    """
    return (
        db.query(RemediationVerification)
        .filter(
            RemediationVerification.compliance_result_id == compliance_result_id,
            RemediationVerification.tenant_id == tenant_id,
        )
        .order_by(RemediationVerification.created_at.desc())
        .first()
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _append_event(
    db: Session,
    *,
    verification_id: str,
    previous_status: Optional[str],
    new_status: str,
    reason: Optional[str],
    evidence: dict,
) -> VerificationEvent:
    # CRITICAL: verification_id column is String(36); ensure str coercion.
    event = VerificationEvent(
        verification_id=str(verification_id),
        previous_status=previous_status,
        new_status=new_status,
        reason=reason,
        evidence_json=evidence,
    )
    db.add(event)
    return event
