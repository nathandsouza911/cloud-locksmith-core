"""Verification lifecycle state machine.

Defines the allowed status values and the transition matrix for
RemediationVerification rows. Callers use VerificationStateMachine to
validate transitions before writing to the DB.
"""

from __future__ import annotations

from enum import Enum


class VerificationStatus(str, Enum):
    PENDING = "PENDING"
    PENDING_PROPAGATION = "PENDING_PROPAGATION"
    VERIFIED_PROVISIONAL = "VERIFIED_PROVISIONAL"
    VERIFIED_CONFIRMED = "VERIFIED_CONFIRMED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"


# Allowed next-states per current state.
# FAILED is terminal — empty frozenset means no outgoing transitions.
_ALLOWED: dict[VerificationStatus, frozenset[VerificationStatus]] = {
    VerificationStatus.PENDING: frozenset(
        {
            VerificationStatus.PENDING_PROPAGATION,
        }
    ),
    VerificationStatus.PENDING_PROPAGATION: frozenset(
        {
            VerificationStatus.VERIFIED_PROVISIONAL,
            VerificationStatus.FAILED,
            VerificationStatus.INDETERMINATE,
        }
    ),
    VerificationStatus.VERIFIED_PROVISIONAL: frozenset(
        {
            VerificationStatus.VERIFIED_CONFIRMED,
            VerificationStatus.DRIFT_DETECTED,
        }
    ),
    VerificationStatus.VERIFIED_CONFIRMED: frozenset(
        {
            VerificationStatus.DRIFT_DETECTED,
        }
    ),
    VerificationStatus.DRIFT_DETECTED: frozenset(
        {
            VerificationStatus.VERIFIED_PROVISIONAL,
        }
    ),
    VerificationStatus.INDETERMINATE: frozenset(
        {
            VerificationStatus.VERIFIED_PROVISIONAL,
            VerificationStatus.FAILED,
        }
    ),
    VerificationStatus.FAILED: frozenset(),
}


class InvalidVerificationTransition(Exception):
    """Raised when a caller attempts a transition not in the allowed matrix."""


class VerificationStateMachine:
    @staticmethod
    def can_transition(
        from_status: VerificationStatus,
        to_status: VerificationStatus,
    ) -> bool:
        return to_status in _ALLOWED.get(from_status, frozenset())

    @staticmethod
    def assert_transition(
        from_status: VerificationStatus,
        to_status: VerificationStatus,
    ) -> None:
        if not VerificationStateMachine.can_transition(from_status, to_status):
            raise InvalidVerificationTransition(
                f"Invalid verification transition: {from_status.value!r} → {to_status.value!r}"
            )

    @staticmethod
    def allowed_transitions(
        from_status: VerificationStatus,
    ) -> frozenset[VerificationStatus]:
        return _ALLOWED.get(from_status, frozenset())
