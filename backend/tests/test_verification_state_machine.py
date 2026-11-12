"""State machine contract tests.

Every allowed transition listed in the spec matrix must be tested.
Every disallowed transition must raise InvalidVerificationTransition.
"""

import pytest

from app.services.remediation.verification.lifecycle_state import (
    InvalidVerificationTransition,
    VerificationStatus,
    VerificationStateMachine,
)

S = VerificationStatus
SM = VerificationStateMachine


# ---------------------------------------------------------------------------
# Enum completeness
# ---------------------------------------------------------------------------


def test_all_seven_statuses_exist():
    names = {s.value for s in VerificationStatus}
    assert names == {
        "PENDING",
        "PENDING_PROPAGATION",
        "VERIFIED_PROVISIONAL",
        "VERIFIED_CONFIRMED",
        "DRIFT_DETECTED",
        "FAILED",
        "INDETERMINATE",
    }


# ---------------------------------------------------------------------------
# Allowed transitions (spec matrix)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "from_s,to_s",
    [
        (S.PENDING, S.PENDING_PROPAGATION),
        (S.PENDING_PROPAGATION, S.VERIFIED_PROVISIONAL),
        (S.PENDING_PROPAGATION, S.FAILED),
        (S.PENDING_PROPAGATION, S.INDETERMINATE),
        (S.VERIFIED_PROVISIONAL, S.VERIFIED_CONFIRMED),
        (S.VERIFIED_PROVISIONAL, S.DRIFT_DETECTED),
        (S.VERIFIED_CONFIRMED, S.DRIFT_DETECTED),
        (S.DRIFT_DETECTED, S.VERIFIED_PROVISIONAL),
        (S.INDETERMINATE, S.VERIFIED_PROVISIONAL),
        (S.INDETERMINATE, S.FAILED),
    ],
)
def test_allowed_transition(from_s, to_s):
    assert SM.can_transition(from_s, to_s) is True
    SM.assert_transition(from_s, to_s)  # must not raise


# ---------------------------------------------------------------------------
# Disallowed transitions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "from_s,to_s",
    [
        (S.PENDING, S.VERIFIED_PROVISIONAL),
        (S.PENDING, S.VERIFIED_CONFIRMED),
        (S.PENDING, S.DRIFT_DETECTED),
        (S.PENDING, S.FAILED),
        (S.PENDING, S.INDETERMINATE),
        (S.VERIFIED_CONFIRMED, S.VERIFIED_PROVISIONAL),  # must go through DRIFT first
        (S.VERIFIED_CONFIRMED, S.FAILED),
        (S.VERIFIED_CONFIRMED, S.PENDING_PROPAGATION),
        (S.DRIFT_DETECTED, S.VERIFIED_CONFIRMED),  # must re-prove provisional first
        (S.DRIFT_DETECTED, S.FAILED),
        (S.FAILED, S.VERIFIED_PROVISIONAL),  # FAILED is terminal
        (S.FAILED, S.PENDING_PROPAGATION),
        (S.FAILED, S.DRIFT_DETECTED),
    ],
)
def test_disallowed_transition_raises(from_s, to_s):
    assert SM.can_transition(from_s, to_s) is False
    with pytest.raises(InvalidVerificationTransition):
        SM.assert_transition(from_s, to_s)


# ---------------------------------------------------------------------------
# allowed_transitions returns correct sets
# ---------------------------------------------------------------------------


def test_failed_has_no_allowed_transitions():
    assert SM.allowed_transitions(S.FAILED) == frozenset()


def test_pending_allows_only_pending_propagation():
    assert SM.allowed_transitions(S.PENDING) == frozenset({S.PENDING_PROPAGATION})


def test_verified_confirmed_allows_only_drift():
    assert SM.allowed_transitions(S.VERIFIED_CONFIRMED) == frozenset({S.DRIFT_DETECTED})


# ---------------------------------------------------------------------------
# Error message quality
# ---------------------------------------------------------------------------


def test_invalid_transition_message_contains_statuses():
    with pytest.raises(InvalidVerificationTransition, match="PENDING.*VERIFIED_CONFIRMED"):
        SM.assert_transition(S.PENDING, S.VERIFIED_CONFIRMED)
