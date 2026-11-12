"""Tests for VerificationScoreContribution model (Phase B)."""

import pytest


def _get(status):
    from app.services.insurance.verification_scoring import get_verification_contribution

    return get_verification_contribution(status)


def test_none_returns_na_entry():
    c = _get(None)
    assert c.status == "VERIFICATION_NOT_APPLICABLE"
    assert c.in_scoring_pool is False


def test_verified_confirmed_weight():
    c = _get("VERIFIED_CONFIRMED")
    assert c.base_weight == 0.90
    assert c.in_scoring_pool is True


def test_verified_provisional_weight():
    c = _get("VERIFIED_PROVISIONAL")
    assert c.base_weight == 0.70
    assert c.in_scoring_pool is True


def test_pending_propagation_weight():
    c = _get("PENDING_PROPAGATION")
    assert c.base_weight == 0.40
    assert c.in_scoring_pool is True


def test_pending_weight():
    c = _get("PENDING")
    assert c.base_weight == 0.30
    assert c.in_scoring_pool is True


def test_indeterminate_weight():
    c = _get("INDETERMINATE")
    assert c.base_weight == 0.20
    assert c.in_scoring_pool is True


def test_failed_weight():
    c = _get("FAILED")
    assert c.base_weight == 0.10
    assert c.in_scoring_pool is True


def test_drift_detected_weight():
    c = _get("DRIFT_DETECTED")
    assert c.base_weight == 0.00
    assert c.in_scoring_pool is True


def test_verification_not_applicable_not_in_pool():
    c = _get("VERIFICATION_NOT_APPLICABLE")
    assert c.in_scoring_pool is False


def test_unknown_status_raises_value_error():
    with pytest.raises(ValueError, match="BOGUS_STATUS"):
        _get("BOGUS_STATUS")


def test_unknown_status_message_contains_value():
    with pytest.raises(ValueError) as exc_info:
        _get("SOME_FUTURE_STATE")
    assert "SOME_FUTURE_STATE" in str(exc_info.value)


def test_all_known_statuses_are_mapped():
    """Every VerificationStatus enum value must have an entry."""
    from app.services.remediation.verification.lifecycle_state import VerificationStatus

    for status in VerificationStatus:
        c = _get(status.value)
        assert c is not None
        assert c.base_weight >= 0.0
