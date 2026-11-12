"""Tests for control confidence index (Phase C).

Formula:
    base_score       = base_weight × 100
    drift_penalty    = min(drift_count × 10, 30)
    durability_bonus = min(verification_count × 1, 10)   [0 when DRIFT_DETECTED]
    score = max(0, min(100, base_score - drift_penalty + durability_bonus))

Scan-only defaults: passed=True → 50, passed=False → 20
N/A controls (verification_supported=False) → None
"""


def _conf(*, status=None, supported=True, drift=0, verifications=0, passed=True):
    from app.services.insurance.control_confidence import compute_control_confidence

    return compute_control_confidence(
        verification_status=status,
        verification_supported=supported,
        drift_count=drift,
        verification_count=verifications,
        scan_passed=passed,
    )


# --- N/A controls ---


def test_na_control_returns_none():
    assert _conf(supported=False) is None


def test_na_control_returns_none_even_with_status():
    assert _conf(status="VERIFIED_CONFIRMED", supported=False) is None


# --- Scan-only defaults (no verification status) ---


def test_scan_only_passing_returns_50():
    assert _conf(status=None, passed=True) == 50


def test_scan_only_failing_returns_20():
    assert _conf(status=None, passed=False) == 20


def test_scan_only_none_passed_returns_none():
    assert _conf(status=None, passed=None) is None


# --- VERIFIED_CONFIRMED formula ---


def test_confirmed_zero_drift_ten_verifications_returns_100():
    # base=90, penalty=0, bonus=10 → 100
    assert _conf(status="VERIFIED_CONFIRMED", drift=0, verifications=10) == 100


def test_confirmed_zero_drift_one_verification_returns_91():
    # base=90, penalty=0, bonus=1 → 91
    assert _conf(status="VERIFIED_CONFIRMED", drift=0, verifications=1) == 91


def test_confirmed_one_drift_ten_verifications_returns_90():
    # base=90, penalty=10, bonus=10 → 90
    assert _conf(status="VERIFIED_CONFIRMED", drift=1, verifications=10) == 90


def test_confirmed_three_drifts_penalty_capped_at_30():
    # base=90, penalty=30 (cap), bonus=10 → 70
    assert _conf(status="VERIFIED_CONFIRMED", drift=3, verifications=10) == 70


def test_confirmed_five_drifts_penalty_still_capped_at_30():
    # drift_count=5 → min(50,30)=30; base=90, penalty=30, bonus=10 → 70
    assert _conf(status="VERIFIED_CONFIRMED", drift=5, verifications=10) == 70


def test_durability_bonus_capped_at_10():
    # verification_count=20 → min(20,10)=10
    assert _conf(status="VERIFIED_CONFIRMED", drift=0, verifications=20) == 100


def test_durability_bonus_not_exceeding_cap():
    score_10 = _conf(status="VERIFIED_CONFIRMED", drift=0, verifications=10)
    score_20 = _conf(status="VERIFIED_CONFIRMED", drift=0, verifications=20)
    assert score_10 == score_20  # bonus capped; no difference above 10


# --- DRIFT_DETECTED ---


def test_drift_detected_always_zero():
    assert _conf(status="DRIFT_DETECTED", drift=0, verifications=0) == 0


def test_drift_detected_durability_bonus_not_applied():
    # Even with 20 verifications, DRIFT_DETECTED → 0
    assert _conf(status="DRIFT_DETECTED", drift=0, verifications=20) == 0


def test_drift_detected_with_high_drift_count_still_zero():
    assert _conf(status="DRIFT_DETECTED", drift=5, verifications=10) == 0


# --- Other statuses ---


def test_verified_provisional_one_verification():
    # base=70, penalty=0, bonus=1 → 71
    assert _conf(status="VERIFIED_PROVISIONAL", drift=0, verifications=1) == 71


def test_pending_no_drift():
    # base=30, penalty=0, bonus=0 → 30
    assert _conf(status="PENDING", drift=0, verifications=0) == 30


def test_failed_no_drift():
    # base=10, penalty=0, bonus=0 → 10
    assert _conf(status="FAILED", drift=0, verifications=0) == 10


def test_score_floor_zero():
    # DRIFT_DETECTED with massive drift_count: still 0, not negative
    assert _conf(status="DRIFT_DETECTED", drift=100, verifications=0) == 0


def test_unknown_status_propagates_value_error():
    import pytest

    with pytest.raises(ValueError):
        _conf(status="BOGUS_STATUS")
