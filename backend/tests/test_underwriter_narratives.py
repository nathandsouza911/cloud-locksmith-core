"""Tests for underwriter-facing per-control prose (Phase E)."""


def _nar(**kwargs):
    from app.services.insurance.underwriter_narratives import build_underwriter_narrative

    return build_underwriter_narrative(**kwargs)


# --- DRIFT_DETECTED ---


def test_drift_three_or_more_uses_count():
    result = _nar(verification_status="DRIFT_DETECTED", drift_count=3, stable_days=None, scan_passed=True)
    assert "3 times" in result
    assert "not currently" in result


def test_drift_count_4_uses_count():
    result = _nar(verification_status="DRIFT_DETECTED", drift_count=4, stable_days=None, scan_passed=True)
    assert "4 times" in result


def test_drift_fewer_than_3_generic_regression():
    result = _nar(verification_status="DRIFT_DETECTED", drift_count=1, stable_days=None, scan_passed=True)
    assert "regressed" in result
    assert "times" not in result


def test_drift_count_2_generic_regression():
    result = _nar(verification_status="DRIFT_DETECTED", drift_count=2, stable_days=None, scan_passed=True)
    assert "regressed" in result


# --- VERIFIED_CONFIRMED ---


def test_confirmed_90_days_includes_day_count():
    result = _nar(verification_status="VERIFIED_CONFIRMED", drift_count=0, stable_days=120, scan_passed=True)
    assert "120 days" in result
    assert "independently verified" in result


def test_confirmed_exactly_90_days_includes_count():
    result = _nar(verification_status="VERIFIED_CONFIRMED", drift_count=0, stable_days=90, scan_passed=True)
    assert "90 days" in result


def test_confirmed_under_90_days_no_day_count():
    result = _nar(verification_status="VERIFIED_CONFIRMED", drift_count=0, stable_days=30, scan_passed=True)
    assert "independently verified" in result
    assert "days" not in result


def test_confirmed_stable_days_none_no_day_count():
    result = _nar(verification_status="VERIFIED_CONFIRMED", drift_count=0, stable_days=None, scan_passed=True)
    assert "independently verified" in result
    assert "days" not in result


# --- VERIFIED_PROVISIONAL ---


def test_provisional_contains_provisional():
    result = _nar(verification_status="VERIFIED_PROVISIONAL", drift_count=0, stable_days=None, scan_passed=True)
    assert "provisional" in result


# --- PENDING states ---


def test_pending_contains_in_progress():
    result = _nar(verification_status="PENDING", drift_count=0, stable_days=None, scan_passed=True)
    assert "in progress" in result


def test_pending_propagation_contains_in_progress():
    result = _nar(verification_status="PENDING_PROPAGATION", drift_count=0, stable_days=None, scan_passed=True)
    assert "in progress" in result


# --- FAILED ---


def test_failed_contains_could_not_be_confirmed():
    result = _nar(verification_status="FAILED", drift_count=0, stable_days=None, scan_passed=True)
    assert "could not be confirmed" in result


# --- Scan-only fallbacks ---


def test_scan_only_passing_no_verification():
    result = _nar(verification_status=None, drift_count=0, stable_days=None, scan_passed=True)
    assert "passed evaluation" in result
    assert "No independent verification" in result


def test_scan_only_failing_no_verification():
    result = _nar(verification_status=None, drift_count=0, stable_days=None, scan_passed=False)
    assert "requires remediation" in result
    assert "No verification evidence" in result
