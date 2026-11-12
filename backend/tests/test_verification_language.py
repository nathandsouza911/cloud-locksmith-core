# tests/test_verification_language.py
from app.services.insurance.verification_language import (
    TERMINOLOGY_MATRIX,
    get_verification_display_label,
    get_remediation_row_label,
    verification_status_is_verified,
)


def test_terminology_matrix_has_exactly_the_known_entries():
    expected = {
        "EVALUATED",
        "REMEDIATED",
        "VERIFIED_PROVISIONAL",
        "VERIFIED_CONFIRMED",
        "DRIFT_DETECTED",
        "FAILED",
        "INDETERMINATE",
        # Both pending states display as "Evaluated".
        "PENDING",
        "PENDING_PROPAGATION",
    }
    assert set(TERMINOLOGY_MATRIX.keys()) == expected


def test_all_matrix_entries_have_required_fields():
    for key, entry in TERMINOLOGY_MATRIX.items():
        assert "label" in entry, f"{key} missing label"
        assert "description" in entry, f"{key} missing description"
        assert "underwriter_safe" in entry, f"{key} missing underwriter_safe"
        assert entry["underwriter_safe"] is True, f"{key} not marked underwriter_safe"


def test_none_status_returns_evaluated():
    assert get_verification_display_label(None) == "Evaluated"


def test_unknown_status_returns_evaluated():
    assert get_verification_display_label("BOGUS_STATUS") == "Evaluated"


def test_drift_detected_label():
    assert get_verification_display_label("DRIFT_DETECTED") == "Drift Detected"


def test_verified_confirmed_label():
    assert get_verification_display_label("VERIFIED_CONFIRMED") == "Verified (Confirmed)"


def test_verified_provisional_label():
    assert get_verification_display_label("VERIFIED_PROVISIONAL") == "Verified (Provisional)"


def test_remediated_label():
    assert get_verification_display_label("REMEDIATED") == "Remediated"


def test_failed_label():
    assert get_verification_display_label("FAILED") == "Verification Failed"


def test_indeterminate_label():
    assert get_verification_display_label("INDETERMINATE") == "Indeterminate"


def test_evaluated_label():
    assert get_verification_display_label("EVALUATED") == "Evaluated"


def test_bare_verified_never_returned():
    """'Verified' alone must never appear — always qualified with (Provisional) or (Confirmed)."""
    all_statuses = [
        None,
        "DRIFT_DETECTED",
        "FAILED",
        "VERIFIED_PROVISIONAL",
        "VERIFIED_CONFIRMED",
        "INDETERMINATE",
        "EVALUATED",
        "REMEDIATED",
        "PENDING",
    ]
    for status in all_statuses:
        label = get_verification_display_label(status)
        assert label != "Verified", f"Bare 'Verified' returned for status={status!r}"


def test_drift_flag_overrides_confirmed_status():
    label = get_remediation_row_label(
        verification_status="VERIFIED_CONFIRMED",
        is_drifted=True,
    )
    assert label == "Drift Detected"


def test_confirmed_without_drift_flag():
    label = get_remediation_row_label(
        verification_status="VERIFIED_CONFIRMED",
        is_drifted=False,
    )
    assert label == "Verified (Confirmed)"


def test_drift_status_without_flag_also_shows_drift():
    label = get_remediation_row_label(
        verification_status="DRIFT_DETECTED",
        is_drifted=False,
    )
    assert label == "Drift Detected"


def test_none_status_no_drift():
    label = get_remediation_row_label(verification_status=None, is_drifted=False)
    assert label == "Evaluated"


def test_verification_status_is_verified_provisional():
    assert verification_status_is_verified("VERIFIED_PROVISIONAL") is True


def test_verification_status_is_verified_confirmed():
    assert verification_status_is_verified("VERIFIED_CONFIRMED") is True


def test_drift_is_not_verified():
    assert verification_status_is_verified("DRIFT_DETECTED") is False


def test_none_is_not_verified():
    assert verification_status_is_verified(None) is False


def test_failed_is_not_verified():
    assert verification_status_is_verified("FAILED") is False


def test_confirmed_and_provisional_produce_different_labels():
    """Spec requirement: VERIFIED_CONFIRMED and VERIFIED_PROVISIONAL must differ."""
    confirmed = get_verification_display_label("VERIFIED_CONFIRMED")
    provisional = get_verification_display_label("VERIFIED_PROVISIONAL")
    assert confirmed != provisional


def test_drift_and_confirmed_produce_different_labels():
    """Spec requirement: DRIFT_DETECTED and VERIFIED_CONFIRMED must differ."""
    drift = get_verification_display_label("DRIFT_DETECTED")
    confirmed = get_verification_display_label("VERIFIED_CONFIRMED")
    assert drift != confirmed
