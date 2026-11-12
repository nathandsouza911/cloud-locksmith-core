"""Tests for readiness_confidence_score integration (Phase D).

Pool rule: include every control where scan_passed is not None.
N/A exclusion is delegated entirely to compute_control_confidence() returning None.
Material controls (MATERIAL_FINDING_CONTROLS) are weighted 2x.
"""

from types import SimpleNamespace


def _make_rv(status, drift=0, verifications=1):
    return SimpleNamespace(status=status, drift_count=drift, verification_count=verifications)


def _run(controls):
    """
    controls: list of (control_id, scan_passed, rv_or_None, verification_supported)
    """
    from app.services.insurance.readiness_confidence import compute_readiness_confidence

    control_pass_map = {c[0]: c[1] for c in controls}
    verification_states = {c[0]: c[2] for c in controls if c[2] is not None}
    registry = {c[0]: {"verification_supported": c[3]} for c in controls}

    return compute_readiness_confidence(
        control_pass_map=control_pass_map,
        verification_states=verification_states,
        control_registry=registry,
    )


# Helper: use a non-material control id
_NM = "IDENTITY_UNUSED_ACCOUNT"
# Helper: use a material control id
_MAT = "IDENTITY_ADMIN_NO_MFA"


def test_all_confirmed_high_score():
    result = _run(
        [
            (_MAT, True, _make_rv("VERIFIED_CONFIRMED", verifications=10), True),
            (_NM, True, _make_rv("VERIFIED_CONFIRMED", verifications=10), True),
        ]
    )
    assert result["score"] >= 90
    assert result["band"] == "High"


def test_mix_confirmed_and_drifted_score_drops():
    confirmed = _run(
        [
            (_NM, True, _make_rv("VERIFIED_CONFIRMED", verifications=5), True),
        ]
    )
    mixed = _run(
        [
            (_NM, True, _make_rv("VERIFIED_CONFIRMED", verifications=5), True),
            ("IDENTITY_GUEST_INVITES_OPEN", False, _make_rv("DRIFT_DETECTED", drift=1), True),
        ]
    )
    assert mixed["score"] < confirmed["score"]


def test_all_na_controls_returns_50():
    """Empty pool (all N/A) → neutral score 50."""
    result = _run(
        [
            (_NM, True, None, False),  # verification_supported=False → score=None
            (_MAT, True, None, False),
        ]
    )
    assert result["score"] == 50


def test_material_controls_weighted_double():
    """Changing a material control's status should move score more than a non-material one."""
    # Baseline: both confirmed
    base = _run(
        [
            (_MAT, True, _make_rv("VERIFIED_CONFIRMED", verifications=5), True),
            (_NM, True, _make_rv("VERIFIED_CONFIRMED", verifications=5), True),
        ]
    )
    # Drift on material control
    drift_material = _run(
        [
            (_MAT, True, _make_rv("DRIFT_DETECTED", drift=1), True),
            (_NM, True, _make_rv("VERIFIED_CONFIRMED", verifications=5), True),
        ]
    )
    # Drift on non-material control
    drift_nonmaterial = _run(
        [
            (_MAT, True, _make_rv("VERIFIED_CONFIRMED", verifications=5), True),
            (_NM, True, _make_rv("DRIFT_DETECTED", drift=1), True),
        ]
    )
    drop_material = base["score"] - drift_material["score"]
    drop_nonmaterial = base["score"] - drift_nonmaterial["score"]
    assert drop_material > drop_nonmaterial


def test_scan_only_passing_participates_with_50():
    """Scan-only passing control (no rv, supported=True) → score 50 in pool."""
    result = _run(
        [
            (_NM, True, None, True),  # scan-only, passing, supported
        ]
    )
    assert result["score"] == 50
    assert result["inputs"]["controls_scan_only"] == 1
    assert result["inputs"]["controls_in_pool"] == 1


def test_scan_only_failing_participates_with_20():
    result = _run(
        [
            (_NM, False, None, True),  # scan-only, failing, supported
        ]
    )
    assert result["score"] == 20
    assert result["inputs"]["controls_scan_only"] == 1


def test_na_control_excluded_by_compute_not_by_layer():
    """N/A exclusion comes from compute_control_confidence returning None,
    NOT from the readiness confidence layer pre-filtering on verification_supported."""
    result = _run(
        [
            (_NM, True, None, False),  # N/A — excluded
            ("IDENTITY_GUEST_INVITES_OPEN", True, None, True),  # scan-only — included
        ]
    )
    assert result["inputs"]["controls_excluded_na"] == 1
    assert result["inputs"]["controls_in_pool"] == 1


def test_mixed_pool_scan_only_verified_na():
    """Mixed pool: scan-only + verified + N/A. Score reflects first two only."""
    result = _run(
        [
            (_MAT, True, _make_rv("VERIFIED_CONFIRMED", verifications=10), True),  # verified
            (_NM, True, None, True),  # scan-only
            ("IDENTITY_ADMIN_COUNT_EXCESS", True, None, False),  # N/A
        ]
    )
    assert result["inputs"]["controls_in_pool"] == 2
    assert result["inputs"]["controls_excluded_na"] == 1
    assert result["inputs"]["controls_scan_only"] == 1
    # Material confirmed → 100; scan-only → 50. Material weight=2, NM weight=1.
    # weighted_sum = 100*2 + 50*1 = 250; total_weight = 3; score = round(250/3) = 83
    assert result["score"] == 83


def test_backward_compat_existing_readiness_keys_unaffected():
    """Calling compute_readiness_confidence must not touch any existing readiness keys."""
    result = _run([(_NM, True, _make_rv("VERIFIED_CONFIRMED"), True)])
    for key in ("readiness", "tier_label", "tier_meaning", "summary", "recommendation"):
        assert key not in result


def test_passed_none_controls_excluded():
    """Controls with scan_passed=None must not enter the pool."""
    result = _run(
        [
            (_NM, None, None, True),  # passed=None → excluded
        ]
    )
    assert result["score"] == 50  # empty pool → neutral
    assert result["inputs"]["controls_in_pool"] == 0
