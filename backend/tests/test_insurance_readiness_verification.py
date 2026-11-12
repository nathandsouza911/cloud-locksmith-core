"""Tests for verification-aware insurance readiness scoring (Phase D)."""

from types import SimpleNamespace


def _make_cr(*, control_id, passed, tenant_id="t1"):
    return SimpleNamespace(
        control_id=control_id,
        passed=passed,
        tenant_id=tenant_id,
        evidence={},
        resource_id=f"r_{control_id}",
    )


def _make_rv(status: str, count: int = 1):
    return SimpleNamespace(status=status, verification_count=count)


def _run(results, verification_states=None, score=80):
    from app.services.insurance.identity_insurance_readiness import (
        calculate_identity_insurance_readiness,
    )

    return calculate_identity_insurance_readiness(
        results,
        score=score,
        verification_states=verification_states,
    )


def test_no_verification_states_returns_verification_aware_false():
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    out = _run(results)
    assert out["verification_aware"] is False
    assert out["drifted_material_controls"] == []
    assert out["confirmed_material_controls"] == []


def test_verification_states_sets_verification_aware_true():
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    states = {"IDENTITY_ADMIN_NO_MFA": _make_rv("VERIFIED_CONFIRMED")}
    out = _run(results, verification_states=states)
    assert out["verification_aware"] is True


def test_drift_on_material_control_surfaces_in_drifted_list():
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    states = {"IDENTITY_ADMIN_NO_MFA": _make_rv("DRIFT_DETECTED")}
    out = _run(results, verification_states=states)
    assert "IDENTITY_ADMIN_NO_MFA" in out["drifted_material_controls"]


def test_confirmed_material_control_surfaces_in_confirmed_list():
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    states = {"IDENTITY_ADMIN_NO_MFA": _make_rv("VERIFIED_CONFIRMED")}
    out = _run(results, verification_states=states)
    assert "IDENTITY_ADMIN_NO_MFA" in out["confirmed_material_controls"]


def test_drift_on_nonmaterial_control_not_in_drifted_list():
    """Only material controls (those that affect underwriting) appear in drift list."""
    results = [_make_cr(control_id="IDENTITY_SOME_MINOR_CTRL", passed=True)]
    states = {"IDENTITY_SOME_MINOR_CTRL": _make_rv("DRIFT_DETECTED")}
    out = _run(results, verification_states=states)
    assert "IDENTITY_SOME_MINOR_CTRL" not in out["drifted_material_controls"]


def test_tier_not_changed_by_verification_state_alone():
    """Tier (readiness) is determined by scan state + score, not verification lifecycle."""
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    # Without verification
    out_no_v = _run(results, score=85)
    # With verification (confirmed)
    states_confirmed = {"IDENTITY_ADMIN_NO_MFA": _make_rv("VERIFIED_CONFIRMED")}
    out_confirmed = _run(results, verification_states=states_confirmed, score=85)
    # Both should produce the same readiness tier
    assert out_no_v["readiness"] == out_confirmed["readiness"]


def test_drift_and_confirmed_produce_different_drifted_list():
    """Spec: confirmed vs drift must produce different insurer-facing outputs."""
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    confirmed_states = {"IDENTITY_ADMIN_NO_MFA": _make_rv("VERIFIED_CONFIRMED")}
    drift_states = {"IDENTITY_ADMIN_NO_MFA": _make_rv("DRIFT_DETECTED")}

    out_confirmed = _run(results, verification_states=confirmed_states)
    out_drift = _run(results, verification_states=drift_states)

    # Confirmed: in confirmed_material_controls, not in drifted
    assert "IDENTITY_ADMIN_NO_MFA" in out_confirmed["confirmed_material_controls"]
    assert "IDENTITY_ADMIN_NO_MFA" not in out_confirmed["drifted_material_controls"]

    # Drift: in drifted_material_controls, not in confirmed
    assert "IDENTITY_ADMIN_NO_MFA" in out_drift["drifted_material_controls"]
    assert "IDENTITY_ADMIN_NO_MFA" not in out_drift["confirmed_material_controls"]


def test_existing_return_keys_still_present():
    """Backward compat: all pre-Phase D keys must still be in the return dict."""
    results = [_make_cr(control_id="IDENTITY_ADMIN_NO_MFA", passed=True)]
    out = _run(results, score=80)
    required = {"readiness", "tier_label", "tier_meaning", "score", "summary", "recommendation"}
    assert required.issubset(set(out.keys()))
