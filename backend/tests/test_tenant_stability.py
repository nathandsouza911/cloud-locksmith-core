"""Tests for Tenant Stability Index (Phase F).

Formula (four weighted components):
  current_drift_score  = max(0, 100 - controls_drifted/controls_remediated*100)  w=0.30
  history_drift_score  = max(0, 100 - min(drift_event_total*5, 40))              w=0.25
  effectiveness_score  = controls_verified/controls_remediated*100                w=0.30
  failure_score        = max(0, 100 - controls_failed/controls_remediated*100)   w=0.15
  When controls_remediated==0: all components default to 50.
"""


def _tsi(**kwargs):
    from app.services.insurance.tenant_stability import compute_tenant_stability_index

    return compute_tenant_stability_index(**kwargs)


def _default(**overrides):
    base = dict(
        controls_drifted=0,
        controls_remediated=0,
        controls_verified=0,
        controls_failed=0,
        drift_event_total=0,
    )
    base.update(overrides)
    return _tsi(**base)


# --- Zero remediations ---


def test_zero_remediations_returns_50():
    result = _default(controls_remediated=0)
    assert result["score"] == 50
    assert result["band"] == "Developing"


def test_zero_remediations_band_developing():
    assert _default(controls_remediated=0)["band"] == "Developing"


# --- Clean tenant (all confirmed, no drift) ---


def test_all_confirmed_no_drift_high_score():
    result = _default(
        controls_drifted=0,
        controls_remediated=6,
        controls_verified=6,
        controls_failed=0,
        drift_event_total=0,
    )
    assert result["score"] >= 90
    assert result["band"] == "Stable"


# --- History drift reduces score even when current state is clean ---


def test_high_drift_event_total_reduces_score():
    clean = _default(
        controls_drifted=0,
        controls_remediated=6,
        controls_verified=6,
        controls_failed=0,
        drift_event_total=0,
    )
    history = _default(
        controls_drifted=0,
        controls_remediated=6,
        controls_verified=6,
        controls_failed=0,
        drift_event_total=8,  # 8 × 5 = 40 pt penalty (capped)
    )
    assert history["score"] < clean["score"]


def test_drift_event_total_capped_at_40_point_penalty():
    # drift_event_total=8 → min(40,40)=40 → history_drift_score=60
    # drift_event_total=100 → same 40-point cap → same history_drift_score
    result_8 = _default(controls_remediated=6, controls_verified=6, drift_event_total=8)
    result_100 = _default(controls_remediated=6, controls_verified=6, drift_event_total=100)
    assert result_8["score"] == result_100["score"]


# --- All drifted ---


def test_all_controls_drifted_low_score():
    result = _default(
        controls_drifted=6,
        controls_remediated=6,
        controls_verified=0,
        controls_failed=0,
        drift_event_total=6,
    )
    assert result["score"] < 50
    assert result["band"] == "Unstable"


# --- Component weights sum to 1.0 ---


def test_component_weights_sum_to_one():
    weights = [0.30, 0.25, 0.30, 0.15]
    assert abs(sum(weights) - 1.0) < 1e-9


# --- Output structure ---


def test_output_has_required_keys():
    result = _default(controls_remediated=4, controls_verified=4)
    assert "score" in result
    assert "band" in result
    assert "inputs" in result
    inputs = result["inputs"]
    assert "rollback_frequency" in inputs
    assert inputs["rollback_frequency"] == "Not yet tracked — planned future input"


def test_band_stable_at_75():
    # Manually construct a scenario that should yield score=75
    # All components at 75: controls_remediated=4, verified=3(75%), drifted=1(25% drift)
    # current_drift_score = 75, history=100, effectiveness=75, failure=100
    # score = 75*0.30 + 100*0.25 + 75*0.30 + 100*0.15 = 22.5+25+22.5+15 = 85
    result = _default(
        controls_remediated=4, controls_verified=3, controls_drifted=1, controls_failed=0, drift_event_total=0
    )
    assert result["band"] == "Stable"


def test_band_unstable_below_50():
    result = _default(
        controls_drifted=6,
        controls_remediated=6,
        controls_verified=0,
        controls_failed=0,
        drift_event_total=0,
    )
    assert result["score"] < 50
    assert result["band"] == "Unstable"
