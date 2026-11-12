import pytest

from app.services.insurance.demo_data import SCENARIOS, get_demo_scenario


def test_cowbell_scenario_exists():
    assert "cowbell" in SCENARIOS


def test_get_demo_scenario_returns_cowbell_by_default():
    scenario = get_demo_scenario()
    assert "prev_payload" in scenario
    assert "remediation_history" in scenario


def test_cowbell_prev_payload_shape():
    scenario = get_demo_scenario("cowbell")
    pp = scenario["prev_payload"]
    assert isinstance(pp["header"]["score"], int)
    assert isinstance(pp["findings"], list)
    assert len(pp["findings"]) > 0
    assert all("title" in f for f in pp["findings"])


def test_cowbell_remediation_history_shape():
    scenario = get_demo_scenario("cowbell")
    rh = scenario["remediation_history"]
    assert "rows" in rh
    assert "empty_message" in rh
    required_keys = {
        "control_id",
        "previous_status",
        "action_taken",
        "remediation_date",
        "current_status",
        "rollback_available",
    }
    for row in rh["rows"]:
        assert required_keys.issubset(row.keys()), f"Row missing keys: {row}"


def test_cowbell_remediation_previous_status_is_fail():
    rows = get_demo_scenario("cowbell")["remediation_history"]["rows"]
    assert all(r["previous_status"] == "Fail" for r in rows)


def test_cowbell_remediation_current_status_is_pass():
    rows = get_demo_scenario("cowbell")["remediation_history"]["rows"]
    assert all(r["current_status"] == "Pass" for r in rows)


def test_cowbell_covers_three_key_controls():
    rows = get_demo_scenario("cowbell")["remediation_history"]["rows"]
    ids = {r["control_id"] for r in rows}
    assert "IDENTITY_ADMIN_NO_MFA" in ids
    assert "IDENTITY_USER_CONSENT_POLICY" in ids
    assert "IDENTITY_ADMIN_COUNT_EXCESS" in ids


def test_unknown_scenario_raises_key_error():
    with pytest.raises(KeyError, match="Unknown demo scenario"):
        get_demo_scenario("nonexistent")


def test_each_scenario_has_required_top_level_keys():
    for name, scenario in SCENARIOS.items():
        assert "prev_payload" in scenario, f"{name!r} missing prev_payload"
        assert "remediation_history" in scenario, f"{name!r} missing remediation_history"


def test_prev_payload_score_is_less_than_100():
    for name, scenario in SCENARIOS.items():
        score = scenario["prev_payload"]["header"]["score"]
        assert 0 <= score <= 100, f"{name!r} has out-of-range score {score}"
