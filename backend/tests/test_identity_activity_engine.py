from datetime import datetime, timezone

from app.services.activity.identity_activity_engine import score_activity

NOW = datetime(2026, 5, 29, tzinfo=timezone.utc)


def _user(**overrides):
    base = {"id": "u1", "userPrincipalName": "user@contoso.com", "accountEnabled": True}
    base.update(overrides)
    return base


def _signin(days_ago):
    ts = NOW.timestamp() - days_ago * 86400
    return {
        "signInActivity": {
            "lastSignInDateTime": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    }


def _workload(days_ago, sources=("teams",)):
    ts = NOW.timestamp() - days_ago * 86400
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    return {
        "last_activity": dt,
        "exchange_activity": "exchange" in sources,
        "non_email_activity": any(s in ("teams", "onedrive", "sharepoint") for s in sources),
        "workload_activity": True,
        "_sources": sources,
    }


def test_recent_signin_is_active():
    profile = score_activity(_user(**_signin(5)), None, workload_available=True, now=NOW)
    assert profile["tier"] == "ACTIVE"
    assert profile["identity_active"] is True
    assert "signin" in profile["activity_sources"]


def test_business_standard_no_signin_but_workload_active_is_info():
    profile = score_activity(_user(), _workload(3, ("teams",)), workload_available=True, now=NOW)
    assert profile["tier"] == "INFO"
    assert profile["identity_active"] is False
    assert profile["workload_active"] is True
    assert profile["confidence"] == "high"


def test_no_activity_with_workload_data_90d_is_high():
    empty_workload = {
        "last_activity": None,
        "exchange_activity": False,
        "non_email_activity": False,
        "workload_activity": False,
    }
    profile = score_activity(_user(), empty_workload, workload_available=True, now=NOW)
    assert profile["tier"] == "HIGH"
    assert profile["confidence"] == "high"


def test_no_activity_without_workload_data_caps_at_medium():
    profile = score_activity(_user(), None, workload_available=False, now=NOW)
    assert profile["tier"] == "MEDIUM"
    assert profile["confidence"] == "low"


def test_stale_signin_60_to_90_is_medium():
    profile = score_activity(_user(**_signin(75)), None, workload_available=True, now=NOW)
    assert profile["tier"] == "MEDIUM"


def test_last_activity_is_max_across_signals():
    user = _user(**_signin(40))
    profile = score_activity(user, _workload(3, ("teams",)), workload_available=True, now=NOW)
    assert profile["tier"] == "ACTIVE"
    assert profile["activity_score"] == 100


def test_activity_score_decay_boundaries():
    assert score_activity(_user(**_signin(10)), None, workload_available=True, now=NOW)["activity_score"] == 100
    assert score_activity(_user(**_signin(90)), None, workload_available=True, now=NOW)["activity_score"] == 0
    mid = score_activity(_user(**_signin(60)), None, workload_available=True, now=NOW)["activity_score"]
    assert 40 <= mid <= 60


def test_unmatched_user_workload_available_is_medium_low_confidence():
    # workload_available=True but workload_activity=None (user not found in report)
    # workload_matched=False -> workload_evaluated=False -> tier is MEDIUM, not HIGH
    profile = score_activity(_user(), None, workload_available=True, now=NOW)
    assert profile["tier"] == "MEDIUM"
    assert profile["confidence"] == "low"


def test_activity_sources_workload_keys():
    profile = score_activity(
        _user(),
        _workload(3, ("exchange", "teams")),
        workload_available=True,
        now=NOW,
    )
    assert "exchange" in profile["activity_sources"]
    assert "workload" in profile["activity_sources"]
    assert "signin" not in profile["activity_sources"]
