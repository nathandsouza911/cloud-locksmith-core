from datetime import datetime, timezone

from app.services.activity.unused_account_detector import evaluate_unused_account

NOW = datetime(2026, 5, 29, tzinfo=timezone.utc)


def _user(**overrides):
    base = {
        "id": "u1",
        "userPrincipalName": "user@contoso.com",
        "displayName": "Real User",
        "accountEnabled": True,
        "createdDateTime": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def test_break_glass_is_skipped_and_passes():
    result = evaluate_unused_account(_user(is_break_glass=True), None, workload_available=True, now=NOW)
    assert result["passed"] is True
    assert result["evidence"]["reason"] == "break_glass_account"


def test_disabled_account_skipped_and_passes():
    result = evaluate_unused_account(_user(accountEnabled=False), None, workload_available=True, now=NOW)
    assert result["passed"] is True
    assert result["evidence"]["reason"] == "disabled_account"


def test_guest_account_skipped():
    result = evaluate_unused_account(
        _user(userPrincipalName="ext_user#EXT#@contoso.com"), None, workload_available=True, now=NOW
    )
    assert result["passed"] is True
    assert result["evidence"]["reason"] == "guest_account"


def test_service_account_keyword_skipped():
    result = evaluate_unused_account(
        _user(userPrincipalName="svc-backup@contoso.com"), None, workload_available=True, now=NOW
    )
    assert result["passed"] is True
    assert result["evidence"]["reason"] == "service_account"


def test_business_standard_workload_active_is_info_and_passes():
    workload = {
        "last_activity": datetime(2026, 5, 26),
        "exchange_activity": True,
        "non_email_activity": True,
        "workload_activity": True,
    }
    result = evaluate_unused_account(_user(), workload, workload_available=True, now=NOW)
    assert result["passed"] is True
    assert result["evidence"]["tier"] == "INFO"
    assert result["severity"] == "INFO"
    assert result["decision_status"] == "RESOLVED"


def test_high_when_no_activity_and_workload_available_matched():
    workload = {
        "last_activity": None,
        "exchange_activity": False,
        "non_email_activity": False,
        "workload_activity": False,
    }
    result = evaluate_unused_account(_user(), workload, workload_available=True, now=NOW)
    assert result["passed"] is False
    assert result["severity"] == "HIGH"
    assert result["evidence"]["tier"] == "HIGH"
    assert result["decision_status"] == "PENDING"


def test_unmatched_user_with_reports_available_never_high():
    # Regression: reports available, but this user matched no activity row.
    # Not evaluated against workload => confidence low, capped at MEDIUM.
    result = evaluate_unused_account(_user(), None, workload_available=True, now=NOW)
    assert result["evidence"]["tier"] == "MEDIUM"
    assert result["evidence"]["confidence"] == "low"
    assert result["passed"] is False


def test_workload_unavailable_caps_at_medium():
    result = evaluate_unused_account(_user(), None, workload_available=False, now=NOW)
    assert result["evidence"]["tier"] == "MEDIUM"
    assert result["severity"] == "MEDIUM"


def test_missing_created_date_is_medium_and_fails():
    user = _user()
    del user["createdDateTime"]
    result = evaluate_unused_account(user, None, workload_available=True, now=NOW)
    assert result["passed"] is False
    assert result["severity"] == "MEDIUM"
    assert result["decision_status"] == "PENDING"
    assert result["evidence"]["reason"] == "missing_created_date"
    assert result["evidence"]["tier"] == "MEDIUM"
