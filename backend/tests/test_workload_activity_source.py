from datetime import datetime

from app.services.activity import workload_activity_source as was


def _row(**overrides):
    base = {
        "user_principal_name": "user@contoso.com",
        "last_activity_date": "",
        "exchange_last_activity_date": "",
        "teams_last_activity_date": "",
        "onedrive_last_activity_date": "",
        "sharepoint_last_activity_date": "",
    }
    base.update(overrides)
    return base


def test_build_activity_map_keys_by_lower_upn_and_takes_max():
    rows = [
        _row(
            user_principal_name="User@Contoso.com",
            exchange_last_activity_date="2026-03-01",
            teams_last_activity_date="2026-03-10",
        )
    ]
    activity_map = was.build_activity_map(rows)

    assert "user@contoso.com" in activity_map
    entry = activity_map["user@contoso.com"]
    assert entry["last_activity"] == datetime(2026, 3, 10)
    assert entry["exchange_activity"] is True
    assert entry["workload_activity"] is True


def test_build_activity_map_no_activity_yields_none():
    activity_map = was.build_activity_map([_row()])
    entry = activity_map["user@contoso.com"]
    assert entry["last_activity"] is None
    assert entry["exchange_activity"] is False
    assert entry["workload_activity"] is False
