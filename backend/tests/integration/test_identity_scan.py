from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services import identity_scan_service
from app.services.graph_client import GraphAPIError
from app.services import graph_user_service


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


async def _capture_user_controls(
    monkeypatch,
    *,
    users: list[dict],
    workload_activity: dict | None,
    workload_available: bool,
):
    """Run run_user_controls with all Graph/DB side effects stubbed.

    Returns the list of upsert kwargs captured for IDENTITY_UNUSED_ACCOUNT.
    """
    saved_calls: list[dict] = []

    async def fake_upsert_control_result(**kwargs):
        saved_calls.append(kwargs)
        return SimpleNamespace(id=len(saved_calls))

    async def fake_list_break_glass(*, db, tenant_id):
        return []

    async def fake_build_role_map(db, tenant):
        return {}

    async def fake_resolve_findings_async(db, *, tenant_id, control_ids, resource_type):
        return 0

    async def fake_fetch_security_defaults(db, tenant):
        # None → MFA evaluation marks UNKNOWN; we only assert on unused-account rows.
        return True

    async def fake_detect_overprivileged(*, db, tenant):
        return {"user_findings": [], "tenant_finding": {"passed": True}}

    monkeypatch.setattr(identity_scan_service, "upsert_control_result", fake_upsert_control_result)
    monkeypatch.setattr(identity_scan_service, "list_break_glass_user_ids_async", fake_list_break_glass)
    monkeypatch.setattr(identity_scan_service, "_build_role_map", fake_build_role_map)
    monkeypatch.setattr(identity_scan_service, "resolve_findings_async", fake_resolve_findings_async)
    monkeypatch.setattr(
        identity_scan_service,
        "fetch_security_defaults_enabled",
        fake_fetch_security_defaults,
    )
    monkeypatch.setattr(
        identity_scan_service,
        "detect_overprivileged_controls",
        fake_detect_overprivileged,
    )

    await identity_scan_service.run_user_controls(
        db=object(),
        tenant=SimpleNamespace(id="tenant-unused"),
        tenant_id="tenant-unused",
        users=users,
        baseline_controls={"IDENTITY_UNUSED_ACCOUNT"},
        workload_activity=workload_activity,
        workload_available=workload_available,
    )

    return [call for call in saved_calls if call.get("control_id") == "IDENTITY_UNUSED_ACCOUNT"]


@pytest.mark.asyncio
async def test_unused_account_flagged_when_inactive_and_no_workload(monkeypatch):
    users = [
        {
            "id": "user-1",
            "displayName": "Stale User",
            "userPrincipalName": "stale@example.com",
            "accountEnabled": True,
            "createdDateTime": _iso(240),
            "signInActivity": {"lastSignInDateTime": _iso(200)},
        }
    ]

    rows = await _capture_user_controls(
        monkeypatch,
        users=users,
        workload_activity={},
        workload_available=False,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["resource_id"] == "user-1"
    assert row["passed"] is False
    # No workload signal available → MEDIUM tier (low confidence).
    assert row["severity"] == "MEDIUM"
    assert row["evidence"]["workload_data_available"] is False


@pytest.mark.asyncio
async def test_unused_account_passes_with_recent_workload_activity(monkeypatch):
    """A user with no recent sign-in but recent M365 workload activity must
    not be flagged as unused — it resolves to a passing INFO result."""
    users = [
        {
            "id": "user-2",
            "displayName": "Workload Active User",
            "userPrincipalName": "workload@example.com",
            "accountEnabled": True,
            "createdDateTime": _iso(240),
            # No signInActivity at all (e.g. non-premium tenant / never recorded).
        }
    ]
    workload_activity = {
        "workload@example.com": {
            "last_activity": datetime.now(timezone.utc) - timedelta(days=3),
            "exchange_activity": True,
            "non_email_activity": False,
            "workload_activity": True,
        }
    }

    rows = await _capture_user_controls(
        monkeypatch,
        users=users,
        workload_activity=workload_activity,
        workload_available=True,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["resource_id"] == "user-2"
    assert row["passed"] is True
    assert row["severity"] == "INFO"
    assert row["decision_status"] == "RESOLVED"
    assert row["evidence"]["workload_active"] is True
    assert "exchange" in row["evidence"]["activity_sources"]


@pytest.mark.asyncio
async def test_fetch_users_falls_back_when_signin_activity_is_unavailable(monkeypatch):
    calls = {"count": 0}

    async def fake_graph_get_all(db, tenant_obj, path):
        calls["count"] += 1
        if "signInActivity" in path:
            raise GraphAPIError(
                method="GET",
                path=path,
                status_code=403,
                response_body='{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant"}}',
                category="permission_issue",
            )
        return [
            {
                "id": "user-1",
                "displayName": "Fallback User",
                "userPrincipalName": "fallback@example.com",
                "accountEnabled": True,
                "createdDateTime": "2024-01-01T00:00:00Z",
            }
        ]

    tenant = SimpleNamespace(id="tenant-non-premium", asset_flags={})
    monkeypatch.setattr(graph_user_service, "graph_get_all", fake_graph_get_all)

    users = await graph_user_service.fetch_users(object(), tenant)

    assert calls["count"] == 2
    assert len(users) == 1
    assert users[0]["id"] == "user-1"
    assert tenant.asset_flags["has_signin_activity"] is False
