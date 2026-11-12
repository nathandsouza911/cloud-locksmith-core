import asyncio
from datetime import timedelta
import logging

from app.utils.datetime import utc_now
from types import SimpleNamespace

from app.db.models.alert import Alert
from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.break_glass_usage_event import BreakGlassUsageEvent
from app.db.models.compliance_result import ComplianceResult
from app.db.models.notification_target import NotificationTarget
from app.db.models.tenant import Tenant
from app.services.graph_client import GraphAPIError
from app.services.break_glass_usage_monitor import (
    BREAK_GLASS_USAGE_CONTROL_ID,
    BREAK_GLASS_USAGE_ALERT_TYPE,
    extract_break_glass_signin_events,
    monitor_break_glass_account_usage,
)


def _create_tenant(db_session, tenant_id: str, *, asset_flags: dict | None = None) -> Tenant:
    tenant = Tenant(
        id=tenant_id,
        tenant_name="Break Glass Monitoring Tenant",
        oauth_token={"access_token": "token", "expires_at": "2099-01-01T00:00:00+00:00"},
        asset_flags=asset_flags or {},
    )
    db_session.add(tenant)
    db_session.commit()
    return tenant


def test_extract_break_glass_signin_events_filters_seen_and_non_break_glass_events():
    events = [
        {
            "id": "event-1",
            "createdDateTime": "2026-04-01T10:00:00Z",
            "userId": "bg-user-1",
            "userPrincipalName": "bg-admin-1@contoso.onmicrosoft.com",
            "location": {"city": "Seattle", "countryOrRegion": "United States"},
        },
        {
            "id": "event-2",
            "createdDateTime": "2026-04-01T10:05:00Z",
            "userId": "normal-user",
            "userPrincipalName": "user@contoso.com",
        },
    ]

    filtered = extract_break_glass_signin_events(
        events=events,
        break_glass_user_ids={"bg-user-1"},
        break_glass_user_principal_names=set(),
        seen_event_ids={"event-2"},
    )

    assert len(filtered) == 1
    assert filtered[0]["id"] == "event-1"
    assert filtered[0]["location"] == "Seattle, United States"


def test_monitor_break_glass_account_usage_persists_and_dispatches_critical_alert(db_session, monkeypatch):
    # With no stored checkpoint the monitor looks back 10 minutes, so the event must be recent.
    recent_signin = (utc_now() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tenant = _create_tenant(db_session, "tenant-break-glass-monitor")
    db_session.add(BreakGlassAccount(tenant_id=tenant.id, user_external_id="bg-user-1"))
    db_session.add(
        NotificationTarget(
            tenant_id=tenant.id,
            channel="webhook",
            destination="https://example.invalid/hook",
            enabled=True,
        )
    )
    db_session.commit()

    delivered = []

    async def fake_send_webhook(url: str, alert):
        delivered.append((url, alert.alert_type, alert.severity, dict(alert.details or {})))

    monkeypatch.setattr("app.services.notification_dispatcher.send_webhook", fake_send_webhook)

    alerts = asyncio.run(
        monitor_break_glass_account_usage(
            db=db_session,
            tenant=tenant,
            sign_in_events=[
                {
                    "id": "event-1",
                    "createdDateTime": recent_signin,
                    "userId": "bg-user-1",
                    "userDisplayName": "[BREAK-GLASS] Break Glass Account 1",
                    "userPrincipalName": "bg-admin-1@contoso.onmicrosoft.com",
                    "ipAddress": "1.2.3.4",
                    "location": {
                        "city": "Seattle",
                        "countryOrRegion": "United States",
                    },
                    "status": {"errorCode": 0},
                }
            ],
        )
    )

    stored_alerts = db_session.query(Alert).filter(Alert.tenant_id == tenant.id).all()
    stored_events = db_session.query(BreakGlassUsageEvent).filter(BreakGlassUsageEvent.tenant_id == tenant.id).all()
    usage_finding = (
        db_session.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant.id,
            ComplianceResult.control_id == BREAK_GLASS_USAGE_CONTROL_ID,
            ComplianceResult.resource_id == "bg-user-1",
        )
        .one()
    )

    assert len(alerts) == 1
    assert len(stored_alerts) == 1
    assert len(stored_events) == 1
    assert stored_events[0].user_id == "bg-user-1"
    assert stored_events[0].status == "success"
    assert stored_alerts[0].alert_type == BREAK_GLASS_USAGE_ALERT_TYPE
    assert stored_alerts[0].severity == "CRITICAL"
    assert stored_alerts[0].details["user"] == "bg-admin-1@contoso.onmicrosoft.com"
    assert stored_alerts[0].details["timestamp"] == recent_signin
    assert stored_alerts[0].details["ip_address"] == "1.2.3.4"
    assert stored_alerts[0].details["location"] == "Seattle, United States"
    assert usage_finding.passed is False
    assert usage_finding.severity == "CRITICAL"
    assert usage_finding.decision_status == "PENDING"
    assert usage_finding.evidence["action"] == "acknowledge"
    assert usage_finding.evidence["label"] == "Mark as Authorized"
    assert usage_finding.evidence["requires_acknowledgment"] is True
    assert delivered == [
        (
            "https://example.invalid/hook",
            BREAK_GLASS_USAGE_ALERT_TYPE,
            "CRITICAL",
            stored_alerts[0].details,
        )
    ]
    assert tenant.asset_flags["break_glass_used"] is True
    assert tenant.asset_flags["break_glass_signin_event_ids"] == ["event-1"]
    assert tenant.asset_flags["break_glass_last_signin_check"] == recent_signin
    assert tenant.asset_flags["break_glass_last_event_id"] == "event-1"


def test_monitor_break_glass_account_usage_skips_duplicate_event_ids(db_session):
    tenant = _create_tenant(
        db_session,
        "tenant-break-glass-dedupe",
        asset_flags={
            "break_glass_signin_event_ids": ["event-1"],
            "break_glass_last_signin_check": "2026-04-01T10:00:00Z",
        },
    )
    db_session.add(BreakGlassAccount(tenant_id=tenant.id, user_external_id="bg-user-1"))
    db_session.commit()

    alerts = asyncio.run(
        monitor_break_glass_account_usage(
            db=db_session,
            tenant=tenant,
            sign_in_events=[
                {
                    "id": "event-1",
                    "createdDateTime": "2026-04-01T10:00:00Z",
                    "userId": "bg-user-1",
                    "userPrincipalName": "bg-admin-1@contoso.onmicrosoft.com",
                }
            ],
        )
    )

    assert alerts == []
    assert db_session.query(Alert).filter(Alert.tenant_id == tenant.id).count() == 0
    assert db_session.query(BreakGlassUsageEvent).filter(BreakGlassUsageEvent.tenant_id == tenant.id).count() == 0


def test_extract_break_glass_signin_events_accepts_marker_fallback():
    filtered = extract_break_glass_signin_events(
        events=[
            {
                "id": "event-3",
                "createdDateTime": "2026-04-01T10:10:00Z",
                "userId": "unknown-user",
                "userDisplayName": "[BREAK-GLASS] Emergency Admin",
                "userPrincipalName": "bg-admin-3@contoso.onmicrosoft.com",
            }
        ],
        break_glass_user_ids=set(),
        break_glass_user_principal_names={"bg-admin-3@contoso.onmicrosoft.com"},
    )

    assert len(filtered) == 1
    assert filtered[0]["id"] == "event-3"


def test_monitor_break_glass_account_usage_does_not_advance_checkpoint_on_graph_failure(
    db_session, monkeypatch, caplog
):
    tenant = _create_tenant(
        db_session,
        "tenant-break-glass-graph-failure",
        asset_flags={
            "break_glass_last_signin_check": "2026-04-01T10:00:00Z",
        },
    )
    db_session.add(BreakGlassAccount(tenant_id=tenant.id, user_external_id="bg-user-1"))
    db_session.commit()

    async def fake_graph_get_all(*args, **kwargs):
        raise GraphAPIError(
            method="GET",
            path="/auditLogs/signIns",
            status_code=503,
            response_body="graph unavailable",
            category="graph_server_error",
        )

    monkeypatch.setattr(
        "app.services.break_glass_usage_monitor.graph_get_all",
        fake_graph_get_all,
    )

    with caplog.at_level(logging.ERROR):
        alerts = asyncio.run(
            monitor_break_glass_account_usage(
                db=db_session,
                tenant=tenant,
            )
        )

    db_session.refresh(tenant)
    assert alerts == []
    assert tenant.asset_flags["break_glass_last_signin_check"] == "2026-04-01T10:00:00Z"
    assert "break_glass_signin_fetch_failed tenant_id=tenant-break-glass-graph-failure" in caplog.text


def test_run_break_glass_monitor_continues_after_tenant_failure(monkeypatch, caplog):
    from app.jobs.break_glass_monitor import run_break_glass_monitor

    tenants = [
        SimpleNamespace(id="tenant-1"),
        SimpleNamespace(id="tenant-2"),
    ]
    processed: list[str] = []

    class _FakeQuery:
        def all(self):
            return tenants

    class _FakeSession:
        def query(self, model):
            assert model is Tenant
            return _FakeQuery()

        def close(self):
            return None

    async def fake_monitor_break_glass_account_usage(*, db, tenant):
        processed.append(tenant.id)
        if tenant.id == "tenant-1":
            raise RuntimeError("boom")
        return []

    monkeypatch.setattr(
        "app.jobs.break_glass_monitor.SyncSessionLocal",
        lambda: _FakeSession(),
    )
    monkeypatch.setattr(
        "app.jobs.break_glass_monitor.monitor_break_glass_account_usage",
        fake_monitor_break_glass_account_usage,
    )

    with caplog.at_level(logging.ERROR):
        asyncio.run(run_break_glass_monitor())

    assert processed == ["tenant-1", "tenant-2"]
    assert "break_glass_monitor_tenant_failed tenant_id=tenant-1 error=boom" in caplog.text
