import inspect

from app.db.models.alert import Alert
from app.services.notification_dispatcher import dispatch_alert as dispatch_notification


async def _maybe_commit(db) -> None:
    commit = getattr(db, "commit", None)
    if commit is None:
        return
    result = commit()
    if inspect.isawaitable(result):
        await result


async def _maybe_refresh(db, alert: Alert) -> None:
    refresh = getattr(db, "refresh", None)
    if refresh is None:
        return
    result = refresh(alert)
    if inspect.isawaitable(result):
        await result


async def create_alert(
    db,
    *,
    tenant_id: str,
    alert_type: str,
    severity: str,
    message: str,
    details: dict | None = None,
) -> Alert:
    alert = Alert(
        tenant_id=tenant_id,
        alert_type=alert_type,
        severity=severity,
        message=message,
        details=details or {},
    )
    db.add(alert)
    await _maybe_commit(db)
    await _maybe_refresh(db, alert)
    await dispatch_notification(db, alert)
    return alert


async def create_alerts(db, *, tenant_id: str, alerts: list[dict] | None) -> list[Alert]:
    created: list[Alert] = []
    for item in alerts or []:
        created.append(
            await create_alert(
                db,
                tenant_id=tenant_id,
                alert_type=str(item.get("type") or "UNKNOWN"),
                severity=str(item.get("severity") or "INFO"),
                message=str(item.get("message") or ""),
                details=item.get("details") if isinstance(item.get("details"), dict) else {},
            )
        )
    return created


async def dispatch_alert(db, tenant_or_alert, alerts: list[dict] | None = None):
    if isinstance(tenant_or_alert, Alert):
        await dispatch_notification(db, tenant_or_alert)
        return [tenant_or_alert]

    tenant = tenant_or_alert
    tenant_id = getattr(tenant, "id", None)
    if not tenant_id:
        raise ValueError("tenant.id is required to dispatch alerts")
    return await create_alerts(db, tenant_id=tenant_id, alerts=alerts)
