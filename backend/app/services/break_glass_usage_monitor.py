from __future__ import annotations

import inspect
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.break_glass_usage_event import BreakGlassUsageEvent
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.services.alert_service import create_alert
from app.services.graph_client import GraphAPIError, graph_get_all
from app.utils.datetime import to_naive_utc, utc_now

logger = logging.getLogger(__name__)

BREAK_GLASS_USAGE_CONTROL_ID = "IDENTITY_BREAK_GLASS_USAGE"
BREAK_GLASS_USAGE_ALERT_TYPE = "BREAK_GLASS_ACCOUNT_USED"
BREAK_GLASS_USAGE_ALERT_SEVERITY = "CRITICAL"
BREAK_GLASS_SIGNIN_SOURCE = "break_glass_signins"
BREAK_GLASS_DISPLAY_MARKER = "[BREAK-GLASS]"
DEFAULT_LOOKBACK_MINUTES = 10
MAX_TRACKED_EVENT_IDS = 100


def _parse_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _has_break_glass_marker(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().startswith(BREAK_GLASS_DISPLAY_MARKER)


def _normalize_location(location: dict | str | None):
    if isinstance(location, dict):
        parts = [
            location.get("city"),
            location.get("state"),
            location.get("countryOrRegion"),
        ]
        return ", ".join(part for part in parts if isinstance(part, str) and part) or None
    if isinstance(location, str) and location:
        return location
    return None


def build_break_glass_usage_alert(event: dict) -> dict:
    user_principal_name = event.get("userPrincipalName") or event.get("user") or "Unknown user"
    display_name = event.get("userDisplayName") or user_principal_name
    occurred_at = event.get("timestamp") or event.get("createdDateTime")
    ip_address = event.get("ipAddress")
    location = event.get("location")

    details = {
        "user": user_principal_name,
        "user_id": event.get("userId"),
        "display_name": display_name,
        "timestamp": occurred_at,
        "ip_address": ip_address,
        "location": location,
        "status": event.get("status") if isinstance(event.get("status"), dict) else {},
        "sign_in_event_id": event.get("id"),
        "source": event.get("source") or BREAK_GLASS_SIGNIN_SOURCE,
    }
    return {
        "type": BREAK_GLASS_USAGE_ALERT_TYPE,
        "severity": BREAK_GLASS_USAGE_ALERT_SEVERITY,
        "message": f"Break-glass account used: {display_name}",
        "details": details,
    }


def _is_known_break_glass_event(
    *,
    event: dict,
    break_glass_user_ids: set[str],
    break_glass_user_principal_names: set[str],
) -> bool:
    user_id = event.get("userId")
    if isinstance(user_id, str) and user_id in break_glass_user_ids:
        return True

    user_principal_name = event.get("userPrincipalName")
    if isinstance(user_principal_name, str) and user_principal_name.lower() in break_glass_user_principal_names:
        return True

    return _has_break_glass_marker(event.get("userDisplayName"))


def extract_break_glass_signin_events(
    *,
    events: list[dict] | None,
    break_glass_user_ids: set[str],
    break_glass_user_principal_names: set[str] | None = None,
    since: datetime | None = None,
    seen_event_ids: set[str] | None = None,
) -> list[dict]:
    filtered: list[dict] = []
    seen_event_ids = seen_event_ids or set()
    break_glass_user_principal_names = break_glass_user_principal_names or set()

    for event in events or []:
        if not isinstance(event, dict):
            continue
        if not _is_known_break_glass_event(
            event=event,
            break_glass_user_ids=break_glass_user_ids,
            break_glass_user_principal_names=break_glass_user_principal_names,
        ):
            continue
        event_id = event.get("id")
        if isinstance(event_id, str) and event_id and event_id in seen_event_ids:
            continue
        created_at = _parse_datetime(event.get("createdDateTime"))
        if since is not None and created_at is not None and created_at <= since:
            continue

        next_event = dict(event)
        next_event["timestamp"] = event.get("createdDateTime")
        next_event["location"] = _normalize_location(event.get("location"))
        next_event["source"] = event.get("source") or BREAK_GLASS_SIGNIN_SOURCE
        filtered.append(next_event)

    filtered.sort(
        key=lambda item: _parse_datetime(item.get("createdDateTime")) or datetime.min.replace(tzinfo=timezone.utc)
    )
    return filtered


def _break_glass_accounts(*, db, tenant) -> dict[str, list[str]]:
    rows = db.query(BreakGlassAccount.user_external_id).filter(BreakGlassAccount.tenant_id == tenant.id).all()
    persisted = [value for (value,) in rows if isinstance(value, str) and value]
    asset_flags = dict(getattr(tenant, "asset_flags", None) or {})
    flagged_ids = []
    flagged_upns = []
    for item in asset_flags.get("break_glass_accounts") or []:
        if not isinstance(item, dict):
            continue
        user_id = item.get("user_id")
        if isinstance(user_id, str) and user_id:
            flagged_ids.append(user_id)
        user_principal_name = item.get("user_principal_name")
        if isinstance(user_principal_name, str) and user_principal_name:
            flagged_upns.append(user_principal_name.lower())
    return {
        "user_ids": list(dict.fromkeys([*persisted, *flagged_ids])),
        "user_principal_names": list(dict.fromkeys(flagged_upns)),
    }


def _last_check_timestamp(tenant) -> datetime:
    asset_flags = dict(getattr(tenant, "asset_flags", None) or {})
    last_check = _parse_datetime(asset_flags.get("break_glass_last_signin_check"))
    if last_check is not None:
        return last_check
    last_scan_at = getattr(tenant, "last_scan_at", None)
    if isinstance(last_scan_at, datetime):
        if last_scan_at.tzinfo is None:
            return last_scan_at.replace(tzinfo=timezone.utc)
        return last_scan_at.astimezone(timezone.utc)
    return utc_now() - timedelta(minutes=DEFAULT_LOOKBACK_MINUTES)


def _tracked_event_ids(tenant) -> list[str]:
    asset_flags = dict(getattr(tenant, "asset_flags", None) or {})
    tracked = []
    for item in asset_flags.get("break_glass_signin_event_ids") or []:
        if isinstance(item, str) and item:
            tracked.append(item)
    return tracked


def _existing_usage_event_ids(*, db, tenant_id: str) -> set[str]:
    rows = db.query(BreakGlassUsageEvent.source_event_id).filter(BreakGlassUsageEvent.tenant_id == tenant_id).all()
    return {value for (value,) in rows if isinstance(value, str) and value}


async def _maybe_commit(db) -> None:
    commit = getattr(db, "commit", None)
    if commit is None:
        return
    result = commit()
    if inspect.isawaitable(result):
        await result


async def fetch_break_glass_signin_events(
    *,
    db,
    tenant,
    since: datetime,
    break_glass_user_principal_names: set[str] | None = None,
) -> list[dict]:
    filter_value = _format_datetime(since)
    filter_clauses = [f"createdDateTime ge {filter_value}"]
    if break_glass_user_principal_names:
        user_filters = []
        for user_principal_name in sorted(break_glass_user_principal_names):
            if not isinstance(user_principal_name, str) or not user_principal_name:
                continue
            escaped = user_principal_name.replace("'", "''")
            user_filters.append(f"userPrincipalName eq '{escaped}'")
        if user_filters:
            filter_clauses.append("(" + " or ".join(user_filters) + ")")
    path = (
        "/auditLogs/signIns?$top=50"
        "&$select=id,createdDateTime,userId,userDisplayName,userPrincipalName,ipAddress,location,status"
        "&$filter=" + quote(" and ".join(filter_clauses), safe="=$'() ")
    )
    return await graph_get_all(db, tenant, path)


def _signin_status(event: dict) -> str:
    status = event.get("status")
    if not isinstance(status, dict):
        return "unknown"
    error_code = status.get("errorCode")
    if error_code in (0, "0", None):
        return "success"
    return "failure"


def _persist_usage_event(*, db, tenant, event: dict) -> BreakGlassUsageEvent | None:
    source_event_id = event.get("id")
    user_id = event.get("userId")
    occurred_at = _parse_datetime(event.get("createdDateTime"))
    if not isinstance(source_event_id, str) or not source_event_id:
        return None
    if not isinstance(user_id, str) or not user_id:
        return None
    if occurred_at is None:
        return None

    usage_event = BreakGlassUsageEvent(
        tenant_id=tenant.id,
        user_id=user_id,
        user_principal_name=event.get("userPrincipalName"),
        source_event_id=source_event_id,
        source=event.get("source") or BREAK_GLASS_SIGNIN_SOURCE,
        event_type="sign_in",
        timestamp=occurred_at.replace(tzinfo=None) if occurred_at.tzinfo else occurred_at,
        ip_address=event.get("ipAddress"),
        location=_normalize_location(event.get("location")),
        status=_signin_status(event),
    )
    db.add(usage_event)
    return usage_event


def _persist_usage_finding(*, db, tenant, event: dict) -> ComplianceResult | None:
    user_id = event.get("userId")
    occurred_at = _parse_datetime(event.get("createdDateTime"))
    if not isinstance(user_id, str) or not user_id:
        return None
    if occurred_at is None:
        return None

    observed_at = to_naive_utc(utc_now())
    event_timestamp = occurred_at.replace(tzinfo=None) if occurred_at.tzinfo else occurred_at
    evidence = {
        "control_id": BREAK_GLASS_USAGE_CONTROL_ID,
        "user_id": user_id,
        "user_principal_name": event.get("userPrincipalName"),
        "display_name": event.get("userDisplayName"),
        "timestamp": event.get("createdDateTime"),
        "ip_address": event.get("ipAddress"),
        "location": _normalize_location(event.get("location")),
        "status": _signin_status(event),
        "source_event_id": event.get("id"),
        "action": "acknowledge",
        "label": "Mark as Authorized",
        "requires_acknowledgment": True,
    }
    finding = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant.id,
            ComplianceResult.control_id == BREAK_GLASS_USAGE_CONTROL_ID,
            ComplianceResult.resource_id == user_id,
        )
        .one_or_none()
    )
    if finding is None:
        finding = ComplianceResult(
            tenant_id=tenant.id,
            control_id=BREAK_GLASS_USAGE_CONTROL_ID,
            resource_type="USER",
            resource_id=user_id,
            framework="identity",
            first_seen_at=observed_at,
        )
        db.add(finding)

    finding.passed = False
    finding.severity = "CRITICAL"
    finding.evidence = evidence
    finding.exposure_status = ExposureStatus.ACTIVE.value
    finding.remediation_status = "PENDING"
    finding.decision_status = "PENDING"
    finding.acknowledged = False
    finding.acknowledged_at = None
    finding.acknowledged_by = None
    finding.resolved_at = None
    finding.resolved_by = None
    finding.last_seen_at = event_timestamp
    finding.evaluated_at = observed_at
    return finding


async def monitor_break_glass_account_usage(
    *,
    db,
    tenant,
    sign_in_events: list[dict] | None = None,
) -> list:
    break_glass_accounts = _break_glass_accounts(db=db, tenant=tenant)
    break_glass_user_ids = set(break_glass_accounts["user_ids"])
    break_glass_user_principal_names = set(break_glass_accounts["user_principal_names"])
    if not break_glass_user_ids and not break_glass_user_principal_names:
        return []

    since = _last_check_timestamp(tenant)
    seen_event_ids = set(_tracked_event_ids(tenant)) | _existing_usage_event_ids(
        db=db,
        tenant_id=tenant.id,
    )
    events = sign_in_events
    if events is None:
        try:
            events = await fetch_break_glass_signin_events(
                db=db,
                tenant=tenant,
                since=since,
                break_glass_user_principal_names=break_glass_user_principal_names,
            )
        except GraphAPIError as exc:
            logger.error(
                "break_glass_signin_fetch_failed tenant_id=%s error=%s",
                tenant.id,
                str(exc),
            )
            return []

    filtered_events = extract_break_glass_signin_events(
        events=events,
        break_glass_user_ids=break_glass_user_ids,
        break_glass_user_principal_names=break_glass_user_principal_names,
        since=since,
        seen_event_ids=seen_event_ids,
    )
    if not filtered_events:
        asset_flags = dict(getattr(tenant, "asset_flags", None) or {})
        asset_flags["break_glass_last_signin_check"] = _format_datetime(utc_now())
        tenant.asset_flags = asset_flags
        await _maybe_commit(db)
        return []

    alerts = []
    latest_seen = since
    tracked_event_ids = _tracked_event_ids(tenant)

    for event in filtered_events:
        if _persist_usage_event(db=db, tenant=tenant, event=event) is None:
            continue
        _persist_usage_finding(db=db, tenant=tenant, event=event)
        payload = build_break_glass_usage_alert(event)
        alerts.append(
            await create_alert(
                db,
                tenant_id=tenant.id,
                alert_type=payload["type"],
                severity=payload["severity"],
                message=payload["message"],
                details=payload["details"],
            )
        )
        created_at = _parse_datetime(event.get("createdDateTime"))
        if created_at is not None and created_at > latest_seen:
            latest_seen = created_at
        event_id = event.get("id")
        if isinstance(event_id, str) and event_id:
            tracked_event_ids.append(event_id)

    asset_flags = dict(getattr(tenant, "asset_flags", None) or {})
    asset_flags["break_glass_used"] = True
    asset_flags["break_glass_last_signin_check"] = _format_datetime(latest_seen)
    asset_flags["break_glass_signin_event_ids"] = tracked_event_ids[-MAX_TRACKED_EVENT_IDS:]
    asset_flags["break_glass_last_event_id"] = (
        tracked_event_ids[-1] if tracked_event_ids else asset_flags.get("break_glass_last_event_id")
    )
    tenant.asset_flags = asset_flags
    await _maybe_commit(db)
    return alerts
