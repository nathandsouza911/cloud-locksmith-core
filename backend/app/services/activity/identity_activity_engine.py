from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.config import settings

try:
    MEDIUM_DAYS: int = settings.DORMANT_DAYS
except AttributeError:
    MEDIUM_DAYS = 60

try:
    HIGH_DAYS: int = settings.UNUSED_ACCOUNT_HIGH_DAYS
except AttributeError:
    HIGH_DAYS = 90


def _parse_signin(user: dict) -> datetime | None:
    activity = user.get("signInActivity")
    if not isinstance(activity, dict):
        return None
    raw = activity.get("lastSignInDateTime")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _days_since(ts: datetime | None, now: datetime) -> float:
    if ts is None:
        return float("inf")
    return (now - ts).total_seconds() / 86400.0


def _activity_score(days: float) -> int:
    if days <= 30:
        return 100
    if days >= 90:
        return 0
    return int(round((90 - days) / 60.0 * 100))


def score_activity(
    user: dict,
    workload_activity: dict[str, Any] | None,
    *,
    workload_available: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Pure activity profile. No I/O. See Identity Activity Engine spec §5."""
    now = _as_aware(now) or datetime.now(timezone.utc)

    signin_ts = _as_aware(_parse_signin(user))
    signin_available = signin_ts is not None

    workload_matched = workload_activity is not None
    workload_ts: datetime | None = None
    if workload_matched:
        workload_ts = _as_aware(workload_activity.get("last_activity"))

    sources: list[str] = []
    if signin_ts is not None:
        sources.append("signin")
    if workload_matched:
        if workload_activity.get("exchange_activity"):
            sources.append("exchange")
        if workload_activity.get("non_email_activity"):
            sources.append("workload")

    candidates = [ts for ts in (signin_ts, workload_ts) if ts is not None]
    last_activity = max(candidates) if candidates else None

    identity_active = _days_since(signin_ts, now) < MEDIUM_DAYS
    workload_active = (
        workload_matched
        and bool(workload_activity.get("workload_activity"))
        and _days_since(workload_ts, now) < MEDIUM_DAYS
    )

    days_since_last = _days_since(last_activity, now)
    workload_evaluated = workload_available and workload_matched
    confidence = "high" if workload_evaluated else "low"

    # Tier decision — precedence order (spec §5.5)
    if identity_active:
        tier = "ACTIVE"
    elif workload_active:
        tier = "INFO"
    elif days_since_last >= HIGH_DAYS and workload_evaluated:
        tier = "HIGH"
    else:
        tier = "MEDIUM"

    return {
        "user_id": user.get("id"),
        "activity_score": _activity_score(days_since_last),
        "last_activity": last_activity.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if last_activity is not None
        else None,
        "activity_sources": sources,
        "tier": tier,
        "confidence": confidence,
        "identity_active": identity_active,
        "workload_active": workload_active,
        "workload_data_available": bool(workload_available),
        "signin_activity_available": bool(signin_available),
    }
