from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.services.activity.identity_activity_engine import HIGH_DAYS, MEDIUM_DAYS, score_activity

logger = logging.getLogger(__name__)

SERVICE_KEYWORDS = ["svc", "service", "bot", "automation"]

# Tier -> (passed, severity, decision_status)
_TIER_MAP = {
    "ACTIVE": (True, "LOW", "RESOLVED"),
    "INFO": (True, "INFO", "RESOLVED"),
    "MEDIUM": (False, "MEDIUM", "PENDING"),
    "HIGH": (False, "HIGH", "PENDING"),
}


def _base_evidence(user: dict) -> dict:
    return {
        "user_id": user.get("id"),
        "user_principal_name": user.get("userPrincipalName"),
        "display_name": user.get("displayName"),
        "roles": user.get("roles", []),
        "account_enabled": user.get("accountEnabled"),
    }


def _skip(user: dict, reason: str, **extra) -> dict:
    return {
        "passed": True,
        "severity": "LOW",
        "decision_status": "RESOLVED",
        "evidence": {**_base_evidence(user), "reason": reason, "method": f"skipped_{reason}", **extra},
    }


def _parse_created(raw) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def evaluate_unused_account(
    user: dict,
    workload_activity: dict[str, Any] | None,
    *,
    workload_available: bool,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)

    if user.get("is_break_glass"):
        return _skip(user, "break_glass_account", is_break_glass=True)
    if user.get("accountEnabled") is False:
        return _skip(user, "disabled_account")

    upn = (user.get("userPrincipalName") or "").lower()
    display = (user.get("displayName") or "").lower()
    if "#ext#" in upn:
        return _skip(user, "guest_account")
    # Only the local part: a keyword in the domain ("contoso-services.com")
    # would skip every user in the tenant.
    local_part = upn.split("@", 1)[0]
    if any(keyword in local_part or keyword in display for keyword in SERVICE_KEYWORDS):
        return _skip(user, "service_account")

    created_raw = user.get("createdDateTime")
    if not created_raw:
        profile = score_activity(user, workload_activity, workload_available=workload_available, now=now)
        passed, severity, decision_status = _TIER_MAP[profile["tier"]]
        return {
            "passed": passed,
            "severity": severity,
            "decision_status": decision_status,
            "evidence": {
                **_base_evidence(user),
                "reason": "missing_created_date",
                "method": "missing_createdDateTime",
                **profile,
            },
        }

    created_at = _parse_created(created_raw)
    age_days = (now - created_at).total_seconds() / 86400 if created_at else None
    # An account cannot have been unused for longer than it has existed.
    if age_days is not None and age_days < MEDIUM_DAYS:
        return _skip(user, "new_account", account_age_days=int(age_days))

    profile = score_activity(user, workload_activity, workload_available=workload_available, now=now)
    if profile["tier"] == "HIGH" and age_days is not None and age_days < HIGH_DAYS:
        profile = {**profile, "tier": "MEDIUM"}
    passed, severity, decision_status = _TIER_MAP[profile["tier"]]

    logger.info(
        "unused_account_evaluated user_id=%s tier=%s confidence=%s identity_active=%s "
        "workload_active=%s workload_available=%s",
        user.get("id"),
        profile["tier"],
        profile["confidence"],
        profile["identity_active"],
        profile["workload_active"],
        workload_available,
    )

    return {
        "passed": passed,
        "severity": severity,
        "decision_status": decision_status,
        "evidence": {**_base_evidence(user), **profile},
    }
