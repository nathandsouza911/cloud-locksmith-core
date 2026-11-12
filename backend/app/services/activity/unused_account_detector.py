from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.services.activity.identity_activity_engine import score_activity

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
    if any(keyword in upn or keyword in display for keyword in SERVICE_KEYWORDS):
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

    profile = score_activity(user, workload_activity, workload_available=workload_available, now=now)
    passed, severity, decision_status = _TIER_MAP[profile["tier"]]

    logger.info(
        "unused_account_evaluated upn=%s tier=%s confidence=%s identity_active=%s "
        "workload_active=%s workload_available=%s",
        user.get("userPrincipalName"),
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
