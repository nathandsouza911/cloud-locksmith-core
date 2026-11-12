"""Detection logic for IDENTITY_APP_SECRET_EXPIRING_SOON.

Pure functions only — no DB, no Graph. The scanner in identity_scan_service.py
supplies the app registration objects.

Checks passwordCredentials and keyCredentials on each app registration.
An app is flagged if any credential has already expired or will expire within
the threshold (default 90 days).

Severity tiers per credential:
    CRITICAL  — already expired (outage risk or active security gap)
    HIGH      — expires within 7 days
    MEDIUM    — expires within 30 days
    LOW       — expires within 90 days

The overall severity for a finding equals the worst-case tier across all
flagged credentials on that app.

This is a scan-only control (MANUAL, no auto-remediation).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


_DEFAULT_EXPIRY_THRESHOLD_DAYS = 90

_TIER_CRITICAL_DAYS = 0  # already expired
_TIER_HIGH_DAYS = 7
_TIER_MEDIUM_DAYS = 30
_TIER_LOW_DAYS = 90

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.rstrip("Z"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _severity_for_days(days_remaining: int, already_expired: bool) -> str:
    if already_expired or days_remaining < 0:
        return "CRITICAL"
    if days_remaining <= _TIER_HIGH_DAYS:
        return "HIGH"
    if days_remaining <= _TIER_MEDIUM_DAYS:
        return "MEDIUM"
    return "LOW"


def _worst_severity(severities: list[str]) -> str:
    for tier in _SEVERITY_ORDER:
        if tier in severities:
            return tier
    return "LOW"


def _check_credential(cred: dict, now: datetime, threshold: timedelta) -> dict | None:
    """Return a summary dict if the credential is expiring soon or already expired, else None."""
    end_dt = _parse_dt(cred.get("endDateTime"))
    if end_dt is None:
        return None
    remaining = end_dt - now
    days_remaining = int(remaining.total_seconds() // 86400)
    already_expired = remaining.total_seconds() < 0
    expiring_soon = 0 <= remaining.total_seconds() <= threshold.total_seconds()
    if not (already_expired or expiring_soon):
        return None
    severity = _severity_for_days(days_remaining, already_expired)
    return {
        "credential_type": cred.get("@odata.type", "passwordCredential").split(".")[-1],
        "key_id": cred.get("keyId"),
        "display_name": cred.get("displayName"),
        "end_date_time": cred.get("endDateTime"),
        "days_remaining": days_remaining,
        "already_expired": already_expired,
        "severity": severity,
    }


def evaluate_app_secret_expiry(
    app: dict,
    *,
    now: datetime | None = None,
    threshold_days: int = _DEFAULT_EXPIRY_THRESHOLD_DAYS,
) -> dict | None:
    """Evaluate a single app registration for expiring credentials.

    Returns a finding dict if any credential is expiring soon or already expired,
    else None (meaning the app passes the check).
    """
    now = now or datetime.now(timezone.utc)
    threshold = timedelta(days=threshold_days)

    app_id = app.get("id")
    app_display_name = app.get("displayName")
    client_id = app.get("appId")

    expiring: list[dict] = []
    for cred in app.get("passwordCredentials") or []:
        summary = _check_credential(cred, now, threshold)
        if summary:
            expiring.append(summary)
    for cred in app.get("keyCredentials") or []:
        summary = _check_credential(cred, now, threshold)
        if summary:
            expiring.append(summary)

    if not expiring:
        return None

    already_expired_count = sum(1 for c in expiring if c["already_expired"])
    min_days = min(c["days_remaining"] for c in expiring)
    worst_severity = _worst_severity([c["severity"] for c in expiring])

    # Breakdown by tier for carrier evidence
    severity_counts = {s: 0 for s in _SEVERITY_ORDER}
    for c in expiring:
        severity_counts[c["severity"]] += 1

    return {
        "passed": False,
        "severity": worst_severity,
        "resource_id": app_id,
        "evidence": {
            "app_id": app_id,
            "app_display_name": app_display_name,
            "client_id": client_id,
            "expiring_credentials": expiring,
            "expiring_count": len(expiring),
            "already_expired_count": already_expired_count,
            "min_days_remaining": min_days,
            "worst_severity": worst_severity,
            "severity_counts": severity_counts,
            "threshold_days": threshold_days,
        },
    }


def evaluate_all_app_secret_expiry(
    apps: list[dict],
    *,
    now: datetime | None = None,
    threshold_days: int = _DEFAULT_EXPIRY_THRESHOLD_DAYS,
) -> list[dict]:
    """Evaluate all app registrations and return findings for those with expiring credentials."""
    now = now or datetime.now(timezone.utc)
    findings = []
    for app in apps:
        result = evaluate_app_secret_expiry(app, now=now, threshold_days=threshold_days)
        if result is not None:
            findings.append(result)
    return findings


def aggregate_app_secret_severity(findings: list[dict]) -> str:
    """Return the worst severity across all per-app findings.

    Used by the scanner to set the overall control severity for carrier evidence.
    Returns 'HIGH' when there are no findings (control passes).
    """
    if not findings:
        return "HIGH"
    return _worst_severity([f["severity"] for f in findings])
