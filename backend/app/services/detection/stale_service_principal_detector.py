"""Detector for IDENTITY_STALE_SERVICE_PRINCIPAL.

A service principal is considered stale when it is enabled AND has not
authenticated in more than STALE_THRESHOLD_DAYS days (or has no recorded
sign-in activity, which indicates it was never used).

Service principals that are already disabled are skipped — they are not
an active risk and disabling them again would be a no-op.

Data requirement: the calling tenant must have AuditLog.Read.All permission
so that signInActivity is populated on servicePrincipal objects. Tenants
without this permission receive an empty signInActivity; those SPs are
included in findings because an absent sign-in record is treated as
never-authenticated (worst-case assumption).

Graph endpoint: GET /servicePrincipals?$select=id,displayName,appId,
    appDisplayName,accountEnabled,signInActivity&$expand=owners($select=id,displayName,userPrincipalName)
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

STALE_THRESHOLD_DAYS = 90


def _parse_graph_datetime(dt_str: str | None) -> datetime | None:
    if not isinstance(dt_str, str) or not dt_str:
        return None
    try:
        # Graph returns ISO 8601 with Z suffix.
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def evaluate_stale_service_principals(
    service_principals: list[dict],
    *,
    owners_map: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """Return one finding per stale or never-authenticated enabled service principal.

    Each finding dict contains:
        control_id, severity, passed, resource_type, resource_id, evidence

    evidence keys: sp_id, display_name, app_id, last_sign_in, days_inactive,
                   owners, stale, never_authenticated
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=STALE_THRESHOLD_DAYS)
    _owners_map = owners_map or {}
    findings: list[dict] = []
    for sp in service_principals:
        if not isinstance(sp, dict):
            continue
        if not sp.get("accountEnabled", True):
            continue  # already disabled — not an active risk
        sp_id = sp.get("id")
        if not sp_id:
            continue
        sign_in_activity = sp.get("signInActivity") or {}
        last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
        last_sign_in = _parse_graph_datetime(last_sign_in_str)
        is_stale = last_sign_in is None or last_sign_in < cutoff
        display_name = sp.get("displayName")
        app_id = sp.get("appId")
        owners = _owners_map.get(sp_id, [])
        if not is_stale:
            findings.append(
                {
                    "control_id": "IDENTITY_STALE_SERVICE_PRINCIPAL",
                    "severity": "MEDIUM",
                    "passed": True,
                    "resource_type": "SERVICE_PRINCIPAL",
                    "resource_id": sp_id,
                    "evidence": {
                        "sp_id": sp_id,
                        "display_name": display_name,
                        "displayName": display_name,
                        "app_id": app_id,
                        "appId": app_id,
                        "last_sign_in": last_sign_in_str,
                        "owners": owners,
                        "stale": False,
                    },
                }
            )
            continue
        days_inactive = (datetime.now(tz=timezone.utc) - last_sign_in).days if last_sign_in is not None else None
        findings.append(
            {
                "control_id": "IDENTITY_STALE_SERVICE_PRINCIPAL",
                "severity": "MEDIUM",
                "passed": False,
                "resource_type": "SERVICE_PRINCIPAL",
                "resource_id": sp_id,
                "evidence": {
                    "sp_id": sp_id,
                    "display_name": display_name,
                    "displayName": display_name,
                    "app_id": app_id,
                    "appId": app_id,
                    "last_sign_in": last_sign_in_str,
                    "days_inactive": days_inactive,
                    "owners": owners,
                    "stale": True,
                    "never_authenticated": last_sign_in is None,
                },
            }
        )
    return findings
