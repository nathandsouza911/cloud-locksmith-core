"""Legacy authentication usage scan for CA_LEGACY_AUTH_BLOCK.

LegacyAuthUsageScanCheck (BLOCKING):
  Queries the Microsoft Graph sign-in audit logs for the last 30 days,
  filtering for sign-in events using legacy authentication protocols.
  If any usage is found, execution is BLOCKED — enabling the CA block
  policy would immediately break those clients.

  Fail closed: if the sign-in log endpoint is unavailable (403, no
  AuditLog.Read.All permission), execution is BLOCKED rather than
  allowed. Unknown = unsafe.

  Protocols detected (clientAppUsed values):
    - Exchange ActiveSync
    - IMAP4
    - POP3
    - SMTP (SMTP AUTH)

  Returns per-finding: protocol, user_principal_name, timestamp.

LegacyAuthUsageSummaryCheck (NON-BLOCKING):
  Returns usage count and protocol breakdown. Fail-open: unavailability
  produces a PASS with an error note.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from app.services.graph_client import graph_get
from app.services.remediation.preflight.base import PreFlightCheck, PreFlightResult

logger = logging.getLogger(__name__)

# Legacy clientAppUsed values in the Graph sign-in log API.
# Source: https://learn.microsoft.com/en-us/graph/api/signin-list
_LEGACY_CLIENT_APP_USED: frozenset[str] = frozenset(
    {
        "Exchange ActiveSync",
        "IMAP4",
        "POP3",
        "SMTP",
    }
)

_LOOKBACK_DAYS = 30
# Cap evidence payload to avoid oversized execution results.
_MAX_FINDINGS_IN_EVIDENCE = 50


def _build_signin_filter(since: datetime) -> str:
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    app_filters = " or ".join(f"clientAppUsed eq '{app}'" for app in sorted(_LEGACY_CLIENT_APP_USED))
    return f"createdDateTime ge {since_str} and ({app_filters})"


async def _fetch_legacy_signins(graph_client) -> list[dict]:
    """Fetch sign-in log entries for legacy auth protocols in the last 30 days.

    Raises PermissionError if the API is inaccessible (fail-closed caller).
    Raises RuntimeError on other unexpected errors.
    Returns [] if no legacy sign-ins detected.
    """
    since = datetime.now(tz=timezone.utc) - timedelta(days=_LOOKBACK_DAYS)
    filter_str = _build_signin_filter(since)
    path = (
        "/auditLogs/signIns"
        f"?$filter={quote(filter_str)}"
        "&$top=100"
        "&$select=createdDateTime,userPrincipalName,clientAppUsed,ipAddress"
    )
    response = await graph_get(graph_client.db, graph_client.tenant, path)
    if isinstance(response, dict) and response.get("status") == "error":
        code = response.get("code") or ""
        reason = response.get("reason") or ""
        raise PermissionError(
            f"Sign-in log access denied (code={code}, reason={reason}). "
            "AuditLog.Read.All permission is required for the legacy auth usage scan."
        )
    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected sign-in log response type: {type(response)}")
    return response.get("value", [])


class LegacyAuthUsageScanCheck(PreFlightCheck):
    check_id = "legacy_auth_usage_scan"
    check_name = "Legacy Authentication Usage Scan"
    blocking = True

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        try:
            signins = await _fetch_legacy_signins(graph_client)
        except PermissionError as exc:
            return self._fail(
                f"Cannot verify legacy auth usage: {exc}. " "Execution blocked until sign-in log access is confirmed.",
                {"reason": "log_access_denied", "detail": str(exc)},
            )
        except Exception as exc:
            return self._fail(
                f"Legacy auth usage scan failed: {type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )

        if not signins:
            return self._pass(
                f"No legacy authentication usage detected in the last " f"{_LOOKBACK_DAYS} days.",
                {"usage_count": 0, "protocols": [], "lookback_days": _LOOKBACK_DAYS},
            )

        protocols_seen: set[str] = set()
        findings: list[dict] = []
        for signin in signins:
            protocol = signin.get("clientAppUsed") or "unknown"
            protocols_seen.add(protocol)
            findings.append(
                {
                    "protocol": protocol,
                    "user": signin.get("userPrincipalName") or "",
                    "timestamp": signin.get("createdDateTime") or "",
                }
            )

        count = len(findings)
        return self._fail(
            f"{count} legacy authentication sign-in(s) detected in the last "
            f"{_LOOKBACK_DAYS} days "
            f"({', '.join(sorted(protocols_seen))}). "
            "Enabling CA_LEGACY_AUTH_BLOCK will immediately break these clients. "
            "Migrate them off legacy auth before proceeding.",
            {
                "usage_count": count,
                "protocols": sorted(protocols_seen),
                "lookback_days": _LOOKBACK_DAYS,
                "findings": findings[:_MAX_FINDINGS_IN_EVIDENCE],
            },
        )


class LegacyAuthUsageSummaryCheck(PreFlightCheck):
    check_id = "legacy_auth_usage_summary"
    check_name = "Legacy Authentication Usage Summary"
    blocking = False

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        try:
            signins = await _fetch_legacy_signins(graph_client)
            protocols: dict[str, int] = {}
            for signin in signins:
                protocol = signin.get("clientAppUsed") or "unknown"
                protocols[protocol] = protocols.get(protocol, 0) + 1
            count = len(signins)
            return self._pass(
                f"Legacy auth usage summary: {count} event(s) across "
                f"{len(protocols)} protocol(s) in the last {_LOOKBACK_DAYS} days.",
                {
                    "usage_count": count,
                    "protocols_breakdown": protocols,
                    "lookback_days": _LOOKBACK_DAYS,
                },
            )
        except Exception as exc:
            return self._pass(
                f"Legacy auth usage summary unavailable: {type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )
