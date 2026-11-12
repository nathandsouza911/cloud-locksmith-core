"""Insurance-grade attestation for archived reports.

An attestation is a structured object describing the key facts of a report
(tenant, type, timestamp, score, hashes) signed with HMAC-SHA256.  It lets
insurers and auditors verify that a report was produced by this system and
has not been altered since it was issued.

The HMAC secret is settings.APP_JWT_SECRET.  The signature covers the full
canonical JSON of the attestation object — the same deterministic serialization
used for content_hash — so any field mutation invalidates the signature.

The secret is NEVER included in any response.
"""

import hashlib
import hmac
from datetime import datetime, timezone

from app.config import settings
from app.db.models.report_payload import ReportPayload

_SYSTEM_VERSION = "cloud-locksmith-v1"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _canonical_json(data: dict) -> str:
    import json

    return json.dumps(data, sort_keys=True, default=str, ensure_ascii=True)


def _extract_controls_summary(report_data: dict) -> dict:
    """Pull a minimal, report-type-agnostic summary from the raw payload."""
    summary: dict = {}

    # Executive summary keys
    for key in ("posture_score", "score_band", "total_findings", "critical_findings"):
        if key in report_data:
            summary[key] = report_data[key]

    # Insurance / evidence report keys nested under "header"
    header = report_data.get("header") or {}
    for key in ("score", "score_band", "total_controls", "passed_controls", "failed_controls"):
        if key in header and key not in summary:
            summary[key] = header[key]

    return summary


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_attestation(report: ReportPayload, report_data: dict) -> dict:
    """Construct the attestation object for a persisted ReportPayload row.

    Must be called after chain_hash has been assigned to the row (i.e. after
    the two-phase write in archive_report) so the attestation covers the
    final chain_hash value.
    """
    attested_at = datetime.now(timezone.utc).replace(tzinfo=None)
    return {
        "report_id": report.id,
        "tenant_id": report.tenant_id,
        "report_type": report.report_type,
        "generated_at": report.generated_at.isoformat() if report.generated_at else None,
        "attested_at": attested_at.isoformat(),
        "score": report.score,
        "content_hash": report.content_hash,
        "chain_hash": report.chain_hash,
        "system_version": _SYSTEM_VERSION,
        "controls_summary": _extract_controls_summary(report_data),
    }


def sign_attestation(attestation: dict) -> str:
    """Return HMAC-SHA256 hex digest of the canonical attestation JSON.

    The signing key is settings.APP_JWT_SECRET.  The digest is 64 hex chars
    (32 bytes).  The secret is not returned or logged.
    """
    serialized = _canonical_json(attestation).encode("utf-8")
    return hmac.new(
        settings.APP_JWT_SECRET.encode("utf-8"),
        serialized,
        hashlib.sha256,
    ).hexdigest()


def verify_attestation_signature(attestation: dict, stored_signature: str) -> bool:
    """Re-derive the signature and compare in constant time.

    Returns True only when the recomputed digest matches stored_signature.
    Use this in the verification endpoint — never roll your own comparison.
    """
    expected = sign_attestation(attestation)
    return hmac.compare_digest(expected, stored_signature)
