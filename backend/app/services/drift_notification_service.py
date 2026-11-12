"""Drift & Regression Notification Service.

Creates durable, tenant-scoped DriftNotification records when a verified
control regresses to DRIFT_DETECTED. Provides query and acknowledgement
functions for the REST API layer.

All DB functions require an explicit tenant_id filter — never trust an
ID alone to scope queries (zero-trust multi-tenant invariant).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.drift_notification import DriftNotification
from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
from app.services.baseline.baseline_definition import BASELINE_CONTROL_DEFINITIONS
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}

# ---------------------------------------------------------------------------
# Pure helper functions — no DB access, fully unit-testable
# ---------------------------------------------------------------------------


def _derive_severity(compliance_severity: str | None) -> str:
    """Map ComplianceResult.severity to notification_severity.

    Falls back to HIGH (safe default) for any unrecognised value.
    """
    if compliance_severity in _VALID_SEVERITIES:
        return compliance_severity
    return "HIGH"


def _derive_insurance_impact(notification_severity: str) -> tuple[bool, bool]:
    """Return (affects_readiness_score, affects_underwriting_evidence).

    CRITICAL/HIGH → both True (material to underwriting evidence).
    MEDIUM → readiness score affected but not underwriting evidence.
    Unknown → (True, True) — err on the side of inclusion.
    """
    if notification_severity == "MEDIUM":
        return True, False
    return True, True


def _derive_confidence_tier(previous_status: str) -> str:
    """Map predecessor verification status to carrier confidence tier label.

    VERIFIED_CONFIRMED → Tier A (highest).
    Anything else (VERIFIED_PROVISIONAL) → Tier B.
    """
    if previous_status == "VERIFIED_CONFIRMED":
        return "A"
    return "B"


def _build_summary(control_id: str, previous_status: str, drift_count: int) -> str:
    """Build a jargon-free operator-readable summary.

    Never exposes internal status strings (VERIFIED_CONFIRMED, DRIFT_DETECTED,
    Graph API, etc.) in the output — this text is operator-facing.
    drift_count is the value BEFORE this drift event (i.e. prior regression count).
    """
    title = BASELINE_CONTROL_DEFINITIONS.get(control_id, {}).get("title", control_id)
    confidence_phrase = "confirmed secure" if previous_status == "VERIFIED_CONFIRMED" else "reported as secure"

    if drift_count == 0:
        return (
            f"{title} ({control_id}) was previously {confidence_phrase} "
            f"but has since regressed. This is the first regression detected for this control."
        )
    total_regressions = drift_count + 1
    return (
        f"{title} ({control_id}) was previously {confidence_phrase} "
        f"but has regressed again. This control has regressed {total_regressions} times."
    )


# ---------------------------------------------------------------------------
# DB functions
# ---------------------------------------------------------------------------


def create_drift_notification(
    db: Session,
    *,
    verification: RemediationVerification,
    event: VerificationEvent,
    compliance_result: ComplianceResult,
) -> DriftNotification:
    """Create a DriftNotification for a DRIFT_DETECTED transition.

    Must be called from within an active transaction — does NOT flush or
    commit. The caller (lifecycle_store) owns transaction boundaries.

    is_repeat_drift reflects compliance_result.drift_count at call time,
    which is the count BEFORE lifecycle.py increments it for this drift.
    """
    severity = _derive_severity(compliance_result.severity)
    affects_readiness, affects_underwriting = _derive_insurance_impact(severity)
    previous_status = event.previous_status or "VERIFIED_PROVISIONAL"
    confidence_tier = _derive_confidence_tier(previous_status)
    drift_count = compliance_result.drift_count or 0
    is_repeat = drift_count > 0
    summary = _build_summary(compliance_result.control_id, previous_status, drift_count)

    notification = DriftNotification(
        tenant_id=verification.tenant_id,
        compliance_result_id=compliance_result.id,
        verification_id=str(verification.id),
        verification_event_id=str(event.id),
        control_id=compliance_result.control_id,
        notification_severity=severity,
        is_repeat_drift=is_repeat,
        previous_status=previous_status,
        affects_readiness_score=affects_readiness,
        affects_underwriting_evidence=affects_underwriting,
        confidence_tier_before=confidence_tier,
        summary=summary,
        acknowledged=False,
    )
    db.add(notification)
    return notification


def acknowledge_notification(
    db: Session,
    *,
    notification_id: str,
    tenant_id: str,
    acknowledged_by: str,
) -> Optional[DriftNotification]:
    """Mark a notification as acknowledged.

    Always filters by (id, tenant_id) — never by id alone. Returns None when
    the notification is not found or belongs to a different tenant (caller
    raises 404; using 404 rather than 403 avoids leaking record existence).

    Idempotent: re-acknowledging an already-acknowledged record updates
    acknowledged_by and acknowledged_at to the latest values.
    """
    notification = (
        db.query(DriftNotification)
        .filter(
            DriftNotification.id == notification_id,
            DriftNotification.tenant_id == tenant_id,
        )
        .one_or_none()
    )
    if notification is None:
        return None

    notification.acknowledged = True
    notification.acknowledged_at = utc_now()
    notification.acknowledged_by = acknowledged_by
    return notification


def list_notifications(
    db: Session,
    *,
    tenant_id: str,
    include_acknowledged: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> list[DriftNotification]:
    """List drift notifications for a tenant, newest first.

    By default returns only unacknowledged notifications. When
    include_acknowledged=True, also includes notifications acknowledged
    within the last 7 days (so recently-resolved items stay visible).

    Always scoped to tenant_id.
    """
    query = db.query(DriftNotification).filter(DriftNotification.tenant_id == tenant_id)

    if not include_acknowledged:
        query = query.filter(DriftNotification.acknowledged == False)  # noqa: E712
    else:
        cutoff = utc_now() - timedelta(days=7)
        query = query.filter(
            (DriftNotification.acknowledged == False)  # noqa: E712
            | (DriftNotification.acknowledged_at >= cutoff)
        )

    return query.order_by(DriftNotification.created_at.desc()).offset(offset).limit(limit).all()


def get_summary(db: Session, *, tenant_id: str) -> dict:
    """Return unacknowledged notification counts grouped by severity.

    Returns: {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "total_unacknowledged": N}
    All missing severity levels default to 0.
    """
    rows = (
        db.query(
            DriftNotification.notification_severity,
            func.count(DriftNotification.id).label("cnt"),
        )
        .filter(
            DriftNotification.tenant_id == tenant_id,
            DriftNotification.acknowledged == False,  # noqa: E712
        )
        .group_by(DriftNotification.notification_severity)
        .all()
    )

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for severity, cnt in rows:
        if severity in counts:
            counts[severity] = cnt

    counts["total_unacknowledged"] = sum(counts[s] for s in ("CRITICAL", "HIGH", "MEDIUM"))
    return counts
