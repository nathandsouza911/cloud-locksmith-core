"""Verification coverage metrics for insurance reporting.

Queries RemediationVerification rows to produce control-level coverage counts
and per-control state lookups suitable for underwriter reports.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from sqlalchemy.orm import Session

from app.db.models.verification_lifecycle import RemediationVerification


@dataclass
class VerificationCoverage:
    controls_evaluated: int  # Distinct controls in the evaluated set (passed from caller)
    controls_remediated: int  # Controls with any RemediationVerification row
    controls_verified_provisional: int  # Status == VERIFIED_PROVISIONAL
    controls_verified_confirmed: int  # Status == VERIFIED_CONFIRMED
    controls_drifted: int  # Status == DRIFT_DETECTED
    controls_failed: int  # Status == FAILED
    drift_event_total: int  # SUM of drift_count across all rows for tenant

    def to_dict(self) -> dict:
        return asdict(self)


def build_verification_coverage(
    db: Session,
    *,
    tenant_id: str,
    control_ids_evaluated: list[str],
) -> VerificationCoverage:
    """Return verification coverage counts for the given evaluated control IDs.

    Only the most recent RemediationVerification row per control_id is used
    for status counts. drift_event_total sums drift_count across ALL rows
    (not just most-recent) to capture full regression history.
    All queries are scoped to tenant_id.
    """
    if not control_ids_evaluated:
        return VerificationCoverage(
            controls_evaluated=0,
            controls_remediated=0,
            controls_verified_provisional=0,
            controls_verified_confirmed=0,
            controls_drifted=0,
            controls_failed=0,
            drift_event_total=0,
        )

    rows: list[RemediationVerification] = (
        db.query(RemediationVerification)
        .filter(
            RemediationVerification.tenant_id == tenant_id,
            RemediationVerification.control_id.in_(control_ids_evaluated),
        )
        .order_by(RemediationVerification.created_at.desc())
        .all()
    )

    # Keep only the most recent status per control_id for status counts.
    latest_by_control: dict[str, str] = {}
    drift_event_total = 0
    for row in rows:
        if row.control_id not in latest_by_control:
            latest_by_control[row.control_id] = row.status
        drift_event_total += getattr(row, "drift_count", 0) or 0

    return VerificationCoverage(
        controls_evaluated=len(control_ids_evaluated),
        controls_remediated=len(latest_by_control),
        controls_verified_provisional=sum(1 for s in latest_by_control.values() if s == "VERIFIED_PROVISIONAL"),
        controls_verified_confirmed=sum(1 for s in latest_by_control.values() if s == "VERIFIED_CONFIRMED"),
        controls_drifted=sum(1 for s in latest_by_control.values() if s == "DRIFT_DETECTED"),
        controls_failed=sum(1 for s in latest_by_control.values() if s == "FAILED"),
        drift_event_total=drift_event_total,
    )


def get_verification_states_for_controls(
    db: Session,
    *,
    tenant_id: str,
    control_ids: list[str],
) -> dict[str, RemediationVerification]:
    """Return the most recent RemediationVerification row per control_id.

    Controls with no verification row are absent from the returned dict.
    All queries are scoped to tenant_id.
    """
    if not control_ids:
        return {}

    rows: list[RemediationVerification] = (
        db.query(RemediationVerification)
        .filter(
            RemediationVerification.tenant_id == tenant_id,
            RemediationVerification.control_id.in_(control_ids),
        )
        .order_by(RemediationVerification.created_at.desc())
        .all()
    )

    result: dict[str, RemediationVerification] = {}
    for row in rows:
        if row.control_id not in result:
            result[row.control_id] = row
    return result
