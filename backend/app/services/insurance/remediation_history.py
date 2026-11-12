"""Remediation History — evidence of completed, rollback-safe remediations.

Pure transform (`rows_to_remediation_history`) + thin tenant-scoped DB wrapper
(`build_remediation_history`). Renders the 6-column underwriting table:
Control | Previous Status | Action Taken | Remediation Date | Current Status | Rollback Available
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session

from app.db.models.remediation_audit import RemediationAuditLog
from app.services.insurance.verification_language import get_remediation_row_label

import logging

logger = logging.getLogger(__name__)

EMPTY_MESSAGE = "No remediations were completed during the reporting period."

# control_id -> plain-language action shown to insurers.
_ACTION_PHRASES = {
    "IDENTITY_ADMIN_NO_MFA": "Enforced MFA on privileged accounts",
    "IDENTITY_USER_NO_MFA": "Enforced MFA on user accounts",
    "IDENTITY_OVERPRIVILEGED_USER": "Reduced over-privileged administrative rights",
    "IDENTITY_ADMIN_COUNT_EXCESS": "Reduced the Global Administrator population",
    "IDENTITY_USER_CONSENT_POLICY": "Restricted user application-consent",
    "IDENTITY_GUEST_INVITES_OPEN": "Tightened external guest-invitation controls",
    "IDENTITY_UNUSED_ACCOUNT": "Disabled or removed an unused account",
    "IDENTITY_BREAK_GLASS_ACCOUNT": "Hardened break-glass account configuration",
    "IDENTITY_ILLICIT_CONSENT_GRANTS": "Revoked unauthorized OAuth application consent grants",
}

_GENERIC_ACTION = "Applied identity control remediation"

# Controls whose remediation is reversible via Cloud Locksmith rollback.
_ROLLBACK_CAPABLE = set(_ACTION_PHRASES.keys())

# Execution audit rows that represent a completed remediation. A successful
# execution is stored with execution_status "EXECUTED"
# (remediation_audit_service._event_log_fields); a later rollback mutates that
# same row's execution_status to "ROLLED_BACK" (remediation_rollback). Both must
# appear in the underwriting history (the latter rendered as "Reversed").
# NOTE: the previous filter looked for "completed", a value nothing ever writes,
# so the history table was always empty.
_COMPLETED_EXECUTION_STATUSES = ("EXECUTED", "ROLLED_BACK")


def _format_date(value: datetime | None) -> str:
    return value.strftime("%d %B %Y") if value else "N/A"


def rows_to_remediation_history(
    audit_rows,
    *,
    current_state: dict[str, bool],
    verification_states: dict | None = None,
) -> dict:
    """Transform RemediationAuditLog-like rows into table rows.

    audit_rows: iterable of objects with control_id, executed_at, verified_at,
                rolled_back.
    current_state: control_id -> bool (current passed state from ComplianceResult).
    verification_states: optional dict of control_id -> RemediationVerification-like
                         object (must have .status and .verification_count attributes).
                         When None, verification fields default to scan-only values.
    """
    rows: list[dict] = []
    for audit in audit_rows:
        control_id = audit.control_id
        date_value = audit.verified_at or audit.executed_at
        current_passed = current_state.get(control_id, False)

        if audit.rolled_back:
            rollback = "Reversed"
        elif control_id in _ROLLBACK_CAPABLE:
            rollback = "Available"
        else:
            rollback = "—"  # em dash

        # Verification fields (Phase D). Default to scan-only values when no lifecycle data.
        vr = (verification_states or {}).get(control_id)
        v_status_raw = getattr(vr, "status", None) if vr else None
        v_count = getattr(vr, "verification_count", 0) if vr else 0
        is_drift = v_status_raw == "DRIFT_DETECTED"
        v_label = get_remediation_row_label(
            verification_status=v_status_raw,
            is_drifted=is_drift,
        )

        row = {
            "control_id": control_id,
            "previous_status": "Fail",
            "action_taken": _ACTION_PHRASES.get(control_id, _GENERIC_ACTION),
            "remediation_date": _format_date(date_value),
            "current_status": "Pass" if current_passed else "Fail",
            "rollback_available": rollback,
            "verification_status": v_label,
            "verification_count": v_count,
            "drift_detected": is_drift,
        }
        rows.append(row)

    return {"rows": rows, "empty_message": EMPTY_MESSAGE if not rows else ""}


def build_remediation_history(
    db: Session,
    *,
    tenant_id: str,
    window_days: int,
    current_state: dict[str, bool],
) -> dict:
    """Tenant-scoped query for completed remediations in the reporting window.

    Most-recent first; one row per control (the latest successful remediation).
    Guards against a missing/incompatible table so the report still renders.
    """
    window_start = datetime.now(timezone.utc) - timedelta(days=window_days)
    try:
        audit_rows = (
            db.query(RemediationAuditLog)
            .filter(
                RemediationAuditLog.tenant_id == tenant_id,
                RemediationAuditLog.execution_status.in_(_COMPLETED_EXECUTION_STATUSES),
                RemediationAuditLog.created_at >= window_start,
            )
            .order_by(RemediationAuditLog.created_at.desc())
            .all()
        )
    except (OperationalError, ProgrammingError):
        logger.warning(
            "remediation_history: RemediationAuditLog query failed for tenant_id=%s; "
            "rendering empty remediation history",
            tenant_id,
        )
        audit_rows = []

    # One row per control — keep the most recent.
    seen: set[str] = set()
    deduped = []
    for audit in audit_rows:
        if audit.control_id in seen:
            continue
        seen.add(audit.control_id)
        deduped.append(audit)

    # Fetch verification lifecycle states for the controls that will be shown.
    # Fail open — missing verification data must not break the history report.
    from app.services.insurance.verification_coverage import get_verification_states_for_controls

    control_ids = list({row.control_id for row in deduped})
    verification_states: dict = {}
    try:
        verification_states = get_verification_states_for_controls(db, tenant_id=tenant_id, control_ids=control_ids)
    except Exception:
        pass

    return rows_to_remediation_history(
        deduped,
        current_state=current_state,
        verification_states=verification_states,
    )
