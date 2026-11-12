# app/services/remediation_audit_service.py

import logging
from datetime import datetime
from app.utils.datetime import to_naive_utc, utc_now
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.db.models.remediation_audit import RemediationAuditLog
from app.services.audit.critical_events import (
    AuditPersistenceError,
    is_critical_audit_event,
)

logger = logging.getLogger(__name__)
from app.services.remediation.lifecycle import (
    TransitionEvent,
    current_remediation_status,
    transition,
)
from app.services.remediation.approval_binding import approved_scope


def _safe_explanation(metadata: dict | None):
    return {
        "summary": "Event recorded",
        "factors": metadata or {},
        "risk_note": "",
    }


def _event_log_fields(*, event_type: str, metadata: dict | None) -> dict:
    now = to_naive_utc(utc_now())
    metadata = metadata or {}
    fields: dict = {}
    if event_type == "APPROVED":
        fields["approved"] = True
        fields["approved_at"] = now
        fields["approved_by"] = metadata.get("approved_by", "system")
    elif event_type == "EXECUTED":
        fields["execution_status"] = "EXECUTED"
        fields["executed_at"] = now
    elif event_type in {"FAILED", "BLOCKED"}:
        fields["execution_status"] = event_type
        fields["executed_at"] = now
    elif event_type == "VERIFIED":
        fields["verified"] = True
        fields["verified_at"] = now
    elif event_type == "ACKNOWLEDGED":
        fields["approved"] = True
        fields["approved_at"] = now
        fields["approved_by"] = metadata.get("acknowledged_by", "system")
    return fields


def log_audit_event(
    *,
    db: Session,
    tenant_id: str,
    compliance_result_id: int,
    control_id: str,
    resource_type: str,
    resource_id: str,
    event_type: str,
    confidence: float = 0.0,
    metadata: dict | None = None,
):
    """
    Audit logger with event-criticality-aware failure handling (M3).

    Security-critical events (see ``AUDIT_CRITICAL_EVENTS`` — execution start/
    finish, rollback) raise ``AuditPersistenceError`` if the record cannot be
    persisted, so the caller aborts instead of reporting an unaudited action as
    applied. All other (informational) events remain fail-open and return None.
    """

    explanation = _safe_explanation(metadata)
    event_fields = _event_log_fields(event_type=event_type, metadata=metadata)

    try:
        log = RemediationAuditLog(
            tenant_id=tenant_id,
            compliance_result_id=compliance_result_id,
            control_id=control_id,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=event_type,
            confidence=confidence,
            explanation_summary=explanation["summary"],
            explanation_factors=explanation["factors"],
            explanation_risk_note=explanation["risk_note"],
            **event_fields,
        )

        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    except Exception as exc:
        db.rollback()
        logger.error(
            "remediation_audit_write_failed event_type=%s tenant_id=%s compliance_result_id=%s control_id=%s",
            event_type,
            tenant_id,
            compliance_result_id,
            control_id,
            exc_info=True,
        )
        # Fail closed for security-critical, state-changing events (execution
        # start/finish, rollback): the caller must abort rather than report a
        # remediation as applied without durable evidence. Informational events
        # (previews, blocks, approvals) keep the prior fail-open behaviour.
        if is_critical_audit_event(event_type):
            raise AuditPersistenceError(
                f"Failed to persist critical audit event event_type={event_type} "
                f"tenant_id={tenant_id} compliance_result_id={compliance_result_id}"
            ) from exc
        return None


def mark_remediation_approved(
    *,
    db: Session,
    finding,
    approved_by: str,
    approval_mode: str,
):
    state = current_remediation_status(finding)
    if state == "APPROVED":
        return None

    transition(TransitionEvent.APPROVE, finding)
    approved_at = to_naive_utc(utc_now())

    # H1 — capture the approved scope (server-side, from the finding's own
    # evidence) so execution can be bound to exactly what was approved. For
    # fixed-action controls this records control_id + resource_id only; for
    # variable-payload controls (overprivileged-role removal) it records the
    # role set, enabling drift detection and subset enforcement at execute time.
    _evidence = dict(finding.evidence or {})
    _scope = approved_scope(finding.control_id, finding.resource_id, _evidence)
    _evidence["approved_scope_hash"] = _scope["approved_scope_hash"]
    _evidence["approved_roles"] = _scope["approved_roles"]
    finding.evidence = _evidence

    record = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == finding.id,
            RemediationAuditLog.tenant_id == finding.tenant_id,
            RemediationAuditLog.explanation_summary != "Event recorded",
            RemediationAuditLog.explanation_summary != "Rollback executed",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )
    if record:
        record.approved = True
        record.approved_at = approved_at
        record.approved_by = approved_by

    return log_audit_event(
        db=db,
        tenant_id=finding.tenant_id,
        compliance_result_id=finding.id,
        control_id=finding.control_id,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        event_type="APPROVED",
        confidence=1.0,
        metadata={
            "approved_by": approved_by,
            "approval_mode": approval_mode,
        },
    )


def persist_remediation_decision(
    db: Session,
    tenant_id: str,
    finding,
    decision_result: dict,
):
    explanation = decision_result.get("explanation") or {}

    summary = explanation.get("summary", "No explanation recorded")
    key_factors = explanation.get("key_factors", {})
    risk_note = explanation.get("risk_note", "")

    CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
    confidence_value = CONFIDENCE_MAP.get(decision_result.get("confidence"), 0.0)

    try:
        log = RemediationAuditLog(
            tenant_id=tenant_id,
            compliance_result_id=finding.id,
            control_id=finding.control_id,
            resource_type="USER",
            resource_id=finding.evidence.get("user_id"),
            decision=decision_result["decision"],
            confidence=confidence_value,
            explanation_summary=summary,
            explanation_factors=key_factors,
            explanation_risk_note=risk_note,
        )

        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    except Exception:
        db.rollback()
        raise


def list_remediation_decisions(
    db: Session,
    tenant_id: str,  # tenant_identifier
    limit: int = 50,
    offset: int = 0,
):
    return (
        db.query(RemediationAuditLog)
        .filter(RemediationAuditLog.tenant_id == tenant_id)
        .order_by(RemediationAuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def get_remediation_decision(
    db: Session,
    tenant_id: str,  # tenant_identifier
    decision_id: str,  # UUID string
):
    return (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.id == decision_id,
            RemediationAuditLog.tenant_id == tenant_id,
        )
        .first()
    )


# -------------------------------------------------------------------
# READ: filtered listing
# -------------------------------------------------------------------


def list_remediation_decisions_filtered(
    db: Session,
    tenant_id: str,  # tenant_identifier
    decision: str | None = None,
    approved: bool | None = None,
    execution_status: str | None = None,
    verified: bool | None = None,
    rolled_back: bool | None = None,
    limit: int = 50,
    offset: int = 0,
):
    query = db.query(RemediationAuditLog).filter(RemediationAuditLog.tenant_id == tenant_id)

    if decision is not None:
        query = query.filter(RemediationAuditLog.decision == decision)

    if approved is not None:
        query = query.filter(RemediationAuditLog.approved == approved)

    if execution_status is not None:
        query = query.filter(RemediationAuditLog.execution_status == execution_status)

    if verified is not None:
        query = query.filter(RemediationAuditLog.verified == verified)

    if rolled_back is not None:
        query = query.filter(RemediationAuditLog.rolled_back == rolled_back)

    return query.order_by(RemediationAuditLog.created_at.desc()).limit(limit).offset(offset).all()


# -------------------------------------------------------------------
# STATS: aggregate counts (all time)
# -------------------------------------------------------------------


def remediation_decision_counts(
    db: Session,
    tenant_id: str,  # tenant_identifier
) -> dict:
    row = (
        db.query(
            func.count(RemediationAuditLog.id).label("total"),
            func.sum(
                case(
                    (
                        (RemediationAuditLog.decision == "REQUIRE_APPROVAL")
                        & (RemediationAuditLog.approved.is_(False)),
                        1,
                    ),
                    else_=0,
                )
            ).label("pending_approvals"),
            func.sum(
                case(
                    (RemediationAuditLog.decision == "AUTO_REMEDIATE", 1),
                    else_=0,
                )
            ).label("auto_remediated"),
            func.sum(
                case(
                    (RemediationAuditLog.decision == "BLOCK", 1),
                    else_=0,
                )
            ).label("blocked"),
            func.sum(
                case(
                    (RemediationAuditLog.execution_status == "EXECUTED", 1),
                    else_=0,
                )
            ).label("executed"),
            func.sum(
                case(
                    (RemediationAuditLog.execution_status == "FAILED", 1),
                    else_=0,
                )
            ).label("failed"),
            func.sum(
                case(
                    (RemediationAuditLog.verified.is_(True), 1),
                    else_=0,
                )
            ).label("verified"),
            func.sum(
                case(
                    (RemediationAuditLog.rolled_back.is_(True), 1),
                    else_=0,
                )
            ).label("rolled_back"),
        )
        .filter(RemediationAuditLog.tenant_id == tenant_id)
        .one()
    )

    return {
        "total": row.total or 0,
        "pending_approvals": row.pending_approvals or 0,
        "auto_remediated": row.auto_remediated or 0,
        "blocked": row.blocked or 0,
        "executed": row.executed or 0,
        "failed": row.failed or 0,
        "verified": row.verified or 0,
        "rolled_back": row.rolled_back or 0,
    }


# -------------------------------------------------------------------
# STATS: aggregate counts (time window)
# -------------------------------------------------------------------


def remediation_decision_counts_windowed(
    db: Session,
    tenant_id: str,  # tenant_identifier
    since: datetime,
) -> dict:
    row = (
        db.query(
            func.count(RemediationAuditLog.id).label("total"),
            func.sum(
                case(
                    (
                        (RemediationAuditLog.decision == "REQUIRE_APPROVAL")
                        & (RemediationAuditLog.approved.is_(False)),
                        1,
                    ),
                    else_=0,
                )
            ).label("pending_approvals"),
            func.sum(
                case(
                    (RemediationAuditLog.decision == "AUTO_REMEDIATE", 1),
                    else_=0,
                )
            ).label("auto_remediated"),
            func.sum(
                case(
                    (RemediationAuditLog.decision == "BLOCK", 1),
                    else_=0,
                )
            ).label("blocked"),
            func.sum(
                case(
                    (RemediationAuditLog.execution_status == "EXECUTED", 1),
                    else_=0,
                )
            ).label("executed"),
            func.sum(
                case(
                    (RemediationAuditLog.execution_status == "FAILED", 1),
                    else_=0,
                )
            ).label("failed"),
            func.sum(
                case(
                    (RemediationAuditLog.verified.is_(True), 1),
                    else_=0,
                )
            ).label("verified"),
            func.sum(
                case(
                    (RemediationAuditLog.rolled_back.is_(True), 1),
                    else_=0,
                )
            ).label("rolled_back"),
        )
        .filter(
            RemediationAuditLog.tenant_id == tenant_id,
            RemediationAuditLog.created_at >= to_naive_utc(since),
        )
        .one()
    )

    return {
        "total": row.total or 0,
        "pending_approvals": row.pending_approvals or 0,
        "auto_remediated": row.auto_remediated or 0,
        "blocked": row.blocked or 0,
        "executed": row.executed or 0,
        "failed": row.failed or 0,
        "verified": row.verified or 0,
        "rolled_back": row.rolled_back or 0,
    }


# -------------------------------------------------------------------
