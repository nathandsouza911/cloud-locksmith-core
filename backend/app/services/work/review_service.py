"""Review decision persistence — Sprint 2.

Append-only. Recording a decision for a resource that already has one writes a
new row and marks the previous row superseded, so the full history of what was
decided, by whom and when survives. Nothing is ever overwritten.

Tenant isolation: every read and every supersession lookup is filtered on
``tenant_id``. One tenant's review can never supersede another's — enforced by
``test_one_tenants_review_never_supersedes_anothers``.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.services.work.evidence_fingerprint import fingerprint_finding
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)

# Key identifying a reviewable resource within a workflow.
DecisionKey = tuple[str, str]


class InvalidDecisionError(ValueError):
    """Raised when an unsupported decision value is submitted."""


def _validate(decision: str, reviewed_by: str) -> None:
    if decision not in ReviewDecision.ALL:
        raise InvalidDecisionError(
            f"Unsupported decision {decision!r}. " f"Expected one of: {', '.join(sorted(ReviewDecision.ALL))}"
        )
    if not (reviewed_by or "").strip():
        raise ValueError("reviewed_by is required — a decision must have an owner")


def _find_active(
    db: Session,
    *,
    tenant_id: str,
    workflow_type: str,
    control_id: str,
    resource_id: str,
) -> WorkflowReviewDecision | None:
    return (
        db.query(WorkflowReviewDecision)
        .filter(
            WorkflowReviewDecision.tenant_id == tenant_id,
            WorkflowReviewDecision.workflow_type == workflow_type,
            WorkflowReviewDecision.control_id == control_id,
            WorkflowReviewDecision.resource_id == resource_id,
            WorkflowReviewDecision.superseded_at.is_(None),
        )
        .one_or_none()
    )


def record_review_decision(
    db: Session,
    *,
    tenant_id: str,
    workflow_type: str,
    control_id: str,
    resource_type: str,
    resource_id: str,
    decision: str,
    reviewed_by: str,
    evidence_hash: str,
    reason: str | None = None,
    workflow_run_id=None,
) -> WorkflowReviewDecision:
    """Record a review decision, superseding any existing active one.

    ``workflow_run_id`` attributes the decision to the run it was made inside
    (Sprint 4). It is optional and stays optional: decisions predating the
    runtime have none, and review memory does not depend on it.
    """
    _validate(decision, reviewed_by)

    # Three phases, in this order, because the unique slot must be freed before
    # the replacement can be inserted, and the self-FK cannot be set until it
    # exists. Reordering these will fail on the partial unique index or the FK.
    #
    #   1. Retire the current decision  (UPDATE — frees the unique slot)
    #   2. Insert the replacement       (INSERT — slot is now free)
    #   3. Link old -> new              (UPDATE — FK target now exists)
    previous = _find_active(
        db,
        tenant_id=tenant_id,
        workflow_type=workflow_type,
        control_id=control_id,
        resource_id=resource_id or "",
    )
    if previous is not None:
        previous.superseded_at = utc_now()
        db.flush()

    entry = WorkflowReviewDecision(
        tenant_id=tenant_id,
        workflow_type=workflow_type,
        control_id=control_id,
        resource_type=resource_type or "TENANT",
        resource_id=resource_id or "",
        decision=decision,
        reason=reason,
        reviewed_by=reviewed_by,
        evidence_hash=evidence_hash,
        workflow_run_id=workflow_run_id,
    )
    db.add(entry)
    db.flush()

    if previous is not None:
        previous.superseded_by = entry.id

    db.commit()
    db.refresh(entry)

    logger.info(
        "review_decision_recorded tenant_id=%s workflow=%s control=%s resource=%s decision=%s",
        tenant_id,
        workflow_type,
        control_id,
        resource_id,
        decision,
    )
    return entry


def record_review_for_finding(
    db: Session,
    *,
    finding,
    workflow_type: str,
    decision: str,
    reviewed_by: str,
    reason: str | None = None,
    workflow_run_id=None,
) -> WorkflowReviewDecision:
    """Record a decision against a ComplianceResult, fingerprinting its evidence.

    The fingerprint is captured at review time. The decision remains valid only
    while the finding continues to hash to this value.
    """
    return record_review_decision(
        db,
        tenant_id=finding.tenant_id,
        workflow_type=workflow_type,
        control_id=finding.control_id,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        decision=decision,
        reviewed_by=reviewed_by,
        evidence_hash=fingerprint_finding(finding),
        reason=reason,
        workflow_run_id=workflow_run_id,
    )


def get_active_decisions(
    db: Session,
    *,
    tenant_id: str,
    workflow_type: str | None = None,
) -> dict[DecisionKey, WorkflowReviewDecision]:
    """Active decisions for a tenant, keyed by ``(control_id, resource_id)``.

    ``workflow_type`` is optional so a caller can load every active decision for
    a tenant in one query — the work queue does this to avoid N queries across
    its workflow groups.
    """
    query = db.query(WorkflowReviewDecision).filter(
        WorkflowReviewDecision.tenant_id == tenant_id,
        WorkflowReviewDecision.superseded_at.is_(None),
    )
    if workflow_type is not None:
        query = query.filter(WorkflowReviewDecision.workflow_type == workflow_type)

    return {(entry.control_id, entry.resource_id): entry for entry in query.all()}


def get_decision_history(
    db: Session,
    *,
    tenant_id: str,
    workflow_type: str,
    control_id: str,
    resource_id: str,
) -> list[WorkflowReviewDecision]:
    """Full decision history for one resource, newest first."""
    return (
        db.query(WorkflowReviewDecision)
        .filter(
            WorkflowReviewDecision.tenant_id == tenant_id,
            WorkflowReviewDecision.workflow_type == workflow_type,
            WorkflowReviewDecision.control_id == control_id,
            WorkflowReviewDecision.resource_id == resource_id,
        )
        .order_by(WorkflowReviewDecision.reviewed_at.desc(), WorkflowReviewDecision.created_at.desc())
        .all()
    )
