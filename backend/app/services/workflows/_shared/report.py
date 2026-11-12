"""The workflow evidence report — the client-facing artefact.

Built from what actually happened: the review decisions recorded against this
run, the resources still outstanding, and the verification outcome. **Never
directly from findings** — a report must state what was done, not re-derive what
is currently wrong.

Persisted through the existing reporting engine (``archive_report``), so it
inherits content hashing, chain linking and attestation without this module
knowing how any of that works.

Workflow-specific sections enter through an optional ``report_sections`` method
on the workflow's projector; the envelope below is identical for every workflow.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.db.models.workflow_run import WorkflowRun
from app.services.report_archival_service import archive_report
from app.services.work.workflow_registry import WORKFLOW_REGISTRY
from app.services.workflows._shared.projector_registry import get_projector
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)

# Decisions meaning "act on this now" — the ones verification must confirm.
_REMEDIATING = frozenset({ReviewDecision.REVOKE})


def _report_type(workflow_id: str) -> str:
    definition = WORKFLOW_REGISTRY.get(workflow_id)
    declared = getattr(definition, "report_type", "") if definition else ""
    return declared or f"{workflow_id}_SUMMARY"


def _run_decisions(db: Session, *, tenant_id: str, workflow_id: str, run: WorkflowRun) -> list[WorkflowReviewDecision]:
    """Decisions made inside this run — tenant-scoped as well as run-scoped.

    Both filters are applied even though the run id already implies the tenant:
    defence in depth costs nothing here and this query is the report's only
    source of truth.
    """
    return (
        db.query(WorkflowReviewDecision)
        .filter(
            WorkflowReviewDecision.tenant_id == tenant_id,
            WorkflowReviewDecision.workflow_type == workflow_id,
            WorkflowReviewDecision.workflow_run_id == run.id,
        )
        .order_by(WorkflowReviewDecision.reviewed_at.asc())
        .all()
    )


def _verification_summary(run: WorkflowRun, remediated_ids: list[str]) -> dict:
    """Verification outcome as recorded on the run.

    The remediation path writes its result into run metadata; nothing is
    re-verified at report time, because a report must state what happened rather
    than re-run the check.
    """
    metadata = run.run_metadata or {}
    return {
        "required": bool(remediated_ids),
        "status": metadata.get("verification_status") or ("NOT_REQUIRED" if not remediated_ids else "PENDING"),
        "verified_at": metadata.get("verification_completed_at"),
        "remediated_resource_ids": remediated_ids,
        "details": metadata.get("verification_details"),
    }


def build_workflow_report(db: Session, *, tenant_id: str, run: WorkflowRun, workflow_id: str) -> dict:
    """Assemble the report. Pure read — persists nothing."""
    from app.services.workflows._shared.review_session import open_review

    definition = WORKFLOW_REGISTRY.get(workflow_id)
    tenant = db.get(Tenant, tenant_id)
    decisions = _run_decisions(db, tenant_id=tenant_id, workflow_id=workflow_id, run=run)

    # Re-derive the current picture so "outstanding" reflects reality at report
    # time rather than what was true when the run opened.
    review = open_review(db, tenant_id=tenant_id, workflow_id=workflow_id, actor=run.created_by)
    # Keyed on (control_id, resource_id), not resource_id alone: a single
    # resource (e.g. one user) can legitimately carry findings from several
    # controls in the same workflow — IDENTITY_HYGIENE's six controls can all
    # fire on the same user object. Keying on resource_id alone would collide
    # and silently attribute one control's title/risk_level to every decision
    # sharing that resource_id, including decisions made against a different
    # control.
    by_resource = {(resource.control_id, resource.resource_id): resource for resource in review.resources}

    counts = {value: 0 for value in ReviewDecision.ALL}
    decision_rows = []
    evidence_references = []

    for entry in decisions:
        counts[entry.decision] = counts.get(entry.decision, 0) + 1
        resource = by_resource.get((entry.control_id, entry.resource_id))
        decision_rows.append(
            {
                "control_id": entry.control_id,
                "resource_id": entry.resource_id,
                "resource_type": entry.resource_type,
                "title": getattr(resource, "title", entry.resource_id),
                "decision": entry.decision,
                "reason": entry.reason,
                "reviewed_by": entry.reviewed_by,
                "reviewed_at": entry.reviewed_at.isoformat() if entry.reviewed_at else None,
                "risk_level": getattr(resource, "risk_level", None),
            }
        )
        evidence_references.append(
            {
                "control_id": entry.control_id,
                "resource_id": entry.resource_id,
                "evidence_hash": entry.evidence_hash,
                "decision_id": str(entry.id),
            }
        )

    outstanding = [
        {
            "control_id": resource.control_id,
            "resource_id": resource.resource_id,
            "title": resource.title,
            "risk_level": resource.risk_level,
            "risk_explanation": resource.risk_explanation,
            "delta_state": resource.delta_state,
            "recommended_action": resource.recommended_action,
        }
        for resource in review.resources
        if resource.needs_attention
    ]

    remediated_ids = [entry.resource_id for entry in decisions if entry.decision in _REMEDIATING]

    report = {
        "report_type": _report_type(workflow_id),
        "generated_at": utc_now().isoformat(),
        "tenant_id": tenant_id,
        "tenant_name": getattr(tenant, "tenant_name", None),
        "workflow": workflow_id,
        "workflow_name": getattr(definition, "name", workflow_id),
        "run_id": str(run.id),
        "run_state": run.state,
        "run_started_at": run.started_at.isoformat() if run.started_at else None,
        "reviewed_by": sorted({entry.reviewed_by for entry in decisions}),
        "resources_discovered": len(review.resources),
        "resources_reviewed": len(decisions),
        "kept": counts.get(ReviewDecision.KEEP, 0),
        "ignored": counts.get(ReviewDecision.IGNORE, 0),
        "remediated": counts.get(ReviewDecision.REVOKE, 0),
        "escalated": counts.get(ReviewDecision.ESCALATE, 0),
        "decisions": decision_rows,
        "outstanding_risks": outstanding,
        "verification": _verification_summary(run, remediated_ids),
        "evidence_references": evidence_references,
    }

    sections = getattr(get_projector(workflow_id), "report_sections", None)
    report["sections"] = sections(review, decisions) if callable(sections) else {}

    return report


def persist_workflow_report(db: Session, *, tenant_id: str, workflow_id: str, report: dict):
    """Archive the report through the existing reporting engine."""
    payload = archive_report(
        db,
        tenant_id=tenant_id,
        report_type=_report_type(workflow_id),
        report_data=report,
    )
    db.commit()
    logger.info(
        "workflow_report_archived tenant_id=%s workflow=%s report_id=%s",
        tenant_id,
        workflow_id,
        payload.id,
    )
    return payload
