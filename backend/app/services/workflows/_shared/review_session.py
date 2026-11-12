"""One review session, for any workflow.

This is ``oauth_review/service.py`` with the three OAuth-specific things —
workflow id, control id and resource projection — lifted into parameters.
Everything it uses already existed:

    runtime          get_or_create_active_run / advance_run / stages
    review memory    record_review_decision / get_active_decisions
    delta engine     classify_delta
    progress         WorkflowProgress
    registry         controls_for / review_actions_for

No workflow-specific behaviour lives here. If a change to this module needs an
``if workflow_id == ...``, it belongs in a projector instead.

Tenant isolation: every query filters on the caller's ``tenant_id``. A resource
belonging to another tenant is simply absent from the projection, which is what
makes ``record_decision`` refuse it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.services.work.delta_engine import DeltaItem, DeltaState, classify_delta
from app.services.work.progress import WorkflowProgress
from app.services.work.review_service import (
    get_active_decisions,
    record_review_decision,
)
from app.services.work.workflow_registry import WORKFLOW_REGISTRY, review_actions_for
from app.services.workflow_runtime.runtime_service import (
    advance_run,
    complete_run,
    complete_stage,
    get_active_run,
    get_or_create_active_run,
    list_stages,
    start_stage,
)
from app.services.workflow_runtime.state_machine import RunState
from app.services.workflows._shared.projector_registry import get_projector
from app.services.workflows._shared.resource_key import ResourceKey
from app.services.workflows._shared.resources import ReviewResource

logger = logging.getLogger(__name__)

STAGE_DISCOVER = "DISCOVER"
STAGE_REVIEW = "REVIEW"
STAGE_REMEDIATE = "REMEDIATE"
STAGE_VERIFY = "VERIFY"


class WorkflowReviewError(ValueError):
    """Raised when a review action cannot be performed."""


@dataclass(frozen=True)
class WorkflowReview:
    tenant_id: str
    workflow_id: str
    run: WorkflowRun
    findings: list[ComplianceResult]
    resources: list[ReviewResource]
    progress: WorkflowProgress
    stages: list[WorkflowStage] = field(default_factory=list)

    @property
    def next_resource(self) -> ReviewResource | None:
        """The item the technician should look at next.

        Resources arrive riskiest-first, so the first one still needing
        attention is the right one — the review advances without the technician
        having to choose.
        """
        for resource in self.resources:
            if resource.needs_attention:
                return resource
        return None

    def resource_for(self, key: ResourceKey) -> ReviewResource | None:
        return next((r for r in self.resources if r.key == key), None)


def _require_definition(workflow_id: str):
    definition = WORKFLOW_REGISTRY.get(workflow_id)
    if definition is None or not definition.enabled:
        raise WorkflowReviewError(f"Unknown workflow: {workflow_id}")
    return definition


def _open_findings(db: Session, *, tenant_id: str, controls: tuple[str, ...]) -> list[ComplianceResult]:
    """This tenant's live findings for the workflow's controls.

    Tenant filter first and always — this query is the boundary that makes every
    downstream step tenant-safe.
    """
    if not controls:
        return []
    return (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.control_id.in_(controls),
            ComplianceResult.exposure_status == ExposureStatus.ACTIVE.value,
            ComplianceResult.passed.is_(False),
        )
        .order_by(ComplianceResult.id.desc())
        .all()
    )


def _progress_from(resources: list[ReviewResource]) -> WorkflowProgress:
    total = len(resources)
    remaining = sum(1 for resource in resources if resource.needs_attention)
    reviewed = max(total - remaining, 0)
    percent = 100 if total == 0 else round((reviewed / total) * 100)
    return WorkflowProgress(
        total_resources=total,
        reviewed_resources=reviewed,
        remaining_resources=remaining,
        percent_complete=percent,
    )


def _decorate_with_delta(
    db: Session, *, tenant_id: str, workflow_id: str, resources: list[ReviewResource]
) -> list[ReviewResource]:
    """Attach delta state and prior-review context, using the platform engine."""
    decisions = get_active_decisions(db, tenant_id=tenant_id, workflow_type=workflow_id)
    delta = classify_delta(
        current_items=[DeltaItem(key=r.key.as_tuple(), evidence_hash=r.evidence_hash) for r in resources],
        decisions=decisions,
    )
    return [
        resource.with_delta(
            delta_state=delta.state_for(resource.key.as_tuple()) or DeltaState.NEW,
            decision=decisions.get(resource.key.as_tuple()),
        )
        for resource in resources
    ]


def open_review(db: Session, *, tenant_id: str, workflow_id: str, actor: str) -> WorkflowReview:
    """Open (or resume) a workflow review for a tenant.

    Idempotent: reuses the live run, and re-running discovery does not create a
    second one.
    """
    _require_definition(workflow_id)
    projector = get_projector(workflow_id)

    run = get_or_create_active_run(
        db,
        tenant_id=tenant_id,
        workflow_definition_key=workflow_id,
        created_by=actor,
    )

    # CREATED -> DISCOVERING -> READY_FOR_REVIEW, walked once. Resuming a review
    # already past this point leaves the state alone.
    if run.state == RunState.CREATED:
        advance_run(db, run=run, target_state=RunState.DISCOVERING)
        start_stage(db, run=run, stage_key=STAGE_DISCOVER)

    findings = _open_findings(db, tenant_id=tenant_id, controls=tuple(projector.controls()))
    resources = projector.project(findings)
    resources = _decorate_with_delta(db, tenant_id=tenant_id, workflow_id=workflow_id, resources=resources)

    if run.state == RunState.DISCOVERING:
        complete_stage(
            db,
            run=run,
            stage_key=STAGE_DISCOVER,
            metadata={"resources_discovered": len(resources)},
        )
        advance_run(db, run=run, target_state=RunState.READY_FOR_REVIEW)

    return WorkflowReview(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        run=run,
        findings=findings,
        resources=resources,
        progress=_progress_from(resources),
        stages=list_stages(db, run=run),
    )


def record_decision(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: str,
    control_id: str,
    resource_id: str,
    decision: str,
    actor: str,
    reason: str | None = None,
) -> WorkflowReview:
    """Record a decision for one resource and return the refreshed review."""
    definition = _require_definition(workflow_id)

    allowed = {action.decision for action in review_actions_for(workflow_id)}
    if decision not in allowed:
        raise WorkflowReviewError(
            f"{definition.name} does not offer that action. Expected one of: " f"{', '.join(sorted(allowed))}"
        )

    run = get_active_run(db, tenant_id=tenant_id, workflow_definition_key=workflow_id)
    if run is None:
        raise WorkflowReviewError(f"No open {definition.name} for this client")

    key = ResourceKey(control_id, resource_id or "")

    # Re-project rather than trusting the caller: this is the cross-tenant
    # guard. Another tenant's resource is simply not in this projection.
    review = open_review(db, tenant_id=tenant_id, workflow_id=workflow_id, actor=actor)
    target = review.resource_for(key)
    if target is None:
        raise WorkflowReviewError(f"{key} is not part of this client's {definition.name}")

    record_review_decision(
        db,
        tenant_id=tenant_id,
        workflow_type=workflow_id,
        control_id=key.control_id,
        resource_type=target.resource_type,
        resource_id=key.resource_id,
        decision=decision,
        reviewed_by=actor,
        # Captured at review time: the decision holds only while this resource's
        # evidence is unchanged.
        evidence_hash=target.evidence_hash,
        reason=reason,
        workflow_run_id=run.id,
    )

    if run.state == RunState.READY_FOR_REVIEW:
        advance_run(db, run=run, target_state=RunState.IN_REVIEW)
        start_stage(db, run=run, stage_key=STAGE_REVIEW)

    logger.info(
        "workflow_review_decision tenant_id=%s workflow=%s resource=%s " "decision=%s run_id=%s",
        tenant_id,
        workflow_id,
        key,
        decision,
        run.id,
    )

    return open_review(db, tenant_id=tenant_id, workflow_id=workflow_id, actor=actor)


def _refuse_if_already_completed(db: Session, *, tenant_id: str, workflow_id: str) -> None:
    """Guard against completing a review twice.

    Deliberately narrower than "no active run": a client with no findings has a
    legitimately empty review that was never opened, and completing that is
    allowed. What is refused is completing when this workflow has no live run
    *and* a finished one already exists — the double-click case.
    """
    if get_active_run(db, tenant_id=tenant_id, workflow_definition_key=workflow_id) is not None:
        return

    already_completed = (
        db.query(WorkflowRun)
        .filter(
            WorkflowRun.tenant_id == tenant_id,
            WorkflowRun.workflow_definition_key == workflow_id,
            WorkflowRun.state == RunState.COMPLETED,
        )
        .first()
    )
    if already_completed is not None:
        raise WorkflowReviewError(
            "This review has already been completed. Its report is archived; "
            "completing again would replace it with an empty one."
        )


def complete_review(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: str,
    actor: str,
    report_builder=None,
) -> WorkflowReview:
    """Close the review, generate its report and freeze a run summary.

    Refuses while any resource still needs attention — a review that closes with
    unreviewed items would produce a report overstating what was done.

    Also refuses to complete a review that has already been completed.
    ``open_review`` starts a run when none is live, which is right for a first
    completion — a client with no findings has a legitimately empty review that
    was never opened — but wrong for a repeat. ``get_active_run`` excludes
    terminal states, so without this guard a second completion would open a
    *fresh* run, find nothing outstanding because every resource is already
    settled, and archive a report scoped to that new run — one containing zero
    decisions — over the real client- and insurer-facing summary. The report
    endpoints return the newest payload, so that empty report would become the
    evidence artefact.

    ``report_builder`` is injected rather than imported so this module stays
    unaware of reporting. It is called as
    ``report_builder(db, tenant_id=..., run=..., workflow_id=...)`` and returns
    the report dict.
    """
    _require_definition(workflow_id)

    _refuse_if_already_completed(db, tenant_id=tenant_id, workflow_id=workflow_id)

    review = open_review(db, tenant_id=tenant_id, workflow_id=workflow_id, actor=actor)
    run = review.run

    if review.progress.remaining_resources > 0:
        raise WorkflowReviewError(
            f"{review.progress.remaining_resources} item(s) still need a "
            "decision before this review can be completed"
        )

    for stage in review.stages:
        if stage.stage_key == STAGE_REVIEW and stage.state == "ACTIVE":
            complete_stage(db, run=run, stage_key=STAGE_REVIEW)

    summary = {
        "resources_discovered": review.progress.total_resources,
        "resources_reviewed": review.progress.reviewed_resources,
    }
    if report_builder is not None:
        report = report_builder(db, tenant_id=tenant_id, run=run, workflow_id=workflow_id)
        # Only scalars are carried into the frozen summary; nested report
        # sections stay in the archived report where they belong.
        summary.update({key: value for key, value in (report or {}).items() if isinstance(value, (int, str, bool))})

    complete_run(db, run=run, summary=summary)

    logger.info(
        "workflow_review_completed tenant_id=%s workflow=%s run_id=%s",
        tenant_id,
        workflow_id,
        run.id,
    )

    return WorkflowReview(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        run=run,
        findings=review.findings,
        resources=review.resources,
        progress=review.progress,
        stages=list_stages(db, run=run),
    )
