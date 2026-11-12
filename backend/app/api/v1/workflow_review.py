"""Generic workflow review API — one surface for every workflow.

    GET  /workflows/{key}/review                     open or resume
    POST /workflows/{key}/review/decisions           decide one resource
    POST /workflows/{key}/review/remediate/simulate  preview, changes nothing
    POST /workflows/{key}/review/remediate           execute (explicit confirm)
    POST /workflows/{key}/review/complete            close and archive the report
    GET  /workflows/{key}/review/report              the latest summary

Adding a workflow adds no endpoints. Workflows are resolved by URL slug, which
already matches the frontend routes.

Security notes
--------------
* The tenant is resolved server-side by ``get_current_tenant``; no endpoint
  accepts a tenant identifier.
* ``reviewed_by`` comes from the session and is absent from every request model,
  so a decision cannot be attributed to someone else.
* Submitted decisions are validated against the workflow's declared
  ``review_actions``, not merely against ``ReviewDecision.ALL``.
* Remediation targets are sent as *ids* and resolved against the tenant's own
  server-side evidence. Resources are projected from a tenant-scoped query, so
  another tenant's id is simply absent and yields 400.
* Every mutating endpoint requires write access — IGNORE suppresses a finding
  and REVOKE acts on live resources; neither is a preview-session action.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_user,
    require_write_access,
)
from app.db.models.platform_user import PlatformUser
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.work.workflow_registry import (
    WORKFLOW_REGISTRY,
    WorkflowDefinition,
    get_workflow_by_key,
    review_actions_for,
)
from app.services.workflows._shared.report import (
    build_workflow_report,
    persist_workflow_report,
)
from app.services.workflows._shared.resources import ReviewResource
from app.services.workflows._shared.review_session import (
    WorkflowReview,
    WorkflowReviewError,
    complete_review,
    open_review,
    record_decision,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflows", tags=["Workflow Review"])


# ── Request models ──────────────────────────────────────────────────────────


class DecisionRequest(BaseModel):
    """``reviewed_by`` is deliberately absent — the reviewer comes from the
    session so a decision cannot be attributed to someone else."""

    control_id: str
    resource_id: str
    decision: str
    reason: str | None = None


class RemediationRequest(BaseModel):
    control_id: str
    resource_ids: list[str]
    # Remediation acts on live resources. The client must say so twice: once by
    # simulating, once by confirming.
    confirmed: bool = False
    reason: str | None = None


class SimulateRequest(BaseModel):
    control_id: str
    resource_ids: list[str]


# ── Helpers ─────────────────────────────────────────────────────────────────


def _definition(workflow_key: str) -> WorkflowDefinition:
    """Resolve a workflow by its URL slug, or by its internal registry id.

    The work-queue list (Sprint 1, outside this plan's scope) links to
    ``/work/{workflow.id}`` — e.g. "IDENTITY_HYGIENE" — while this API and the
    dedicated frontend routes are keyed by the URL slug — e.g.
    "identity-hygiene". Accepting both here is one lookup, versus teaching the
    work-queue list a slug it was never designed to carry.
    """
    definition = get_workflow_by_key(workflow_key) or WORKFLOW_REGISTRY.get(workflow_key)
    if definition is None or not definition.enabled:
        raise HTTPException(status_code=404, detail="Unknown workflow")
    return definition


def _actor(current_user: PlatformUser) -> str:
    return getattr(current_user, "email", None) or str(getattr(current_user, "id", ""))


def _serialize_resource(resource: ReviewResource) -> dict:
    return {
        "control_id": resource.control_id,
        "resource_id": resource.resource_id,
        "resource_type": resource.resource_type,
        "title": resource.title,
        "subtitle": resource.subtitle,
        "risk_level": resource.risk_level,
        "risk_explanation": resource.risk_explanation,
        "risk_drivers": resource.risk_drivers,
        "recommended_action": resource.recommended_action,
        "facts": [{"label": fact.label, "value": fact.value, "emphasis": fact.emphasis} for fact in resource.facts],
        "evidence": resource.evidence,
        "evidence_hash": resource.evidence_hash,
        "compliance_result_id": resource.compliance_result_id,
        "delta_state": resource.delta_state,
        "previous_decision": resource.previous_decision,
        "previous_reviewed_by": resource.previous_reviewed_by,
        "previous_reviewed_at": resource.previous_reviewed_at,
    }


def _serialize_review(review: WorkflowReview, definition: WorkflowDefinition) -> dict:
    next_resource = review.next_resource
    return {
        "tenant_id": review.tenant_id,
        "workflow": {
            "id": definition.id,
            "key": definition.key,
            "name": definition.name,
            "description": definition.description,
            "category": definition.category,
            "icon": definition.icon,
            "review_philosophy": definition.review_philosophy,
            "supports_remediation": definition.supports_remediation,
            "supports_reports": definition.supports_reports,
        },
        "review_actions": [
            {
                "decision": action.decision,
                "label": action.label,
                "description": action.description,
            }
            for action in review_actions_for(definition.id)
        ],
        "run": {
            "id": str(review.run.id),
            "state": review.run.state,
            "current_stage": review.run.current_stage,
            "started_at": review.run.started_at,
            "completed_at": review.run.completed_at,
            "created_by": review.run.created_by,
            "summary": review.run.summary or {},
        },
        "stages": [
            {
                "stage_key": stage.stage_key,
                "state": stage.state,
                "started_at": stage.started_at,
                "completed_at": stage.completed_at,
            }
            for stage in review.stages
        ],
        "progress": {
            "total_resources": review.progress.total_resources,
            "reviewed_resources": review.progress.reviewed_resources,
            "remaining_resources": review.progress.remaining_resources,
            "percent_complete": review.progress.percent_complete,
            "is_complete": review.progress.is_complete,
        },
        "resources": [_serialize_resource(r) for r in review.resources],
        # The item the technician should look at next — the UI focuses it so
        # they never have to choose.
        "next_resource_id": next_resource.resource_id if next_resource else None,
    }


def _resource_evidence(review: WorkflowReview, control_id: str, resource_ids):
    """Server-side evidence for the requested ids, or 400.

    This is the tenant guard for remediation: the projection is tenant-scoped,
    so an id belonging to another tenant is simply not here.
    """
    from app.services.workflows._shared.resource_key import ResourceKey

    selected = []
    for resource_id in resource_ids:
        resource = review.resource_for(ResourceKey(control_id, resource_id))
        if resource is None:
            raise HTTPException(
                status_code=400,
                detail=f"{control_id}/{resource_id} is not part of this review",
            )
        selected.append(resource)
    if not selected:
        raise HTTPException(status_code=400, detail="No resources were selected")
    return selected


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get("/{workflow_key}/review")
def get_review(
    workflow_key: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Open or resume this workflow's review. Starts a run if none is live."""
    definition = _definition(workflow_key)
    try:
        review = open_review(
            db,
            tenant_id=current_tenant.id,
            workflow_id=definition.id,
            actor=_actor(current_user),
        )
    except WorkflowReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_review(review, definition)


@router.post("/{workflow_key}/review/decisions")
def submit_decision(
    workflow_key: str,
    payload: DecisionRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
    _write: None = Depends(require_write_access),
):
    """Record a decision for one resource and return the refreshed review."""
    definition = _definition(workflow_key)
    try:
        review = record_decision(
            db,
            tenant_id=current_tenant.id,
            workflow_id=definition.id,
            control_id=payload.control_id,
            resource_id=payload.resource_id,
            decision=payload.decision,
            actor=_actor(current_user),
            reason=payload.reason,
        )
    except WorkflowReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_review(review, definition)


@router.post("/{workflow_key}/review/remediate/simulate")
def simulate_remediation(
    workflow_key: str,
    payload: SimulateRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Explain exactly what remediating the selection would do. Changes nothing."""
    definition = _definition(workflow_key)
    review = open_review(
        db,
        tenant_id=current_tenant.id,
        workflow_id=definition.id,
        actor=_actor(current_user),
    )
    selected = _resource_evidence(review, payload.control_id, payload.resource_ids)

    return {
        "control_id": payload.control_id,
        "selected_resource_ids": [r.resource_id for r in selected],
        "changes": [
            {
                "resource_id": r.resource_id,
                "title": r.title,
                "resource_type": r.resource_type,
                "recommended_action": r.recommended_action,
                "risk_level": r.risk_level,
            }
            for r in selected
        ],
        "reversible": True,
        "rollback_strategy": ("Restore from the pre-execution snapshot captured by the remediation " "engine"),
        "requires_confirmation": True,
        "summary": (
            f"{len(selected)} item(s) will be remediated. A snapshot is captured " "first, so this can be rolled back."
        ),
    }


@router.post("/{workflow_key}/review/remediate")
async def execute_remediation(
    workflow_key: str,
    payload: RemediationRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
    _write: None = Depends(require_write_access),
):
    """Remediate the selection through the existing remediation engine.

    No second execution path: this delegates to ``execute_approved_remediation``,
    which runs preflight, snapshot, execution, verification and audit exactly as
    it does for every other control.
    """
    definition = _definition(workflow_key)
    if not payload.confirmed:
        raise HTTPException(
            status_code=400,
            detail="Remediation must be confirmed. Simulate it first, then " "resubmit with confirmed=true.",
        )

    actor = _actor(current_user)
    review = open_review(db, tenant_id=current_tenant.id, workflow_id=definition.id, actor=actor)
    selected = _resource_evidence(review, payload.control_id, payload.resource_ids)

    # Record the intent before acting, so an execution failure still leaves an
    # auditable record of what the technician asked for.
    for resource in selected:
        try:
            record_decision(
                db,
                tenant_id=current_tenant.id,
                workflow_id=definition.id,
                control_id=resource.control_id,
                resource_id=resource.resource_id,
                decision="REVOKE",
                actor=actor,
                reason=payload.reason,
            )
        except WorkflowReviewError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    from app.services.remediation_execution_service import execute_approved_remediation

    results = []
    for resource in selected:
        if resource.compliance_result_id is None:
            raise HTTPException(
                status_code=400,
                detail=f"{resource.resource_id} has no finding to remediate",
            )
        try:
            results.append(
                await execute_approved_remediation(
                    db=db,
                    compliance_result_id=resource.compliance_result_id,
                    tenant=current_tenant,
                    tenant_id=current_tenant.id,
                    auto_approve=True,
                    approved_by=actor,
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.info(
        "workflow_remediation_executed tenant_id=%s workflow=%s resources=%s",
        current_tenant.id,
        definition.id,
        [r.resource_id for r in selected],
    )

    return {
        "selected_resource_ids": [r.resource_id for r in selected],
        "executions": results,
        "review": _serialize_review(
            open_review(
                db,
                tenant_id=current_tenant.id,
                workflow_id=definition.id,
                actor=actor,
            ),
            definition,
        ),
    }


@router.post("/{workflow_key}/review/complete")
def complete(
    workflow_key: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
    _write: None = Depends(require_write_access),
):
    """Close the review, freeze the run summary and archive the report."""
    definition = _definition(workflow_key)

    def _report_builder(db_, *, tenant_id, run, workflow_id):
        report = build_workflow_report(db_, tenant_id=tenant_id, run=run, workflow_id=workflow_id)
        persist_workflow_report(db_, tenant_id=tenant_id, workflow_id=workflow_id, report=report)
        return report

    try:
        review = complete_review(
            db,
            tenant_id=current_tenant.id,
            workflow_id=definition.id,
            actor=_actor(current_user),
            report_builder=_report_builder,
        )
    except WorkflowReviewError as exc:
        # 409: the request is fine, the review's state conflicts with it.
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return _serialize_review(review, definition)


@router.get("/{workflow_key}/review/report")
def get_report(
    workflow_key: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """The most recent archived report for this workflow and client."""
    definition = _definition(workflow_key)
    report_type = definition.report_type or f"{definition.id}_SUMMARY"

    payload = (
        db.query(ReportPayload)
        .filter(
            ReportPayload.tenant_id == current_tenant.id,
            ReportPayload.report_type == report_type,
        )
        .order_by(ReportPayload.id.desc())
        .first()
    )
    if payload is None:
        raise HTTPException(status_code=404, detail="No report for this workflow yet")

    return {
        **payload.payload,
        "report_id": payload.id,
        "content_hash": payload.content_hash,
        "generated_at": payload.generated_at,
    }
