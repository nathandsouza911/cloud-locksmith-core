"""Work queue service — Sprint 1.

Reads existing ``ComplianceResult`` rows and presents them as technician work.

Deliberate non-goals for this sprint (see the Sprint 1 brief):
  * No new tables — nothing here is persisted.
  * No scheduler, no recurrence, no approval, no execution.
  * No mutation of any finding. This module is strictly read-only; the
    ``test_building_the_queue_does_not_mutate_findings`` test enforces it.

Tenant isolation: every query is filtered on the ``tenant_id`` resolved
server-side by the route dependency. The caller never passes a client-supplied
tenant id into this service — see ``app/api/v1/work.py``.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta

from sqlalchemy.orm import Session

from app.db.models.compliance_result import (
    ComplianceResult,
    ExposureStatus,
    RemediationStatus,
)
from app.db.models.tenant import Tenant
from app.services.reports.control_presentation import enrich_control
from app.services.work.delta_engine import DeltaItem, DeltaState, classify_delta
from app.services.work.evidence_fingerprint import fingerprint_finding
from app.services.work.review_service import get_active_decisions
from app.services.workflow_runtime.runtime_service import (
    get_active_run,
    get_or_create_active_run,
    list_active_runs,
)
from app.services.work.priority import (
    PRIORITY_HIGH,
    PRIORITY_NORMAL,
    classify_priority,
    estimate_group_minutes,
    group_priority,
)
from app.services.work.work_item import (
    WorkGroup,
    WorkItem,
    WorkQueue,
    WorkQueueSummary,
)
from app.services.work.workflow_registry import (
    WORKFLOW_DISPLAY_ORDER,
    get_workflow,
    resolve_workflow_id,
)
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)

COMPLETED_WINDOW_DAYS = 7

# Statuses that mean "this is not open technician work right now".
#   IGNORED   — a decision has already been taken.
#   EXECUTING — remediation is in flight; surfacing it invites double-action.
#   SUCCESS   — done; it shows in the completed counter instead.
_NON_ACTIONABLE_STATUSES = {
    RemediationStatus.IGNORED.value,
    RemediationStatus.EXECUTING.value,
    RemediationStatus.SUCCESS.value,
}


def _status_value(value) -> str | None:
    """Normalise an enum-or-string column value to its string form."""
    if value is None:
        return None
    return getattr(value, "value", value)


def _work_item_title(control_id: str, resource_type: str | None) -> str:
    """Human-readable title, reusing the existing presentation layer.

    ``enrich_control`` is a pure display module (no execution/detection
    coupling) and already carries reviewed, business-language names for every
    control — exactly what a work card needs.
    """
    name = enrich_control(control_id, include_cost_estimate=False)["name"]
    if resource_type == "USER":
        return name
    return name


def _group_summary(workflow_name: str, item_count: int) -> str:
    noun = "item" if item_count == 1 else "items"
    return f"{item_count} {noun} to review"


def _decision_attr(decisions: dict, finding, attribute: str):
    """Read one field off the active decision for a finding, if any."""
    decision = decisions.get((finding.control_id, finding.resource_id))
    return getattr(decision, attribute, None) if decision is not None else None


def _fetch_open_findings(db: Session, tenant_id: str) -> list[ComplianceResult]:
    return (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.exposure_status == ExposureStatus.ACTIVE.value,
            ComplianceResult.passed.is_(False),
        )
        .all()
    )


def _count_recently_completed(db: Session, tenant_id: str) -> int:
    """Findings this tenant resolved inside the completed window.

    Sprint 1 placeholder for the real "work completed" counter, which will read
    finished workflow runs once the engine exists. Derived from existing data so
    the panel is honest rather than stubbed.
    """
    cutoff = utc_now().replace(tzinfo=None) - timedelta(days=COMPLETED_WINDOW_DAYS)
    return (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.exposure_status == ExposureStatus.RESOLVED.value,
            ComplianceResult.resolved_at.isnot(None),
            ComplianceResult.resolved_at >= cutoff,
        )
        .count()
    )


def build_work_queue(db: Session, *, tenant_id: str) -> WorkQueue:
    """Build the technician work queue for one tenant.

    Read-only. Returns presentation dataclasses; nothing is written.
    """
    tenant = db.get(Tenant, tenant_id)
    tenant_name = getattr(tenant, "tenant_name", None)

    findings = _fetch_open_findings(db, tenant_id)

    buckets: dict[str, list[ComplianceResult]] = defaultdict(list)
    for finding in findings:
        if _status_value(finding.remediation_status) in _NON_ACTIONABLE_STATUSES:
            continue
        buckets[resolve_workflow_id(finding.control_id)].append(finding)

    # Sprint 2 — review memory. One query for the whole tenant; the per-group
    # lookup is then in-memory.
    all_decisions = get_active_decisions(db, tenant_id=tenant_id)

    # Sprint 4 — report the active run per workflow. Listing the queue never
    # CREATES a run: that would spawn runs for every workflow on every page
    # load. Runs are created when a workflow is opened (see build_workflow_delta).
    runs_by_workflow = {run.workflow_definition_key: run for run in list_active_runs(db, tenant_id=tenant_id)}

    groups: list[WorkGroup] = []
    for workflow_id, workflow_findings in buckets.items():
        workflow = get_workflow(workflow_id)

        # Decisions are scoped to (workflow, control, resource): a decision made
        # in a different workflow must never suppress work here.
        workflow_decisions = {
            key: decision for key, decision in all_decisions.items() if decision.workflow_type == workflow.id
        }
        delta = classify_delta(
            current_items=[
                DeltaItem(
                    key=(finding.control_id, finding.resource_id),
                    evidence_hash=fingerprint_finding(finding),
                    payload=finding,
                )
                for finding in workflow_findings
            ],
            decisions=workflow_decisions,
        )

        # Effort covers only what still needs a decision. A group where
        # everything has been reviewed and nothing has changed costs nothing.
        estimated_minutes = estimate_group_minutes(workflow, item_count=delta.needs_attention_count)
        per_item_minutes = (
            max(1, round(estimated_minutes / max(delta.needs_attention_count, 1))) if delta.needs_attention_count else 0
        )

        items = [
            WorkItem(
                id=finding.id,
                compliance_result_id=finding.id,
                tenant_id=finding.tenant_id,
                tenant_name=tenant_name,
                title=_work_item_title(finding.control_id, finding.resource_type),
                category=workflow.category,
                severity=str(finding.severity or "MEDIUM").upper(),
                priority=classify_priority(
                    severity=finding.severity,
                    drift_count=finding.drift_count,
                ),
                estimated_minutes=per_item_minutes,
                recommended_action=workflow.recommended_action,
                related_control=finding.control_id,
                created_at=finding.first_seen_at or finding.evaluated_at,
                resource_type=finding.resource_type,
                resource_id=finding.resource_id,
                workflow_id=workflow.id,
                drift_count=finding.drift_count or 0,
                delta_state=delta.state_for((finding.control_id, finding.resource_id)) or DeltaState.NEW,
                last_reviewed_at=_decision_attr(workflow_decisions, finding, "reviewed_at"),
                last_reviewed_by=_decision_attr(workflow_decisions, finding, "reviewed_by"),
                last_decision=_decision_attr(workflow_decisions, finding, "decision"),
            )
            for finding in workflow_findings
        ]
        # Unattended work first, then priority, then a stable tiebreak — a
        # technician should never have to hunt past ten already-approved items
        # to find the four that are new.
        items.sort(
            key=lambda item: (
                0 if item.delta_state in DeltaState.NEEDS_ATTENTION else 1,
                0 if item.priority == PRIORITY_HIGH else 1,
                item.related_control,
                str(item.resource_id or ""),
            )
        )

        groups.append(
            WorkGroup(
                workflow_id=workflow.id,
                workflow_name=workflow.name,
                category=workflow.category,
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                item_count=len(items),
                priority=group_priority(item.priority for item in items),
                estimated_minutes=estimated_minutes,
                recommended_action=workflow.recommended_action,
                summary=_group_summary(workflow.name, len(items)),
                cadence=workflow.typical_cadence,
                new_count=delta.new_count,
                reviewed_count=delta.reviewed_count,
                changed_count=delta.changed_count,
                needs_attention_count=delta.needs_attention_count,
                resolved_count=delta.resolved_count,
                run_id=getattr(runs_by_workflow.get(workflow.id), "id", None),
                run_state=getattr(runs_by_workflow.get(workflow.id), "state", None),
                run_started_at=getattr(runs_by_workflow.get(workflow.id), "started_at", None),
                items=items,
            )
        )

    # High priority first, then largest effort (biggest win), then a stable
    # catalog order so the queue never reshuffles between refreshes.
    display_order = {workflow_id: index for index, workflow_id in enumerate(WORKFLOW_DISPLAY_ORDER)}
    # Groups with outstanding work come first — a fully-reviewed group is not
    # work, however severe its findings were when they were first approved.
    # Within that, high priority, then largest effort, then stable catalog order
    # so the queue never reshuffles between refreshes.
    groups.sort(
        key=lambda group: (
            0 if group.needs_attention_count > 0 else 1,
            0 if group.priority == PRIORITY_HIGH else 1,
            -group.needs_attention_count,
            -group.item_count,
            display_order.get(group.workflow_id, len(display_order)),
        )
    )

    actionable = [group for group in groups if group.needs_attention_count > 0]

    summary = WorkQueueSummary(
        # "Today's work" counts groups that still need a decision. A group where
        # everything has been reviewed and nothing changed is not work today.
        today_count=len(actionable),
        item_count=sum(group.item_count for group in groups),
        estimated_minutes=sum(group.estimated_minutes for group in groups),
        high_priority=sum(1 for g in actionable if g.priority == PRIORITY_HIGH),
        normal_priority=sum(1 for g in actionable if g.priority == PRIORITY_NORMAL),
        completed=_count_recently_completed(db, tenant_id),
        new_count=sum(group.new_count for group in groups),
        reviewed_count=sum(group.reviewed_count for group in groups),
        changed_count=sum(group.changed_count for group in groups),
        needs_attention_count=sum(group.needs_attention_count for group in groups),
    )

    logger.info(
        "work_queue_built tenant_id=%s groups=%s items=%s estimated_minutes=%s",
        tenant_id,
        summary.today_count,
        summary.item_count,
        summary.estimated_minutes,
    )

    return WorkQueue(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        generated_at=utc_now(),
        summary=summary,
        groups=groups,
    )


def build_workflow_delta(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: str,
    created_by: str | None = None,
    ensure_run: bool = False,
) -> dict:
    """Delta for a single workflow — what changed since the last review.

    Reuses exactly the same classification path as ``build_work_queue`` so the
    counts on a work card and the counts inside a review can never disagree.

    ``ensure_run`` performs Sprint 4's lazy run creation: opening a workflow
    starts a run if none is live. It is off by default so read-only callers
    (and tests) do not create runtime state as a side effect of looking.
    """
    workflow = get_workflow(workflow_id)

    run = get_active_run(db, tenant_id=tenant_id, workflow_definition_key=workflow.id)
    if run is None and ensure_run:
        run = get_or_create_active_run(
            db,
            tenant_id=tenant_id,
            workflow_definition_key=workflow.id,
            created_by=created_by or "system",
        )

    findings = [
        finding
        for finding in _fetch_open_findings(db, tenant_id)
        if _status_value(finding.remediation_status) not in _NON_ACTIONABLE_STATUSES
        and resolve_workflow_id(finding.control_id) == workflow.id
    ]

    decisions = get_active_decisions(db, tenant_id=tenant_id, workflow_type=workflow.id)
    finding_by_key = {(finding.control_id, finding.resource_id): finding for finding in findings}

    delta = classify_delta(
        current_items=[
            DeltaItem(
                key=(finding.control_id, finding.resource_id),
                evidence_hash=fingerprint_finding(finding),
                payload=finding,
            )
            for finding in findings
        ],
        decisions=decisions,
    )

    items = []
    for state, state_items in delta.by_state.items():
        for entry in state_items:
            control_id, resource_id = entry.key
            finding = finding_by_key.get(entry.key)
            decision = decisions.get(entry.key)
            items.append(
                {
                    "delta_state": state,
                    "control_id": control_id,
                    "resource_type": getattr(finding, "resource_type", None)
                    or getattr(decision, "resource_type", None),
                    "resource_id": resource_id,
                    "title": _work_item_title(control_id, getattr(finding, "resource_type", None)),
                    "severity": (str(finding.severity or "MEDIUM").upper() if finding else None),
                    # RESOLVED items have no current finding to link to.
                    "compliance_result_id": getattr(finding, "id", None),
                    "last_decision": getattr(decision, "decision", None),
                    "last_reviewed_by": getattr(decision, "reviewed_by", None),
                    "last_reviewed_at": getattr(decision, "reviewed_at", None),
                }
            )

    # Unattended work first so a review opens on what actually needs a decision.
    items.sort(
        key=lambda item: (
            0 if item["delta_state"] in DeltaState.NEEDS_ATTENTION else 1,
            item["control_id"],
            str(item["resource_id"] or ""),
        )
    )

    return {
        "tenant_id": tenant_id,
        "workflow_id": workflow.id,
        "workflow_name": workflow.name,
        "generated_at": utc_now(),
        "run": {
            "id": getattr(run, "id", None),
            "state": getattr(run, "state", None),
            "started_at": getattr(run, "started_at", None),
            "current_stage": getattr(run, "current_stage", None),
            "trigger": getattr(run, "trigger", None),
            "created_by": getattr(run, "created_by", None),
        },
        "counts": delta.counts,
        "needs_attention_count": delta.needs_attention_count,
        "reviewed_count": delta.reviewed_count,
        "items": items,
    }
