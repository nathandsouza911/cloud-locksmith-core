"""Timeline source adapters.

One adapter per existing subsystem. Each knows how to read its own table and
project rows into ``TimelineEvent``. None of them writes anything.

Adding a source — including ``workflow_runs`` when the Workflow Engine lands —
means adding one adapter to ``TIMELINE_SOURCES``. The merge, ordering and
pagination logic in ``timeline_service`` does not change.

Every adapter MUST filter on ``tenant_id``. ``VerificationSource`` is the one
that needs a join to do it, because ``verification_events`` carries no tenant
column of its own.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models.audit_log import AuditLog
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.report_payload import ReportPayload
from app.db.models.verification_lifecycle import (
    RemediationVerification,
    VerificationEvent,
)
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.services.timeline.timeline_event import (
    SourceSystem,
    TimelineEvent,
    TimelineEventType,
)
from app.services.work.workflow_registry import get_workflow, resolve_workflow_id
from app.utils.datetime import ensure_utc

logger = logging.getLogger(__name__)


def _workflow_fields(control_id: str | None) -> tuple[str | None, str | None]:
    if not control_id:
        return None, None
    workflow_id = resolve_workflow_id(control_id)
    return workflow_id, get_workflow(workflow_id).name


def _humanise(control_id: str | None) -> str:
    if not control_id:
        return "resource"
    return control_id.replace("IDENTITY_", "").replace("_", " ").title()


class TimelineSource(ABC):
    """Projects one subsystem's rows into timeline events."""

    source_system: str
    event_type: str

    @abstractmethod
    def fetch(
        self,
        db: Session,
        *,
        tenant_id: str,
        until: datetime | None,
        since: datetime | None,
        limit: int,
    ) -> list[TimelineEvent]:
        """Newest-first events for one tenant, at most ``limit`` of them.

        ``until`` is the pagination bound (inclusive — the service drops
        anything at or before the exact cursor position after merging).
        """


class ReviewDecisionSource(TimelineSource):
    source_system = SourceSystem.REVIEW_DECISIONS
    event_type = TimelineEventType.REVIEW_DECISION

    def fetch(self, db, *, tenant_id, until, since, limit):
        query = db.query(WorkflowReviewDecision).filter(WorkflowReviewDecision.tenant_id == tenant_id)
        if until is not None:
            query = query.filter(WorkflowReviewDecision.reviewed_at <= until)
        if since is not None:
            query = query.filter(WorkflowReviewDecision.reviewed_at >= since)

        rows = query.order_by(WorkflowReviewDecision.reviewed_at.desc()).limit(limit).all()

        events = []
        for row in rows:
            workflow = get_workflow(row.workflow_type)
            events.append(
                TimelineEvent(
                    id=f"{self.source_system}:{row.id}",
                    tenant_id=row.tenant_id,
                    timestamp=ensure_utc(row.reviewed_at),
                    source_system=self.source_system,
                    event_type=self.event_type,
                    action="REVIEWED",
                    title=f"{_humanise(row.control_id)} reviewed — {row.decision}",
                    description=row.reason,
                    actor=row.reviewed_by,
                    outcome=row.decision,
                    workflow_id=row.workflow_type,
                    workflow_name=workflow.name,
                    evidence_reference=row.evidence_hash,
                    control_id=row.control_id,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                    metadata={"superseded": row.superseded_at is not None},
                )
            )
        return events


class RemediationSource(TimelineSource):
    source_system = SourceSystem.REMEDIATION
    event_type = TimelineEventType.REMEDIATION

    def fetch(self, db, *, tenant_id, until, since, limit):
        query = db.query(RemediationAuditLog).filter(RemediationAuditLog.tenant_id == tenant_id)
        if until is not None:
            query = query.filter(RemediationAuditLog.created_at <= until)
        if since is not None:
            query = query.filter(RemediationAuditLog.created_at >= since)

        rows = query.order_by(RemediationAuditLog.created_at.desc()).limit(limit).all()

        events = []
        for row in rows:
            workflow_id, workflow_name = _workflow_fields(row.control_id)
            status = row.execution_status or "PENDING"
            events.append(
                TimelineEvent(
                    id=f"{self.source_system}:{row.id}",
                    tenant_id=row.tenant_id,
                    timestamp=ensure_utc(row.created_at),
                    source_system=self.source_system,
                    event_type=self.event_type,
                    action="REMEDIATED",
                    title=f"{_humanise(row.control_id)} remediation — {status}",
                    description=row.explanation_summary,
                    actor=row.approved_by,
                    outcome=status,
                    workflow_id=workflow_id,
                    workflow_name=workflow_name,
                    evidence_reference=str(row.id),
                    control_id=row.control_id,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                    metadata={
                        "verified": row.verified,
                        "rolled_back": row.rolled_back,
                        "confidence": row.confidence,
                    },
                )
            )
        return events


class VerificationSource(TimelineSource):
    source_system = SourceSystem.VERIFICATION
    event_type = TimelineEventType.VERIFICATION

    def fetch(self, db, *, tenant_id, until, since, limit):
        # verification_events has no tenant column — scope through the parent
        # remediation_verifications row, which does.
        query = (
            db.query(VerificationEvent, RemediationVerification)
            .join(
                RemediationVerification,
                RemediationVerification.id == VerificationEvent.verification_id,
            )
            .filter(RemediationVerification.tenant_id == tenant_id)
        )
        if until is not None:
            query = query.filter(VerificationEvent.created_at <= until)
        if since is not None:
            query = query.filter(VerificationEvent.created_at >= since)

        rows = query.order_by(VerificationEvent.created_at.desc()).limit(limit).all()

        events = []
        for event_row, verification in rows:
            workflow_id, workflow_name = _workflow_fields(verification.control_id)
            transition = (
                f"{event_row.previous_status} → {event_row.new_status}"
                if event_row.previous_status
                else event_row.new_status
            )
            events.append(
                TimelineEvent(
                    id=f"{self.source_system}:{event_row.id}",
                    tenant_id=verification.tenant_id,
                    timestamp=ensure_utc(event_row.created_at),
                    source_system=self.source_system,
                    event_type=self.event_type,
                    action="VERIFIED",
                    title=f"{_humanise(verification.control_id)} verification — {transition}",
                    description=event_row.reason,
                    actor=None,  # verification is machine-driven
                    outcome=event_row.new_status,
                    workflow_id=workflow_id,
                    workflow_name=workflow_name,
                    evidence_reference=str(verification.id),
                    control_id=verification.control_id,
                    metadata={"previous_status": event_row.previous_status},
                )
            )
        return events


class AuditLogSource(TimelineSource):
    source_system = SourceSystem.AUDIT_LOG
    event_type = TimelineEventType.AUDIT

    def fetch(self, db, *, tenant_id, until, since, limit):
        query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
        if until is not None:
            query = query.filter(AuditLog.created_at <= until)
        if since is not None:
            query = query.filter(AuditLog.created_at >= since)

        rows = query.order_by(AuditLog.created_at.desc()).limit(limit).all()

        return [
            TimelineEvent(
                id=f"{self.source_system}:{row.id}",
                tenant_id=row.tenant_id,
                timestamp=ensure_utc(row.created_at),
                source_system=self.source_system,
                event_type=self.event_type,
                action=row.action,
                title=f"{row.action.replace('_', ' ').title()} — {row.status}",
                description=row.reason,
                actor=row.actor,
                outcome=row.status,
                # The hash-chain entry is the evidence. Timeline never alters it.
                evidence_reference=row.sequence_hash,
                resource_id=row.target,
                metadata={"details": row.details or {}},
            )
            for row in rows
        ]


class ReportSource(TimelineSource):
    source_system = SourceSystem.REPORTS
    event_type = TimelineEventType.REPORT_GENERATED

    def fetch(self, db, *, tenant_id, until, since, limit):
        query = db.query(ReportPayload).filter(ReportPayload.tenant_id == tenant_id)
        if until is not None:
            query = query.filter(ReportPayload.generated_at <= until)
        if since is not None:
            query = query.filter(ReportPayload.generated_at >= since)

        rows = query.order_by(ReportPayload.generated_at.desc()).limit(limit).all()

        return [
            TimelineEvent(
                id=f"{self.source_system}:{row.id}",
                tenant_id=row.tenant_id,
                timestamp=ensure_utc(row.generated_at),
                source_system=self.source_system,
                event_type=self.event_type,
                action="REPORT_GENERATED",
                title=f"{row.report_type.replace('_', ' ').title()} report generated",
                description=None,
                actor=None,
                outcome=row.report_type,
                evidence_reference=row.content_hash,
                metadata={"score": row.score, "report_payload_id": row.id},
            )
            for row in rows
        ]


class PostureSnapshotSource(TimelineSource):
    source_system = SourceSystem.POSTURE_SNAPSHOT
    event_type = TimelineEventType.POSTURE_SNAPSHOT

    def fetch(self, db, *, tenant_id, until, since, limit):
        query = db.query(PostureSnapshot).filter(PostureSnapshot.tenant_id == tenant_id)
        if until is not None:
            query = query.filter(PostureSnapshot.created_at <= until)
        if since is not None:
            query = query.filter(PostureSnapshot.created_at >= since)

        rows = query.order_by(PostureSnapshot.created_at.desc()).limit(limit).all()

        return [
            TimelineEvent(
                id=f"{self.source_system}:{row.id}",
                tenant_id=row.tenant_id,
                timestamp=ensure_utc(row.created_at),
                source_system=self.source_system,
                event_type=self.event_type,
                action="POSTURE_CAPTURED",
                title=f"Posture snapshot — score {row.security_score}",
                description=None,
                actor=None,
                outcome=str(row.security_score),
                metadata={"security_score": row.security_score},
            )
            for row in rows
        ]


class WorkflowRunSource(TimelineSource):
    """Projects workflow runs and their stages into lifecycle events.

    Runs carry no state-change ledger of their own — a run is a single row that
    moves through states. Its events are therefore *derived* from the timestamps
    already on the row (``started_at``, ``completed_at``) and on its stages.
    That keeps the runtime free of a second write path and honours the rule that
    the timeline consumes existing storage rather than duplicating it.

    One row can yield several events, so ids are suffixed by event kind to stay
    globally unique.
    """

    source_system = SourceSystem.WORKFLOW_RUN
    event_type = TimelineEventType.WORKFLOW_RUN

    _TERMINAL_ACTIONS = {
        "COMPLETED": "WORKFLOW_COMPLETED",
        "FAILED": "WORKFLOW_FAILED",
        "CANCELLED": "WORKFLOW_CANCELLED",
    }

    def _event(self, run, *, suffix, timestamp, action, title, outcome, metadata):
        workflow = get_workflow(run.workflow_definition_key)
        return TimelineEvent(
            id=f"{self.source_system}:{run.id}:{suffix}",
            tenant_id=run.tenant_id,
            timestamp=ensure_utc(timestamp),
            source_system=self.source_system,
            event_type=self.event_type,
            action=action,
            title=title,
            description=None,
            actor=run.created_by,
            outcome=outcome,
            workflow_id=run.workflow_definition_key,
            workflow_name=workflow.name,
            evidence_reference=str(run.id),
            metadata=metadata,
        )

    def fetch(self, db, *, tenant_id, until, since, limit):
        runs = (
            db.query(WorkflowRun)
            .filter(WorkflowRun.tenant_id == tenant_id)
            .order_by(WorkflowRun.created_at.desc())
            .limit(limit)
            .all()
        )
        if not runs:
            return []

        run_by_id = {run.id: run for run in runs}

        events: list[TimelineEvent] = []
        for run in runs:
            workflow = get_workflow(run.workflow_definition_key)

            if run.started_at is not None:
                events.append(
                    self._event(
                        run,
                        suffix="started",
                        timestamp=run.started_at,
                        action="WORKFLOW_STARTED",
                        title=f"{workflow.name} started",
                        outcome=None,
                        metadata={"trigger": run.trigger, "run_id": str(run.id)},
                    )
                )

            action = self._TERMINAL_ACTIONS.get(run.state)
            if action and run.completed_at is not None:
                events.append(
                    self._event(
                        run,
                        suffix=run.state.lower(),
                        timestamp=run.completed_at,
                        action=action,
                        title=f"{workflow.name} {run.state.lower()}",
                        outcome=run.state,
                        metadata={
                            "run_id": str(run.id),
                            "summary": run.summary or {},
                            **(run.run_metadata or {}),
                        },
                    )
                )

        # Stages are scoped by their parent run, which is already tenant-filtered.
        stages = (
            db.query(WorkflowStage)
            .filter(WorkflowStage.workflow_run_id.in_(list(run_by_id)))
            .order_by(WorkflowStage.sequence)
            .all()
        )
        for stage in stages:
            run = run_by_id.get(stage.workflow_run_id)
            if run is None:  # pragma: no cover - defensive
                continue
            workflow = get_workflow(run.workflow_definition_key)

            if stage.started_at is not None:
                events.append(
                    self._event(
                        run,
                        suffix=f"stage-{stage.stage_key}-started",
                        timestamp=stage.started_at,
                        action="STAGE_STARTED",
                        title=f"{workflow.name}: {stage.stage_key} started",
                        outcome=None,
                        metadata={"stage_key": stage.stage_key, "run_id": str(run.id)},
                    )
                )
            if stage.completed_at is not None:
                events.append(
                    self._event(
                        run,
                        suffix=f"stage-{stage.stage_key}-{stage.state.lower()}",
                        timestamp=stage.completed_at,
                        action=f"STAGE_{stage.state}",
                        title=f"{workflow.name}: {stage.stage_key} {stage.state.lower()}",
                        outcome=stage.state,
                        metadata={"stage_key": stage.stage_key, "run_id": str(run.id)},
                    )
                )

        # Apply the caller's time window after derivation — the bounds describe
        # event times, not row-creation times.
        def _within(event):
            if until is not None and event.timestamp > ensure_utc(until):
                return False
            if since is not None and event.timestamp < ensure_utc(since):
                return False
            return True

        events = [event for event in events if _within(event)]
        events.sort(key=lambda event: event.timestamp, reverse=True)
        return events[:limit]


TIMELINE_SOURCES: tuple[TimelineSource, ...] = (
    ReviewDecisionSource(),
    RemediationSource(),
    VerificationSource(),
    AuditLogSource(),
    ReportSource(),
    PostureSnapshotSource(),
    WorkflowRunSource(),
)
