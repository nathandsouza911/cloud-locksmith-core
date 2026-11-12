"""Sprint 4 — workflow runs become first-class timeline events."""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.audit_log import AuditLog
from app.db.models.compliance_result import ComplianceResult
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.services.timeline.timeline_event import SourceSystem, TimelineEventType
from app.services.timeline.timeline_service import build_timeline
from app.services.workflow_runtime.runtime_service import (
    advance_run,
    cancel_run,
    complete_run,
    complete_stage,
    create_run,
    fail_run,
    start_stage,
)
from app.services.workflow_runtime.state_machine import RunState


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    for model in (
        Tenant,
        ComplianceResult,
        WorkflowRun,
        WorkflowStage,
        WorkflowReviewDecision,
        RemediationAuditLog,
        AuditLog,
        ReportPayload,
        PostureSnapshot,
    ):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=uuid.uuid4()))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    db.commit()
    yield db
    db.close()


def _run(session, tenant_id="t1", key="OAUTH_REVIEW"):
    return create_run(
        session,
        tenant_id=tenant_id,
        workflow_definition_key=key,
        created_by="tech@msp.example",
    )


def _workflow_events(session, tenant_id="t1"):
    page = build_timeline(session, tenant_id=tenant_id, limit=100)
    return [e for e in page.events if e.source_system == SourceSystem.WORKFLOW_RUN]


# ── Run lifecycle events ────────────────────────────────────────────────────


def test_a_run_that_has_not_started_produces_no_timeline_event(session):
    _run(session)

    assert _workflow_events(session) == []


def test_starting_a_run_produces_a_workflow_started_event(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)

    events = _workflow_events(session)

    assert len(events) == 1
    assert events[0].action == "WORKFLOW_STARTED"
    assert events[0].event_type == TimelineEventType.WORKFLOW_RUN
    assert events[0].workflow_id == "OAUTH_REVIEW"
    assert events[0].actor == "tech@msp.example"


def test_completing_a_run_produces_a_completion_event(session):
    run = _run(session)
    for state in (RunState.DISCOVERING, RunState.READY_FOR_REVIEW, RunState.IN_REVIEW):
        advance_run(session, run=run, target_state=state)
    complete_run(session, run=run, summary={"reviewed": 10})

    actions = {event.action for event in _workflow_events(session)}

    assert "WORKFLOW_STARTED" in actions
    assert "WORKFLOW_COMPLETED" in actions


def test_a_failed_run_produces_a_failure_event(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    fail_run(session, run=run, reason="graph unavailable")

    events = [e for e in _workflow_events(session) if e.action == "WORKFLOW_FAILED"]

    assert len(events) == 1
    assert events[0].outcome == RunState.FAILED


def test_a_cancelled_run_produces_a_cancellation_event(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    cancel_run(session, run=run, reason="client postponed")

    events = [e for e in _workflow_events(session) if e.action == "WORKFLOW_CANCELLED"]

    assert len(events) == 1


def test_a_completion_event_carries_the_run_summary(session):
    run = _run(session)
    for state in (RunState.DISCOVERING, RunState.READY_FOR_REVIEW, RunState.IN_REVIEW):
        advance_run(session, run=run, target_state=state)
    complete_run(session, run=run, summary={"reviewed": 10, "new": 4})

    event = next(e for e in _workflow_events(session) if e.action == "WORKFLOW_COMPLETED")

    assert event.metadata.get("summary") == {"reviewed": 10, "new": 4}


# ── Stage events ────────────────────────────────────────────────────────────


def test_starting_a_stage_produces_a_stage_event(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    start_stage(session, run=run, stage_key="DISCOVER")

    events = [e for e in _workflow_events(session) if e.action == "STAGE_STARTED"]

    assert len(events) == 1
    assert events[0].metadata.get("stage_key") == "DISCOVER"


def test_completing_a_stage_produces_a_stage_completed_event(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    start_stage(session, run=run, stage_key="DISCOVER")
    complete_stage(session, run=run, stage_key="DISCOVER")

    actions = [e.action for e in _workflow_events(session)]

    assert "STAGE_STARTED" in actions
    assert "STAGE_COMPLETED" in actions


# ── Merging and ordering ────────────────────────────────────────────────────


def test_workflow_events_merge_with_existing_sources(session):
    session.add(
        AuditLog(
            tenant_id="t1",
            action="OFFBOARDING",
            actor="tech@msp.example",
            target="user-1",
            status="SUCCESS",
            reason=None,
            details={},
            sequence_hash="b" * 64,
        )
    )
    session.commit()
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)

    page = build_timeline(session, tenant_id="t1", limit=100)
    sources = {event.source_system for event in page.events}

    assert SourceSystem.WORKFLOW_RUN in sources
    assert SourceSystem.AUDIT_LOG in sources


def test_workflow_events_respect_newest_first_ordering(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    advance_run(session, run=run, target_state=RunState.READY_FOR_REVIEW)
    advance_run(session, run=run, target_state=RunState.IN_REVIEW)
    complete_run(session, run=run)

    timestamps = [event.timestamp for event in _workflow_events(session)]

    assert timestamps == sorted(timestamps, reverse=True)


def test_workflow_events_can_be_filtered_by_workflow(session):
    a = _run(session, key="OAUTH_REVIEW")
    b = _run(session, key="GUEST_REVIEW")
    advance_run(session, run=a, target_state=RunState.DISCOVERING)
    advance_run(session, run=b, target_state=RunState.DISCOVERING)

    page = build_timeline(session, tenant_id="t1", workflow_id="OAUTH_REVIEW", limit=100)

    assert page.events
    assert all(event.workflow_id == "OAUTH_REVIEW" for event in page.events)


def test_workflow_events_can_be_filtered_by_event_type(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)

    page = build_timeline(
        session,
        tenant_id="t1",
        event_types=[TimelineEventType.WORKFLOW_RUN],
        limit=100,
    )

    assert page.events
    assert all(event.event_type == TimelineEventType.WORKFLOW_RUN for event in page.events)


def test_workflow_event_ids_are_unique(session):
    run = _run(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    start_stage(session, run=run, stage_key="DISCOVER")
    complete_stage(session, run=run, stage_key="DISCOVER")
    advance_run(session, run=run, target_state=RunState.READY_FOR_REVIEW)
    advance_run(session, run=run, target_state=RunState.IN_REVIEW)
    complete_run(session, run=run)

    ids = [event.id for event in _workflow_events(session)]

    assert len(ids) == len(set(ids))


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_another_tenants_run_never_appears_on_this_timeline(session):
    run = _run(session, tenant_id="t2")
    advance_run(session, run=run, target_state=RunState.DISCOVERING)

    assert _workflow_events(session, tenant_id="t1") == []


def test_another_tenants_stages_never_appear_on_this_timeline(session):
    run = _run(session, tenant_id="t2")
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    start_stage(session, run=run, stage_key="DISCOVER")

    assert _workflow_events(session, tenant_id="t1") == []
