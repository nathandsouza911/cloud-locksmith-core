"""Sprint 4 — runtime integration with review memory and the work queue.

Covers the runtime's first consumer: review decisions become owned by a run,
the work queue reports run state, and progress is resource-driven.
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.services.work.progress import build_progress
from app.services.work.review_service import record_review_for_finding
from app.services.work.work_queue_service import build_work_queue, build_workflow_delta
from app.services.workflow_runtime.runtime_service import (
    cancel_run,
    create_run,
    get_active_run,
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
    ):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=uuid.uuid4()))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    db.commit()
    yield db
    db.close()


def _grant(session, resource_id, *, tenant_id="t1", scopes=None):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        passed=False,
        severity="HIGH",
        evidence={"client_id": f"app-{resource_id}", "scopes": scopes or ["Mail.Read"]},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _oauth_group(queue):
    return next(g for g in queue.groups if g.workflow_id == "OAUTH_REVIEW")


# ── Review decisions belong to a run ────────────────────────────────────────


def test_a_review_can_be_attributed_to_a_run(session):
    run = create_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    finding = _grant(session, "g-1")

    decision = record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
        workflow_run_id=run.id,
    )

    assert decision.workflow_run_id == run.id


def test_a_review_without_a_run_is_still_valid(session):
    """Historical review memory predates the runtime and must keep working."""
    finding = _grant(session, "g-1")

    decision = record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )

    assert decision.workflow_run_id is None


def test_a_decision_made_before_the_runtime_still_suppresses_a_finding(session):
    """Regression guard: review memory must not depend on run ownership."""
    finding = _grant(session, "g-1")
    record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
        workflow_run_id=None,
    )

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))

    assert group.reviewed_count == 1
    assert group.new_count == 0


def test_decisions_from_an_earlier_run_still_count_in_a_later_run(session):
    """Review memory spans runs — it is not reset when a run closes."""
    first_run = create_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    finding = _grant(session, "g-1")
    record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
        workflow_run_id=first_run.id,
    )
    cancel_run(session, run=first_run)

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))

    assert group.reviewed_count == 1


# ── Work queue reports run state ────────────────────────────────────────────


def test_a_group_reports_no_run_when_none_exists(session):
    _grant(session, "g-1")

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))

    assert group.run_id is None
    assert group.run_state is None


def test_a_group_reports_its_active_run(session):
    run = create_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    _grant(session, "g-1")

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))

    assert group.run_id == run.id
    assert group.run_state == RunState.CREATED


def test_listing_the_queue_does_not_create_runs(session):
    """Runs are created when a workflow is opened, not when the queue is listed
    — otherwise every page load would spawn runs for every workflow."""
    _grant(session, "g-1")

    build_work_queue(session, tenant_id="t1")

    assert session.query(WorkflowRun).count() == 0


def test_a_terminal_run_is_not_reported_as_the_groups_run(session):
    run = create_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    cancel_run(session, run=run)
    _grant(session, "g-1")

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))

    assert group.run_id is None


def test_another_tenants_run_is_never_attached_to_this_tenants_group(session):
    create_run(
        session,
        tenant_id="t2",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    _grant(session, "g-1")

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))

    assert group.run_id is None


# ── Lazy run creation on open ───────────────────────────────────────────────


def test_opening_a_workflow_creates_a_run_lazily(session):
    _grant(session, "g-1")

    build_workflow_delta(
        session,
        tenant_id="t1",
        workflow_id="OAUTH_REVIEW",
        created_by="tech@msp.example",
        ensure_run=True,
    )

    run = get_active_run(session, tenant_id="t1", workflow_definition_key="OAUTH_REVIEW")
    assert run is not None


def test_opening_a_workflow_twice_reuses_the_same_run(session):
    _grant(session, "g-1")

    for _ in range(3):
        build_workflow_delta(
            session,
            tenant_id="t1",
            workflow_id="OAUTH_REVIEW",
            created_by="tech@msp.example",
            ensure_run=True,
        )

    assert session.query(WorkflowRun).count() == 1


def test_opening_a_workflow_without_ensure_run_creates_nothing(session):
    _grant(session, "g-1")

    build_workflow_delta(session, tenant_id="t1", workflow_id="OAUTH_REVIEW")

    assert session.query(WorkflowRun).count() == 0


def test_the_delta_reports_the_run_it_belongs_to(session):
    _grant(session, "g-1")

    delta = build_workflow_delta(
        session,
        tenant_id="t1",
        workflow_id="OAUTH_REVIEW",
        created_by="tech@msp.example",
        ensure_run=True,
    )

    assert delta["run"]["id"] is not None
    assert delta["run"]["state"] == RunState.CREATED


# ── Progress is resource-driven ─────────────────────────────────────────────


def test_progress_counts_resources_not_stages(session):
    for i in range(10):
        finding = _grant(session, f"reviewed-{i}")
        record_review_for_finding(
            session,
            finding=finding,
            workflow_type="OAUTH_REVIEW",
            decision=ReviewDecision.KEEP,
            reviewed_by="tech@msp.example",
            reason=None,
        )
    for i in range(4):
        _grant(session, f"new-{i}")

    group = _oauth_group(build_work_queue(session, tenant_id="t1"))
    progress = build_progress(group)

    assert progress.total_resources == 14
    assert progress.reviewed_resources == 10
    assert progress.remaining_resources == 4
    assert progress.percent_complete == 71


def test_progress_of_an_untouched_workflow_is_zero(session):
    for i in range(4):
        _grant(session, f"new-{i}")

    progress = build_progress(_oauth_group(build_work_queue(session, tenant_id="t1")))

    assert progress.total_resources == 4
    assert progress.reviewed_resources == 0
    assert progress.percent_complete == 0


def test_progress_of_a_fully_reviewed_workflow_is_complete(session):
    for i in range(3):
        finding = _grant(session, f"g-{i}")
        record_review_for_finding(
            session,
            finding=finding,
            workflow_type="OAUTH_REVIEW",
            decision=ReviewDecision.KEEP,
            reviewed_by="tech@msp.example",
            reason=None,
        )

    progress = build_progress(_oauth_group(build_work_queue(session, tenant_id="t1")))

    assert progress.percent_complete == 100
    assert progress.remaining_resources == 0
    assert progress.is_complete is True


def test_progress_of_an_empty_workflow_is_complete_not_a_division_error(session):
    from app.services.work.work_item import WorkGroup

    empty = WorkGroup(
        workflow_id="OAUTH_REVIEW",
        workflow_name="OAuth Review",
        category="IDENTITY",
        tenant_id="t1",
        tenant_name="Contoso",
        item_count=0,
        priority="NORMAL",
        estimated_minutes=0,
        recommended_action="",
        summary="",
        cadence="MONTHLY",
    )
    progress = build_progress(empty)

    assert progress.total_resources == 0
    assert progress.percent_complete == 100
    assert progress.is_complete is True


def test_changed_resources_count_as_remaining_work(session):
    finding = _grant(session, "g-1", scopes=["Mail.Read"])
    record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )
    finding.evidence = {**finding.evidence, "scopes": ["Mail.Read", "Mail.ReadWrite"]}
    session.commit()

    progress = build_progress(_oauth_group(build_work_queue(session, tenant_id="t1")))

    assert progress.remaining_resources == 1
    assert progress.reviewed_resources == 0
    assert progress.percent_complete == 0
