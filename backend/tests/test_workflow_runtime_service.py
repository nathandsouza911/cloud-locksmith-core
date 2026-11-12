"""Sprint 4 — the workflow runtime service.

Generic lifecycle management. The service creates, loads, advances, completes
and cancels runs. It contains no workflow-specific behaviour: it never asks
what OAuth Review means, only what state a run is in and whether a transition
is legal.
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.db.models.workflow_run import RunTrigger, WorkflowRun, WorkflowStage
from app.services.workflow_runtime.runtime_service import (
    UnknownWorkflowDefinition,
    advance_run,
    cancel_run,
    complete_run,
    create_run,
    get_active_run,
    get_or_create_active_run,
    get_run,
    list_active_runs,
    start_stage,
    complete_stage,
    skip_stage,
)
from app.services.workflow_runtime.state_machine import (
    InvalidStateTransition,
    RunState,
    StageState,
)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    for model in (Tenant, WorkflowRun, WorkflowStage, WorkflowReviewDecision):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=uuid.uuid4()))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    db.commit()
    yield db
    db.close()


def _create(session, *, tenant_id="t1", key="OAUTH_REVIEW", **kwargs):
    return create_run(
        session,
        tenant_id=tenant_id,
        workflow_definition_key=key,
        created_by="tech@msp.example",
        **kwargs,
    )


# ── Creation ────────────────────────────────────────────────────────────────


def test_a_run_starts_in_the_created_state(session):
    run = _create(session)

    assert run.state == RunState.CREATED
    assert run.tenant_id == "t1"
    assert run.workflow_definition_key == "OAUTH_REVIEW"
    assert run.created_by == "tech@msp.example"
    assert run.completed_at is None


def test_a_run_records_what_triggered_it(session):
    run = _create(session, trigger=RunTrigger.MANUAL)

    assert run.trigger == RunTrigger.MANUAL


def test_lazy_is_the_default_trigger(session):
    assert _create(session).trigger == RunTrigger.LAZY


def test_a_run_for_an_unknown_definition_is_rejected(session):
    """The runtime references the registry; it cannot run a workflow that is
    not defined."""
    with pytest.raises(UnknownWorkflowDefinition):
        _create(session, key="NOT_A_WORKFLOW")

    assert session.query(WorkflowRun).count() == 0


def test_a_run_stores_no_definition_metadata(session):
    """Definition data must never be copied into runtime tables."""
    run = _create(session)

    for forbidden in ("name", "description", "supported_controls", "category"):
        assert not hasattr(run, forbidden), f"run duplicates definition field {forbidden}"


# ── Idempotent / concurrent creation ────────────────────────────────────────


def test_only_one_active_run_exists_per_workflow_per_tenant(session):
    first = get_or_create_active_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    second = get_or_create_active_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )

    assert first.id == second.id
    assert session.query(WorkflowRun).count() == 1


def test_get_or_create_returns_the_existing_run_rather_than_a_new_one(session):
    existing = _create(session)
    advance_run(session, run=existing, target_state=RunState.DISCOVERING)

    resolved = get_or_create_active_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="someone.else@msp.example",
    )

    assert resolved.id == existing.id
    assert resolved.state == RunState.DISCOVERING


def test_a_second_run_is_created_once_the_first_reaches_a_terminal_state(session):
    first = _create(session)
    cancel_run(session, run=first)

    second = get_or_create_active_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )

    assert second.id != first.id
    assert session.query(WorkflowRun).count() == 2


def test_creating_a_duplicate_active_run_directly_is_refused_by_the_database(session):
    """The partial unique index is the concurrency control — not application
    logic that a second process could race past."""
    _create(session)

    session.add(
        WorkflowRun(
            tenant_id="t1",
            workflow_definition_key="OAUTH_REVIEW",
            created_by="racer@msp.example",
            state=RunState.CREATED,
        )
    )
    with pytest.raises(Exception):
        session.commit()
    session.rollback()


def test_two_tenants_may_each_have_an_active_run_for_the_same_workflow(session):
    a = get_or_create_active_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    b = get_or_create_active_run(
        session,
        tenant_id="t2",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )

    assert a.id != b.id


def test_one_tenant_may_have_active_runs_for_different_workflows(session):
    a = _create(session, key="OAUTH_REVIEW")
    b = _create(session, key="GUEST_REVIEW")

    assert a.id != b.id


# ── State transitions ───────────────────────────────────────────────────────


def test_advancing_a_run_persists_the_new_state(session):
    run = _create(session)

    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    session.refresh(run)

    assert run.state == RunState.DISCOVERING


def test_an_illegal_transition_is_refused_and_leaves_the_run_untouched(session):
    run = _create(session)

    with pytest.raises(InvalidStateTransition):
        advance_run(session, run=run, target_state=RunState.COMPLETED)

    session.refresh(run)
    assert run.state == RunState.CREATED


def test_a_completed_run_cannot_be_advanced_again(session):
    run = _create(session)
    for state in (
        RunState.DISCOVERING,
        RunState.READY_FOR_REVIEW,
        RunState.IN_REVIEW,
    ):
        advance_run(session, run=run, target_state=state)
    complete_run(session, run=run)

    with pytest.raises(InvalidStateTransition):
        advance_run(session, run=run, target_state=RunState.DISCOVERING)


def test_started_at_is_stamped_when_discovery_begins(session):
    run = _create(session)
    assert run.started_at is None

    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    session.refresh(run)

    assert run.started_at is not None


def test_completed_at_is_stamped_only_on_a_terminal_state(session):
    run = _create(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    session.refresh(run)
    assert run.completed_at is None

    advance_run(session, run=run, target_state=RunState.CANCELLED)
    session.refresh(run)
    assert run.completed_at is not None


# ── Completion and cancellation ─────────────────────────────────────────────


def test_completing_a_run_from_review_works(session):
    run = _create(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)
    advance_run(session, run=run, target_state=RunState.READY_FOR_REVIEW)
    advance_run(session, run=run, target_state=RunState.IN_REVIEW)

    complete_run(session, run=run, summary={"reviewed": 10, "new": 4})
    session.refresh(run)

    assert run.state == RunState.COMPLETED
    assert run.summary == {"reviewed": 10, "new": 4}
    assert run.completed_at is not None


def test_a_run_can_be_cancelled_from_any_live_state(session):
    run = _create(session)
    advance_run(session, run=run, target_state=RunState.DISCOVERING)

    cancel_run(session, run=run, reason="client postponed")
    session.refresh(run)

    assert run.state == RunState.CANCELLED
    assert run.run_metadata.get("cancel_reason") == "client postponed"


def test_a_cancelled_run_cannot_be_completed(session):
    run = _create(session)
    cancel_run(session, run=run)

    with pytest.raises(InvalidStateTransition):
        complete_run(session, run=run)


# ── Loading ─────────────────────────────────────────────────────────────────


def test_the_active_run_can_be_loaded(session):
    created = _create(session)

    found = get_active_run(session, tenant_id="t1", workflow_definition_key="OAUTH_REVIEW")

    assert found is not None and found.id == created.id


def test_no_active_run_is_returned_once_it_is_terminal(session):
    run = _create(session)
    cancel_run(session, run=run)

    assert get_active_run(session, tenant_id="t1", workflow_definition_key="OAUTH_REVIEW") is None


def test_active_runs_can_be_listed_for_a_tenant(session):
    _create(session, key="OAUTH_REVIEW")
    _create(session, key="GUEST_REVIEW")
    terminal = _create(session, key="ADMIN_REVIEW")
    cancel_run(session, run=terminal)

    active = list_active_runs(session, tenant_id="t1")

    assert {run.workflow_definition_key for run in active} == {
        "OAUTH_REVIEW",
        "GUEST_REVIEW",
    }


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_a_run_is_never_visible_to_another_tenant(session):
    created = _create(session, tenant_id="t2")

    assert get_run(session, tenant_id="t1", run_id=created.id) is None


def test_active_run_lookup_is_tenant_scoped(session):
    _create(session, tenant_id="t2")

    assert get_active_run(session, tenant_id="t1", workflow_definition_key="OAUTH_REVIEW") is None


def test_listing_active_runs_never_crosses_tenants(session):
    _create(session, tenant_id="t2")

    assert list_active_runs(session, tenant_id="t1") == []


# ── Stages ──────────────────────────────────────────────────────────────────


def test_starting_a_stage_creates_it_active(session):
    run = _create(session)

    stage = start_stage(session, run=run, stage_key="DISCOVER")

    assert stage.state == StageState.ACTIVE
    assert stage.started_at is not None
    assert stage.workflow_run_id == run.id


def test_starting_a_stage_records_it_as_the_runs_current_stage(session):
    run = _create(session)

    start_stage(session, run=run, stage_key="DISCOVER")
    session.refresh(run)

    assert run.current_stage == "DISCOVER"


def test_completing_a_stage_stamps_its_end(session):
    run = _create(session)
    start_stage(session, run=run, stage_key="DISCOVER")

    stage = complete_stage(session, run=run, stage_key="DISCOVER")

    assert stage.state == StageState.COMPLETED
    assert stage.completed_at is not None


def test_a_stage_can_be_skipped(session):
    run = _create(session)

    stage = skip_stage(session, run=run, stage_key="EXECUTE")

    assert stage.state == StageState.SKIPPED


def test_completing_a_stage_that_never_started_is_refused(session):
    run = _create(session)
    skip_stage(session, run=run, stage_key="EXECUTE")

    with pytest.raises(InvalidStateTransition):
        complete_stage(session, run=run, stage_key="EXECUTE")


def test_a_stage_key_is_unique_within_a_run(session):
    run = _create(session)
    first = start_stage(session, run=run, stage_key="DISCOVER")
    complete_stage(session, run=run, stage_key="DISCOVER")

    with pytest.raises(InvalidStateTransition):
        start_stage(session, run=run, stage_key="DISCOVER")

    assert session.query(WorkflowStage).count() == 1
    assert first.state == StageState.COMPLETED


def test_stages_are_sequenced_in_creation_order(session):
    run = _create(session)
    start_stage(session, run=run, stage_key="DISCOVER")
    complete_stage(session, run=run, stage_key="DISCOVER")
    start_stage(session, run=run, stage_key="REVIEW")

    stages = (
        session.query(WorkflowStage)
        .filter(WorkflowStage.workflow_run_id == run.id)
        .order_by(WorkflowStage.sequence)
        .all()
    )
    assert [stage.stage_key for stage in stages] == ["DISCOVER", "REVIEW"]


def test_the_same_stage_key_may_exist_in_two_different_runs(session):
    first = _create(session, key="OAUTH_REVIEW")
    second = _create(session, key="GUEST_REVIEW")

    start_stage(session, run=first, stage_key="DISCOVER")
    start_stage(session, run=second, stage_key="DISCOVER")

    assert session.query(WorkflowStage).count() == 2


# ── Genericity ──────────────────────────────────────────────────────────────


def test_the_runtime_accepts_any_registered_workflow(session):
    from app.services.work.workflow_registry import all_workflows

    for definition in all_workflows():
        run = create_run(
            session,
            tenant_id="t1",
            workflow_definition_key=definition.id,
            created_by="tech@msp.example",
        )
        assert run.state == RunState.CREATED


def test_stage_keys_are_not_constrained_by_the_runtime(session):
    """Stage vocabulary belongs to the consumer, not the runtime."""
    run = _create(session)

    stage = start_stage(session, run=run, stage_key="SOMETHING_ENTIRELY_NEW")

    assert stage.stage_key == "SOMETHING_ENTIRELY_NEW"
