"""The generic review session — run lifecycle, delta, progress, decisions.

Every assertion here is workflow-agnostic. Anything needing to know what OAuth
or Identity Hygiene *mean* belongs in that workflow's own test file.
"""

import uuid

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.services.work.delta_engine import DeltaState
from app.services.workflow_runtime.state_machine import RunState
from app.services.workflows._shared.review_session import (
    STAGE_DISCOVER,
    STAGE_REVIEW,
    WorkflowReviewError,
    complete_review,
    open_review,
    record_decision,
)

WORKFLOW = "IDENTITY_HYGIENE"
CONTROL = "IDENTITY_USER_NO_MFA"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


def _install_postgres_shims(engine):
    """Teach SQLite the two Postgres functions the archival service uses."""

    @event.listens_for(engine, "connect")
    def _register(dbapi_connection, _record):
        dbapi_connection.create_function("hashtext", 1, lambda value: hash(value))
        dbapi_connection.create_function("pg_advisory_xact_lock", 1, lambda _k: None)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    _install_postgres_shims(engine)
    for model in (
        Tenant,
        ComplianceResult,
        WorkflowRun,
        WorkflowStage,
        WorkflowReviewDecision,
        ReportPayload,
    ):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=uuid.uuid4()))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    db.commit()
    yield db
    db.close()


def _finding(session, *, resource_id="user-1", tenant_id="t1", control_id=CONTROL, severity="HIGH", evidence=None):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="USER",
        resource_id=resource_id,
        passed=False,
        severity=severity,
        exposure_status=ExposureStatus.ACTIVE.value,
        evidence=evidence or {"user_principal_name": f"{resource_id}@contoso.com"},
    )
    session.add(finding)
    session.commit()
    return finding


# ── Opening ─────────────────────────────────────────────────────────────────


def test_opening_creates_a_run_and_walks_it_to_ready_for_review(session):
    _finding(session)
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.run.state == RunState.READY_FOR_REVIEW


def test_opening_records_a_completed_discover_stage(session):
    _finding(session)
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    discover = next(s for s in review.stages if s.stage_key == STAGE_DISCOVER)
    assert discover.state == "COMPLETED"
    assert discover.stage_metadata["resources_discovered"] == 1


def test_opening_twice_reuses_the_same_run(session):
    _finding(session)
    first = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    second = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert first.run.id == second.run.id


def test_opening_only_sees_this_tenants_findings(session):
    _finding(session, resource_id="mine", tenant_id="t1")
    _finding(session, resource_id="theirs", tenant_id="t2")
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert [r.resource_id for r in review.resources] == ["mine"]


def test_opening_ignores_findings_belonging_to_another_workflow(session):
    _finding(session, control_id="IDENTITY_ILLICIT_CONSENT_GRANTS")
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.resources == []


def test_opening_ignores_resolved_findings(session):
    finding = _finding(session)
    finding.exposure_status = ExposureStatus.RESOLVED.value
    session.commit()
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.resources == []


def test_an_unknown_workflow_is_refused(session):
    with pytest.raises(WorkflowReviewError, match="Unknown workflow"):
        open_review(session, tenant_id="t1", workflow_id="NOPE", actor="tech")


# ── Delta and progress ──────────────────────────────────────────────────────


def test_a_never_reviewed_resource_is_new(session):
    _finding(session)
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.resources[0].delta_state == DeltaState.NEW


def test_progress_counts_resources_needing_attention_as_remaining(session):
    _finding(session, resource_id="u1")
    _finding(session, resource_id="u2")
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.progress.total_resources == 2
    assert review.progress.remaining_resources == 2
    assert review.progress.percent_complete == 0


def test_a_kept_resource_becomes_settled_and_progress_advances(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    review = record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    assert review.resources[0].delta_state == DeltaState.PREVIOUSLY_REVIEWED
    assert review.progress.percent_complete == 100


def test_changed_evidence_reopens_a_previously_kept_resource(session):
    finding = _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    finding.evidence = {"user_principal_name": "renamed@contoso.com", "mfa_registered": False}
    session.commit()

    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.resources[0].delta_state == DeltaState.CHANGED


def test_next_resource_is_the_riskiest_item_still_needing_attention(session):
    _finding(session, resource_id="low", severity="LOW")
    _finding(session, resource_id="high", severity="CRITICAL")
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.next_resource.resource_id == "high"


def test_next_resource_is_none_when_everything_is_settled(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    review = record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    assert review.next_resource is None


# ── Decisions ───────────────────────────────────────────────────────────────


def test_recording_a_decision_moves_the_run_into_review(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    review = record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    assert review.run.state == RunState.IN_REVIEW
    assert any(s.stage_key == STAGE_REVIEW for s in review.stages)


def test_the_decision_is_attributed_to_the_run_and_the_workflow(session):
    _finding(session, resource_id="u1")
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    stored = session.query(WorkflowReviewDecision).one()
    assert stored.workflow_run_id == review.run.id
    assert stored.workflow_type == WORKFLOW
    assert stored.reviewed_by == "tech"


def test_deciding_on_a_resource_this_tenant_cannot_see_is_refused(session):
    """The cross-tenant guard: another tenant's resource is simply not in this
    tenant's projection."""
    _finding(session, resource_id="theirs", tenant_id="t2")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    with pytest.raises(WorkflowReviewError, match="not part of"):
        record_decision(
            session,
            tenant_id="t1",
            workflow_id=WORKFLOW,
            control_id=CONTROL,
            resource_id="theirs",
            decision=ReviewDecision.KEEP,
            actor="tech",
        )


def test_a_cross_tenant_decision_attempt_writes_nothing(session):
    """Refusing must not leave a partial record behind."""
    _finding(session, resource_id="theirs", tenant_id="t2")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    with pytest.raises(WorkflowReviewError):
        record_decision(
            session,
            tenant_id="t1",
            workflow_id=WORKFLOW,
            control_id=CONTROL,
            resource_id="theirs",
            decision=ReviewDecision.KEEP,
            actor="tech",
        )
    assert session.query(WorkflowReviewDecision).count() == 0


def test_deciding_without_an_open_review_is_refused(session):
    _finding(session, resource_id="u1")
    with pytest.raises(WorkflowReviewError, match="No open"):
        record_decision(
            session,
            tenant_id="t1",
            workflow_id=WORKFLOW,
            control_id=CONTROL,
            resource_id="u1",
            decision=ReviewDecision.KEEP,
            actor="tech",
        )


def test_a_decision_the_workflow_does_not_declare_is_refused(session):
    """Registry-declared actions bound what may be recorded."""
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    with pytest.raises(WorkflowReviewError, match="does not offer"):
        record_decision(
            session,
            tenant_id="t1",
            workflow_id=WORKFLOW,
            control_id=CONTROL,
            resource_id="u1",
            decision=ReviewDecision.FIX,
            actor="tech",
        )


def test_re_deciding_supersedes_rather_than_overwrites(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    for decision in (ReviewDecision.KEEP, ReviewDecision.IGNORE):
        record_decision(
            session,
            tenant_id="t1",
            workflow_id=WORKFLOW,
            control_id=CONTROL,
            resource_id="u1",
            decision=decision,
            actor="tech",
        )
    rows = session.query(WorkflowReviewDecision).all()
    assert len(rows) == 2
    assert sum(1 for row in rows if row.superseded_at is None) == 1


# ── Completion ──────────────────────────────────────────────────────────────


def test_completing_with_outstanding_resources_is_refused(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    with pytest.raises(WorkflowReviewError, match="still need"):
        complete_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")


def test_completing_closes_the_run_and_freezes_a_summary(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    review = complete_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.run.state == RunState.COMPLETED
    assert review.run.summary["resources_reviewed"] == 1


def test_completing_calls_the_supplied_report_builder(session):
    _finding(session, resource_id="u1")
    open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    calls = []

    def builder(db, *, tenant_id, run, workflow_id):
        calls.append((tenant_id, workflow_id))
        return {"resources_reviewed": 1}

    complete_review(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        actor="tech",
        report_builder=builder,
    )
    assert calls == [("t1", WORKFLOW)]


def test_completing_a_review_with_nothing_to_do_is_allowed(session):
    """A tenant with no findings has a legitimately empty, completable review."""
    review = complete_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    assert review.run.state == RunState.COMPLETED
