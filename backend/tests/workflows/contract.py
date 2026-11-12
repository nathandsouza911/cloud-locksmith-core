"""Behavioural contract every workflow must satisfy.

Subclass ``WorkflowContractTests`` in a ``test_*.py`` module, set
``workflow_id`` and implement the two hooks. Adding a workflow to this suite is
how it inherits the platform's safety guarantees rather than re-asserting them.

The hooks exist because workflows differ in *how* a resource comes to exist —
Identity Hygiene creates one finding per resource, OAuth creates one finding
carrying many grants — while everything asserted below is identical.
"""

from __future__ import annotations

import copy
import uuid

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.services.work.delta_engine import DeltaState
from app.services.work.workflow_registry import WORKFLOW_REGISTRY, review_actions_for
from app.services.workflow_runtime.state_machine import (
    RunState,
    can_transition_run,
)
from app.services.workflows._shared.projector_registry import get_projector
from app.services.workflows._shared.report import (
    build_workflow_report,
    persist_workflow_report,
)
from app.services.workflows._shared.review_session import (
    WorkflowReviewError,
    complete_review,
    open_review,
    record_decision,
)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


def _install_postgres_shims(engine):
    @event.listens_for(engine, "connect")
    def _register(dbapi_connection, _record):
        dbapi_connection.create_function("hashtext", 1, lambda value: hash(value))
        dbapi_connection.create_function("pg_advisory_xact_lock", 1, lambda _k: None)


class WorkflowContractTests:
    """Inherit this to assert a workflow behaves like every other workflow."""

    #: Registry id of the workflow under test.
    workflow_id: str = ""

    # ── Hooks a subclass must implement ─────────────────────────────────────

    def create_resources(self, session, resource_ids, tenant_id="t1") -> None:
        """Create whatever findings make ``resource_ids`` appear in the review."""
        raise NotImplementedError

    def key_for(self, resource_id):
        """The ResourceKey a given resource id projects to."""
        raise NotImplementedError

    # ── Fixtures ────────────────────────────────────────────────────────────

    @pytest.fixture()
    def session(self):
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

    def _open(self, session, tenant_id="t1"):
        return open_review(session, tenant_id=tenant_id, workflow_id=self.workflow_id, actor="tech")

    def _decide(self, session, resource_id, decision, tenant_id="t1"):
        key = self.key_for(resource_id)
        return record_decision(
            session,
            tenant_id=tenant_id,
            workflow_id=self.workflow_id,
            control_id=key.control_id,
            resource_id=key.resource_id,
            decision=decision,
            actor="tech",
        )

    # ── Registry and projector wiring ───────────────────────────────────────

    def test_the_workflow_is_registered_and_enabled(self):
        definition = WORKFLOW_REGISTRY.get(self.workflow_id)
        assert definition is not None, f"{self.workflow_id} is not in the registry"
        assert definition.enabled

    def test_the_workflow_resolves_a_projector_declaring_controls(self):
        projector = get_projector(self.workflow_id)
        assert projector.controls(), f"{self.workflow_id} projects no controls, so it can never discover " "anything"

    def test_the_workflow_declares_actions_the_platform_can_store(self):
        actions = review_actions_for(self.workflow_id)
        assert actions
        for action in actions:
            assert action.decision in ReviewDecision.ALL

    # ── Discovery ───────────────────────────────────────────────────────────

    def test_discovery_never_mutates_the_findings(self, session):
        self.create_resources(session, ["r1", "r2"])
        findings = session.query(ComplianceResult).all()
        before = {f.id: copy.deepcopy(f.evidence) for f in findings}

        self._open(session)

        for finding in session.query(ComplianceResult).all():
            assert finding.evidence == before[finding.id]

    def test_no_two_resources_share_a_key(self, session):
        """A duplicate key would make one decision silently suppress another
        resource. If this fires, ResourceKey needs resource_type."""
        self.create_resources(session, ["r1", "r2", "r3"])
        keys = [resource.key for resource in self._open(session).resources]
        assert len(keys) == len(set(keys)), f"duplicate ResourceKeys: {keys}"

    def test_every_resource_carries_an_evidence_fingerprint(self, session):
        """Without a hash, a decision could never go stale."""
        self.create_resources(session, ["r1"])
        for resource in self._open(session).resources:
            assert resource.evidence_hash

    def test_resource_order_is_stable_between_refreshes(self, session):
        self.create_resources(session, ["r1", "r2", "r3"])
        first = [r.key for r in self._open(session).resources]
        second = [r.key for r in self._open(session).resources]
        assert first == second

    # ── Delta ───────────────────────────────────────────────────────────────

    def test_every_resource_gets_exactly_one_delta_state(self, session):
        self.create_resources(session, ["r1", "r2"])
        for resource in self._open(session).resources:
            assert resource.delta_state in DeltaState.ALL

    def test_an_unreviewed_resource_is_new(self, session):
        self.create_resources(session, ["r1"])
        assert self._open(session).resources[0].delta_state == DeltaState.NEW

    def test_a_kept_resource_becomes_settled(self, session):
        self.create_resources(session, ["r1"])
        self._open(session)
        review = self._decide(session, "r1", ReviewDecision.KEEP)
        assert review.resources[0].delta_state == DeltaState.PREVIOUSLY_REVIEWED
        assert review.resources[0].needs_attention is False

    def test_progress_and_delta_agree(self, session):
        self.create_resources(session, ["r1", "r2"])
        review = self._open(session)
        needing = sum(1 for r in review.resources if r.needs_attention)
        assert review.progress.remaining_resources == needing
        assert review.progress.total_resources == len(review.resources)

    # ── Review memory ───────────────────────────────────────────────────────

    def test_a_decision_round_trips_through_review_memory(self, session):
        self.create_resources(session, ["r1"])
        review = self._open(session)
        self._decide(session, "r1", ReviewDecision.KEEP)

        stored = session.query(WorkflowReviewDecision).one()
        key = self.key_for("r1")
        assert stored.workflow_type == self.workflow_id
        assert stored.control_id == key.control_id
        assert stored.resource_id == key.resource_id
        assert stored.workflow_run_id == review.run.id

    def test_re_deciding_supersedes_rather_than_overwrites(self, session):
        self.create_resources(session, ["r1"])
        self._open(session)
        self._decide(session, "r1", ReviewDecision.KEEP)
        self._decide(session, "r1", ReviewDecision.IGNORE)

        rows = session.query(WorkflowReviewDecision).all()
        assert len(rows) == 2
        assert sum(1 for row in rows if row.superseded_at is None) == 1

    # ── Tenant isolation ────────────────────────────────────────────────────

    def test_another_tenants_resources_are_not_discovered(self, session):
        self.create_resources(session, ["mine"], tenant_id="t1")
        self.create_resources(session, ["theirs"], tenant_id="t2")
        ids = {r.resource_id for r in self._open(session, "t1").resources}
        assert self.key_for("theirs").resource_id not in ids

    def test_deciding_on_another_tenants_resource_is_refused(self, session):
        self.create_resources(session, ["mine"], tenant_id="t1")
        self.create_resources(session, ["theirs"], tenant_id="t2")
        self._open(session, "t1")
        with pytest.raises(WorkflowReviewError):
            self._decide(session, "theirs", ReviewDecision.KEEP, tenant_id="t1")

    def test_a_refused_cross_tenant_decision_writes_nothing(self, session):
        self.create_resources(session, ["mine"], tenant_id="t1")
        self.create_resources(session, ["theirs"], tenant_id="t2")
        self._open(session, "t1")
        with pytest.raises(WorkflowReviewError):
            self._decide(session, "theirs", ReviewDecision.KEEP, tenant_id="t1")
        assert session.query(WorkflowReviewDecision).count() == 0

    def test_one_tenants_report_never_contains_anothers_decisions(self, session):
        self.create_resources(session, ["mine"], tenant_id="t1")
        self.create_resources(session, ["theirs"], tenant_id="t2")
        run = self._open(session, "t1").run
        self._decide(session, "mine", ReviewDecision.KEEP, tenant_id="t1")

        self._open(session, "t2")
        self._decide(session, "theirs", ReviewDecision.KEEP, tenant_id="t2")

        report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=self.workflow_id)
        other = self.key_for("theirs").resource_id
        assert all(row["resource_id"] != other for row in report["decisions"])

    # ── Run lifecycle ───────────────────────────────────────────────────────

    def test_opening_walks_the_run_to_ready_for_review(self, session):
        self.create_resources(session, ["r1"])
        assert self._open(session).run.state == RunState.READY_FOR_REVIEW

    def test_opening_is_idempotent(self, session):
        self.create_resources(session, ["r1"])
        assert self._open(session).run.id == self._open(session).run.id

    def test_the_run_only_makes_legal_transitions(self, session):
        self.create_resources(session, ["r1"])
        review = self._open(session)
        assert can_transition_run(RunState.READY_FOR_REVIEW, RunState.IN_REVIEW)

        review = self._decide(session, "r1", ReviewDecision.KEEP)
        assert review.run.state == RunState.IN_REVIEW

        review = complete_review(session, tenant_id="t1", workflow_id=self.workflow_id, actor="tech")
        assert review.run.state == RunState.COMPLETED

    def test_stages_are_recorded_in_order(self, session):
        self.create_resources(session, ["r1"])
        self._open(session)
        review = self._decide(session, "r1", ReviewDecision.KEEP)
        keys = [stage.stage_key for stage in review.stages]
        assert keys[:2] == ["DISCOVER", "REVIEW"]

    # ── Completion ──────────────────────────────────────────────────────────

    def test_completing_with_outstanding_work_is_refused(self, session):
        self.create_resources(session, ["r1"])
        self._open(session)
        with pytest.raises(WorkflowReviewError, match="still need"):
            complete_review(session, tenant_id="t1", workflow_id=self.workflow_id, actor="tech")

    def test_completing_freezes_a_summary(self, session):
        self.create_resources(session, ["r1"])
        self._open(session)
        self._decide(session, "r1", ReviewDecision.KEEP)
        review = complete_review(session, tenant_id="t1", workflow_id=self.workflow_id, actor="tech")
        assert review.run.summary["resources_reviewed"] == 1

    def test_completing_an_already_completed_review_is_refused(self, session):
        """A completed review must stay closed.

        open_review starts a run when none is live — right for a review being
        worked, wrong for one already finished. Without the guard a second
        completion opens a fresh run and succeeds, because every resource is
        already settled.
        """
        self.create_resources(session, ["r1"])
        self._open(session)
        self._decide(session, "r1", ReviewDecision.KEEP)
        complete_review(session, tenant_id="t1", workflow_id=self.workflow_id, actor="tech")

        with pytest.raises(WorkflowReviewError):
            complete_review(session, tenant_id="t1", workflow_id=self.workflow_id, actor="tech")

    def test_a_repeat_completion_archives_no_second_report(self, session):
        """The defect that matters: a double-click must not overwrite the
        client- and insurer-facing summary with an empty one.

        The report endpoints return the newest ReportPayload, so an extra report
        scoped to a fresh run — containing zero decisions — would replace the
        real evidence artefact and leave a junk entry in the hash-chained
        archive.
        """

        def _persist(db_, *, tenant_id, run, workflow_id):
            report = build_workflow_report(db_, tenant_id=tenant_id, run=run, workflow_id=workflow_id)
            persist_workflow_report(db_, tenant_id=tenant_id, workflow_id=workflow_id, report=report)
            return report

        self.create_resources(session, ["r1"])
        self._open(session)
        self._decide(session, "r1", ReviewDecision.KEEP)
        complete_review(
            session,
            tenant_id="t1",
            workflow_id=self.workflow_id,
            actor="tech",
            report_builder=_persist,
        )

        before = session.query(ReportPayload).count()
        assert before == 1

        with pytest.raises(WorkflowReviewError):
            complete_review(
                session,
                tenant_id="t1",
                workflow_id=self.workflow_id,
                actor="tech",
                report_builder=_persist,
            )

        assert session.query(ReportPayload).count() == before
        # The surviving report is the real one: it records the decision.
        assert session.query(ReportPayload).one().payload["kept"] == 1

    # ── Reporting ───────────────────────────────────────────────────────────

    def test_the_report_is_derivable_from_decisions_alone(self, session):
        """Findings are deleted first: a report must record what was done, not
        re-derive what is currently wrong."""
        self.create_resources(session, ["r1"])
        run = self._open(session).run
        self._decide(session, "r1", ReviewDecision.KEEP)

        session.query(ComplianceResult).delete()
        session.commit()

        report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=self.workflow_id)
        assert report["resources_reviewed"] == 1
        assert report["kept"] == 1
        assert report["workflow"] == self.workflow_id

    def test_the_report_names_the_workflow_and_declares_a_type(self, session):
        self.create_resources(session, ["r1"])
        run = self._open(session).run
        self._decide(session, "r1", ReviewDecision.KEEP)
        report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=self.workflow_id)
        assert report["report_type"]
        assert report["workflow_name"]
