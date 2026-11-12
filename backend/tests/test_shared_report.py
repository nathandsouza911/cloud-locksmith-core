"""The workflow evidence report.

Built from what actually happened — the run, its decisions and its verification
outcome — never directly from findings. A report must state what was done, not
re-derive what is currently wrong.
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
from app.services.workflows._shared.report import (
    build_workflow_report,
    persist_workflow_report,
)
from app.services.workflows._shared.review_session import open_review, record_decision

# Import for the registration side effect. Without it these tests would exercise
# the default projector when run alone and Identity Hygiene's real one when run
# after a suite that imports it — an order-dependent risk_level below. Binding
# the workflow to its real projector is what makes this file deterministic.
import app.services.workflows.identity_hygiene  # noqa: F401

WORKFLOW = "IDENTITY_HYGIENE"
CONTROL = "IDENTITY_USER_NO_MFA"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


def _install_postgres_shims(engine):
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


def _finding(session, *, resource_id="user-1", tenant_id="t1", control_id=CONTROL, severity="HIGH"):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="USER",
        resource_id=resource_id,
        passed=False,
        severity=severity,
        exposure_status=ExposureStatus.ACTIVE.value,
        evidence={"user_principal_name": f"{resource_id}@contoso.com"},
    )
    session.add(finding)
    session.commit()
    return finding


def _reviewed(session, decision=ReviewDecision.KEEP, resource_id="user-1"):
    _finding(session, resource_id=resource_id)
    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id=resource_id,
        decision=decision,
        actor="tech",
    )
    return review.run


def test_report_counts_decisions_by_kind(session):
    run = _reviewed(session, ReviewDecision.KEEP, "u1")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="u1",
        decision=ReviewDecision.IGNORE,
        actor="tech",
    )
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    # Superseded rows still count: the report is the history of the run.
    assert report["kept"] == 1
    assert report["ignored"] == 1


def test_report_names_the_workflow_and_the_client(session):
    run = _reviewed(session)
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert report["workflow"] == WORKFLOW
    assert report["tenant_name"] == "Contoso"
    assert report["report_type"] == "IDENTITY_HYGIENE_SUMMARY"


def test_report_lists_who_reviewed(session):
    run = _reviewed(session)
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert report["reviewed_by"] == ["tech"]


def test_report_survives_the_findings_being_deleted(session):
    """The report is built from decisions, so it must not depend on findings."""
    run = _reviewed(session)
    session.query(ComplianceResult).delete()
    session.commit()

    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert report["resources_reviewed"] == 1
    assert report["decisions"][0]["resource_id"] == "user-1"


def test_report_only_includes_decisions_from_this_run(session):
    run = _reviewed(session, resource_id="u1")
    other = WorkflowRun(
        tenant_id="t1",
        workflow_definition_key=WORKFLOW,
        created_by="x",
        state="COMPLETED",
        summary={},
        run_metadata={},
    )
    session.add(other)
    session.commit()
    session.add(
        WorkflowReviewDecision(
            tenant_id="t1",
            workflow_type=WORKFLOW,
            control_id=CONTROL,
            resource_type="USER",
            resource_id="elsewhere",
            decision="KEEP",
            reviewed_by="someone",
            evidence_hash="h",
            workflow_run_id=other.id,
        )
    )
    session.commit()

    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert [row["resource_id"] for row in report["decisions"]] == ["u1"]


def test_another_tenants_decisions_never_appear(session):
    run = _reviewed(session, resource_id="u1")
    session.add(
        WorkflowReviewDecision(
            tenant_id="t2",
            workflow_type=WORKFLOW,
            control_id=CONTROL,
            resource_type="USER",
            resource_id="theirs",
            decision="KEEP",
            reviewed_by="other-tenant",
            evidence_hash="h",
            workflow_run_id=run.id,
        )
    )
    session.commit()

    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert "other-tenant" not in report["reviewed_by"]
    assert all(row["resource_id"] != "theirs" for row in report["decisions"])


def test_outstanding_risks_reflect_reality_at_report_time(session):
    run = _reviewed(session, resource_id="u1")
    _finding(session, resource_id="u2")  # never reviewed
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert [row["resource_id"] for row in report["outstanding_risks"]] == ["u2"]


def test_evidence_references_link_decisions_to_their_fingerprints(session):
    run = _reviewed(session)
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    reference = report["evidence_references"][0]
    assert reference["resource_id"] == "user-1"
    assert reference["evidence_hash"]
    assert reference["decision_id"]


def test_verification_is_not_required_when_nothing_was_remediated(session):
    run = _reviewed(session, ReviewDecision.KEEP)
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert report["verification"]["required"] is False
    assert report["verification"]["status"] == "NOT_REQUIRED"


def test_verification_is_pending_when_something_was_remediated(session):
    run = _reviewed(session, ReviewDecision.REVOKE)
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert report["verification"]["required"] is True
    assert report["verification"]["status"] == "PENDING"
    assert report["verification"]["remediated_resource_ids"] == ["user-1"]


def test_verification_reports_what_the_run_recorded(session):
    run = _reviewed(session, ReviewDecision.REVOKE)
    run.run_metadata = {
        "verification_status": "VERIFIED",
        "verification_completed_at": "2026-08-01T10:00:00Z",
    }
    session.commit()
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    assert report["verification"]["status"] == "VERIFIED"
    assert report["verification"]["verified_at"] == "2026-08-01T10:00:00Z"


def test_two_controls_sharing_a_resource_id_do_not_cross_contaminate_decision_rows(session):
    """Resource identity is (control_id, resource_id), not resource_id alone.

    IDENTITY_HYGIENE's controls can all fire on the same user object, so a
    lookup keyed on resource_id alone would collide and attribute one
    control's risk_level to a decision recorded against a different control.
    """
    other_control = "IDENTITY_UNUSED_ACCOUNT"
    _finding(session, resource_id="user-1", control_id=CONTROL, severity="HIGH")
    _finding(session, resource_id="user-1", control_id=other_control, severity="LOW")

    review = open_review(session, tenant_id="t1", workflow_id=WORKFLOW, actor="tech")
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=CONTROL,
        resource_id="user-1",
        decision=ReviewDecision.KEEP,
        actor="tech",
    )
    record_decision(
        session,
        tenant_id="t1",
        workflow_id=WORKFLOW,
        control_id=other_control,
        resource_id="user-1",
        decision=ReviewDecision.IGNORE,
        actor="tech",
    )
    run = review.run

    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)

    # Distinct levels are the point: each row must carry the risk of *its own*
    # control. The values come from Identity Hygiene's classifier — HIGH for no
    # MFA, MEDIUM for a dormant account holding no privileged roles — which is
    # why the second is MEDIUM rather than the LOW severity on the finding.
    rows = {row["control_id"]: row for row in report["decisions"]}
    assert rows[CONTROL]["risk_level"] == "HIGH"
    assert rows[other_control]["risk_level"] == "MEDIUM"


def test_persisting_archives_through_the_existing_reporting_engine(session):
    run = _reviewed(session)
    report = build_workflow_report(session, tenant_id="t1", run=run, workflow_id=WORKFLOW)
    payload = persist_workflow_report(session, tenant_id="t1", workflow_id=WORKFLOW, report=report)
    assert payload.report_type == "IDENTITY_HYGIENE_SUMMARY"
    assert payload.content_hash
