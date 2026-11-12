"""Sprint 2 — review decision persistence and supersession."""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.services.work.review_service import (
    InvalidDecisionError,
    get_active_decisions,
    get_decision_history,
    record_review_decision,
    record_review_for_finding,
)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    # Sprint 4: review decisions FK to workflow_runs and the queue reads
    # them. No runs are created in these modules, so every assertion below
    # still describes pre-Sprint-4 behaviour — the regression protection.
    WorkflowRun.__table__.create(engine)
    WorkflowStage.__table__.create(engine)
    WorkflowReviewDecision.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=uuid.uuid4()))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    db.commit()
    yield db
    db.close()


def _record(session, **overrides):
    payload = {
        "tenant_id": "t1",
        "workflow_type": "OAUTH_REVIEW",
        "control_id": "IDENTITY_ILLICIT_CONSENT_GRANTS",
        "resource_type": "SERVICE_PRINCIPAL",
        "resource_id": "grant-1",
        "decision": ReviewDecision.KEEP,
        "reason": None,
        "reviewed_by": "tech@msp.example",
        "evidence_hash": "a" * 64,
    }
    payload.update(overrides)
    return record_review_decision(session, **payload)


def _finding(
    session, control_id="IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="grant-1", evidence=None, tenant_id="t1"
):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        passed=False,
        severity="HIGH",
        evidence=evidence or {"client_id": "app-1", "scopes": ["Mail.Read"]},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


# ── Persistence ─────────────────────────────────────────────────────────────


def test_a_decision_is_persisted(session):
    decision = _record(session)

    stored = session.query(WorkflowReviewDecision).one()
    assert stored.id == decision.id
    assert stored.decision == ReviewDecision.KEEP
    assert stored.reviewed_by == "tech@msp.example"
    assert stored.evidence_hash == "a" * 64
    assert stored.superseded_by is None
    assert stored.reviewed_at is not None


def test_a_reason_is_persisted_when_given(session):
    _record(session, decision=ReviewDecision.IGNORE, reason="Sanctioned by the client")

    assert session.query(WorkflowReviewDecision).one().reason == "Sanctioned by the client"


@pytest.mark.parametrize(
    "decision",
    [ReviewDecision.KEEP, ReviewDecision.IGNORE, ReviewDecision.FIX, ReviewDecision.ESCALATE],
)
def test_every_supported_decision_can_be_recorded(session, decision):
    assert _record(session, decision=decision).decision == decision


def test_an_unsupported_decision_is_rejected(session):
    with pytest.raises(InvalidDecisionError):
        _record(session, decision="DELETE_EVERYTHING")

    assert session.query(WorkflowReviewDecision).count() == 0


def test_a_decision_without_a_reviewer_is_rejected(session):
    with pytest.raises(ValueError):
        _record(session, reviewed_by="")

    assert session.query(WorkflowReviewDecision).count() == 0


# ── Supersession ────────────────────────────────────────────────────────────


def test_re_reviewing_supersedes_the_previous_decision(session):
    first = _record(session, decision=ReviewDecision.KEEP)
    second = _record(session, decision=ReviewDecision.IGNORE)

    session.refresh(first)
    assert first.superseded_by == second.id
    assert second.superseded_by is None


def test_supersession_preserves_history_rather_than_overwriting(session):
    _record(session, decision=ReviewDecision.KEEP)
    _record(session, decision=ReviewDecision.FIX)
    _record(session, decision=ReviewDecision.IGNORE)

    assert session.query(WorkflowReviewDecision).count() == 3


def test_only_one_decision_stays_active_per_resource(session):
    _record(session)
    _record(session)
    _record(session)

    active = session.query(WorkflowReviewDecision).filter(WorkflowReviewDecision.superseded_by.is_(None)).all()
    assert len(active) == 1


def test_history_is_returned_newest_first(session):
    _record(session, decision=ReviewDecision.KEEP)
    _record(session, decision=ReviewDecision.FIX)

    history = get_decision_history(
        session,
        tenant_id="t1",
        workflow_type="OAUTH_REVIEW",
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_id="grant-1",
    )

    assert [entry.decision for entry in history] == [ReviewDecision.FIX, ReviewDecision.KEEP]


# ── Scoping ─────────────────────────────────────────────────────────────────


def test_a_different_resource_gets_its_own_decision(session):
    _record(session, resource_id="grant-1")
    _record(session, resource_id="grant-2")

    active = get_active_decisions(session, tenant_id="t1", workflow_type="OAUTH_REVIEW")
    assert len(active) == 2


def test_the_same_resource_in_a_different_workflow_is_reviewed_independently(session):
    """A resource can be judged differently by two workflows."""
    _record(session, workflow_type="OAUTH_REVIEW", decision=ReviewDecision.KEEP)
    _record(session, workflow_type="ADMIN_REVIEW", decision=ReviewDecision.ESCALATE)

    oauth = get_active_decisions(session, tenant_id="t1", workflow_type="OAUTH_REVIEW")
    admin = get_active_decisions(session, tenant_id="t1", workflow_type="ADMIN_REVIEW")

    assert list(oauth.values())[0].decision == ReviewDecision.KEEP
    assert list(admin.values())[0].decision == ReviewDecision.ESCALATE


def test_active_decisions_exclude_superseded_rows(session):
    _record(session, decision=ReviewDecision.KEEP)
    _record(session, decision=ReviewDecision.IGNORE)

    active = get_active_decisions(session, tenant_id="t1", workflow_type="OAUTH_REVIEW")

    assert len(active) == 1
    assert list(active.values())[0].decision == ReviewDecision.IGNORE


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_decisions_never_leak_across_tenants(session):
    _record(session, tenant_id="t1", resource_id="mine")
    _record(session, tenant_id="t2", resource_id="theirs")

    active = get_active_decisions(session, tenant_id="t1", workflow_type="OAUTH_REVIEW")

    assert len(active) == 1
    assert all(d.tenant_id == "t1" for d in active.values())


def test_one_tenants_review_never_supersedes_anothers(session):
    first = _record(session, tenant_id="t1")
    _record(session, tenant_id="t2")

    session.refresh(first)
    assert first.superseded_by is None


def test_history_is_tenant_scoped(session):
    _record(session, tenant_id="t2")

    history = get_decision_history(
        session,
        tenant_id="t1",
        workflow_type="OAUTH_REVIEW",
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_id="grant-1",
    )

    assert history == []


# ── Recording from a finding ────────────────────────────────────────────────


def test_recording_from_a_finding_captures_its_evidence_fingerprint(session):
    finding = _finding(session)

    decision = record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )

    from app.services.work.evidence_fingerprint import fingerprint_finding

    assert decision.evidence_hash == fingerprint_finding(finding)
    assert decision.control_id == finding.control_id
    assert decision.resource_id == finding.resource_id
    assert decision.tenant_id == finding.tenant_id


def test_recording_from_a_finding_with_changed_evidence_yields_a_new_hash(session):
    finding = _finding(session, evidence={"client_id": "app-1", "scopes": ["Mail.Read"]})
    first = record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )

    finding.evidence = {"client_id": "app-1", "scopes": ["Mail.Read", "Mail.ReadWrite"]}
    session.commit()

    second = record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )

    assert first.evidence_hash != second.evidence_hash


# ── Keying ──────────────────────────────────────────────────────────────────


def test_active_decisions_are_keyed_by_control_and_resource(session):
    _record(session, control_id="IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="grant-1")

    active = get_active_decisions(session, tenant_id="t1", workflow_type="OAUTH_REVIEW")

    assert ("IDENTITY_ILLICIT_CONSENT_GRANTS", "grant-1") in active


def test_two_controls_sharing_a_resource_id_do_not_collide(session):
    _record(session, control_id="IDENTITY_ADMIN_NO_MFA", resource_id="user-1")
    _record(session, control_id="IDENTITY_USER_NO_MFA", resource_id="user-1")

    active = get_active_decisions(session, tenant_id="t1", workflow_type="OAUTH_REVIEW")

    assert len(active) == 2
