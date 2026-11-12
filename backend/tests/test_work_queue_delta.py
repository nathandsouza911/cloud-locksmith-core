"""Sprint 2 — the work queue remembers.

The queue now distinguishes previously-reviewed findings from genuinely new
ones, and prioritises accordingly. Sprint 1's behaviour must survive unchanged
when no decisions exist — that regression protection is asserted explicitly in
tests/test_work_queue_service.py, which is left untouched.
"""

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
from app.services.work.delta_engine import DeltaState
from app.services.work.review_service import record_review_for_finding
from app.services.work.work_queue_service import build_work_queue


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


def _grant(session, resource_id, *, scopes=None, tenant_id="t1"):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        passed=False,
        severity="HIGH",
        evidence={
            "client_id": f"app-{resource_id}",
            "publisher": "Acme",
            "consent_type": "Principal",
            "scopes": scopes or ["Mail.Read"],
        },
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _review(session, finding, decision=ReviewDecision.KEEP):
    return record_review_for_finding(
        session,
        finding=finding,
        workflow_type="OAUTH_REVIEW",
        decision=decision,
        reviewed_by="tech@msp.example",
        reason=None,
    )


def _oauth(queue):
    return next(g for g in queue.groups if g.workflow_id == "OAUTH_REVIEW")


# ── The product goal ────────────────────────────────────────────────────────


def test_previously_reviewed_and_new_are_reported_separately(session):
    """14 applications → 10 previously reviewed, 4 new."""
    for i in range(10):
        _review(session, _grant(session, f"reviewed-{i}"))
    for i in range(4):
        _grant(session, f"new-{i}")

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.item_count == 14
    assert group.reviewed_count == 10
    assert group.new_count == 4


def test_a_fully_reviewed_group_reports_no_new_work(session):
    for i in range(3):
        _review(session, _grant(session, f"g-{i}"))

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.new_count == 0
    assert group.reviewed_count == 3
    assert group.needs_attention_count == 0


def test_an_unreviewed_group_reports_everything_as_new(session):
    for i in range(3):
        _grant(session, f"g-{i}")

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.new_count == 3
    assert group.reviewed_count == 0


# ── Evidence change re-opens a decision ─────────────────────────────────────


def test_a_grant_whose_scopes_escalate_is_reported_as_changed(session):
    finding = _grant(session, "g-1", scopes=["Mail.Read"])
    _review(session, finding)

    finding.evidence = {**finding.evidence, "scopes": ["Mail.Read", "Mail.ReadWrite"]}
    session.commit()

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.changed_count == 1
    assert group.reviewed_count == 0
    assert group.needs_attention_count == 1


def test_an_ignored_grant_that_materially_changes_comes_back(session):
    """A suppression must not survive a material change."""
    finding = _grant(session, "g-1", scopes=["Mail.Read"])
    _review(session, finding, decision=ReviewDecision.IGNORE)

    finding.evidence = {**finding.evidence, "consent_type": "AllPrincipals"}
    session.commit()

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.changed_count == 1
    assert group.needs_attention_count == 1


def test_a_cosmetic_evidence_change_does_not_reopen_a_decision(session):
    finding = _grant(session, "g-1", scopes=["Mail.Read", "Files.Read.All"])
    _review(session, finding)

    # Same scopes, different order — not a material change.
    finding.evidence = {**finding.evidence, "scopes": ["Files.Read.All", "Mail.Read"]}
    session.commit()

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.changed_count == 0
    assert group.reviewed_count == 1


def test_re_reviewing_a_changed_grant_settles_it_again(session):
    finding = _grant(session, "g-1", scopes=["Mail.Read"])
    _review(session, finding)
    finding.evidence = {**finding.evidence, "scopes": ["Mail.Read", "Mail.ReadWrite"]}
    session.commit()
    _review(session, finding)

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.changed_count == 0
    assert group.reviewed_count == 1


# ── Triaged but open ────────────────────────────────────────────────────────


@pytest.mark.parametrize("decision", [ReviewDecision.FIX, ReviewDecision.ESCALATE])
def test_a_triaged_grant_still_needs_attention(session, decision):
    _review(session, _grant(session, "g-1"), decision=decision)

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.needs_attention_count == 1
    assert group.reviewed_count == 0


# ── Items carry their delta state ───────────────────────────────────────────


def test_each_item_reports_its_delta_state(session):
    _review(session, _grant(session, "kept"))
    _grant(session, "fresh")

    group = _oauth(build_work_queue(session, tenant_id="t1"))
    states = {item.resource_id: item.delta_state for item in group.items}

    assert states["kept"] == DeltaState.PREVIOUSLY_REVIEWED
    assert states["fresh"] == DeltaState.NEW


def test_new_items_sort_above_previously_reviewed_items(session):
    _review(session, _grant(session, "kept"))
    _grant(session, "fresh")

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.items[0].resource_id == "fresh"


# ── Group prioritisation ────────────────────────────────────────────────────


def test_a_group_with_new_work_sorts_above_a_fully_reviewed_group(session):
    # Guest group: fully reviewed.
    guest = ComplianceResult(
        tenant_id="t1",
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id="t1",
        passed=False,
        severity="CRITICAL",
        evidence={},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(guest)
    session.commit()
    session.refresh(guest)
    record_review_for_finding(
        session,
        finding=guest,
        workflow_type="GUEST_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )

    # OAuth group: brand new, lower severity.
    _grant(session, "fresh")

    queue = build_work_queue(session, tenant_id="t1")

    assert queue.groups[0].workflow_id == "OAUTH_REVIEW"


def test_estimated_effort_covers_only_work_that_still_needs_attention(session):
    for i in range(10):
        _review(session, _grant(session, f"reviewed-{i}"))
    for i in range(4):
        _grant(session, f"new-{i}")

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    from app.services.work.priority import estimate_group_minutes
    from app.services.work.workflow_registry import get_workflow

    assert group.estimated_minutes == estimate_group_minutes(get_workflow("OAUTH_REVIEW"), item_count=4)


def test_a_fully_reviewed_group_costs_no_estimated_time(session):
    _review(session, _grant(session, "g-1"))

    assert _oauth(build_work_queue(session, tenant_id="t1")).estimated_minutes == 0


# ── Summary ─────────────────────────────────────────────────────────────────


def test_summary_reports_fleet_wide_new_and_reviewed_counts(session):
    for i in range(3):
        _review(session, _grant(session, f"reviewed-{i}"))
    for i in range(2):
        _grant(session, f"new-{i}")

    summary = build_work_queue(session, tenant_id="t1").summary

    assert summary.new_count == 2
    assert summary.reviewed_count == 3


def test_today_count_excludes_groups_with_nothing_left_to_do(session):
    _review(session, _grant(session, "settled"))

    summary = build_work_queue(session, tenant_id="t1").summary

    assert summary.today_count == 0


# ── Scoping ─────────────────────────────────────────────────────────────────


def test_another_tenants_decisions_never_suppress_this_tenants_work(session):
    _grant(session, "shared-id", tenant_id="t1")
    finding_b = _grant(session, "shared-id", tenant_id="t2")
    _review(session, finding_b)

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.new_count == 1
    assert group.reviewed_count == 0


def test_a_decision_recorded_under_another_workflow_does_not_suppress_this_one(session):
    finding = _grant(session, "g-1")
    record_review_for_finding(
        session,
        finding=finding,
        workflow_type="ADMIN_REVIEW",
        decision=ReviewDecision.KEEP,
        reviewed_by="tech@msp.example",
        reason=None,
    )

    group = _oauth(build_work_queue(session, tenant_id="t1"))

    assert group.new_count == 1
    assert group.reviewed_count == 0
