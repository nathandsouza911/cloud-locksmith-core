"""Sprint 1 — work queue service.

Builds the technician work queue as a presentation model over existing
ComplianceResult rows. Nothing is persisted and no finding is mutated.
"""

import uuid
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import (
    ComplianceResult,
    ExposureStatus,
    RemediationStatus,
)
from app.db.models.tenant import Tenant
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.services.work.work_queue_service import build_work_queue


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover - test plumbing
    return "JSON"


def _session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    # Sprint 2: the queue consults review memory. No decisions are recorded in
    # this module, so every assertion below still describes Sprint 1 behaviour
    # — which is exactly the regression protection we want.
    # Sprint 4: review decisions FK to workflow_runs and the queue reads
    # them. No runs are created in these modules, so every assertion below
    # still describes pre-Sprint-4 behaviour — the regression protection.
    WorkflowRun.__table__.create(engine)
    WorkflowStage.__table__.create(engine)
    WorkflowReviewDecision.__table__.create(engine)
    return sessionmaker(bind=engine)()


def _tenant(session, tenant_id="t1", name="Contoso"):
    tenant = Tenant(id=tenant_id, tenant_name=name, organization_id=uuid.uuid4())
    session.add(tenant)
    session.commit()
    return tenant


def _finding(
    session,
    tenant_id,
    control_id,
    *,
    resource_id="r1",
    severity="HIGH",
    passed=False,
    exposure_status=ExposureStatus.ACTIVE.value,
    remediation_status=RemediationStatus.PENDING.value,
    drift_count=0,
    resolved_at=None,
    first_seen_at=None,
):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=resource_id,
        passed=passed,
        severity=severity,
        evidence={},
        exposure_status=exposure_status,
        remediation_status=remediation_status,
        drift_count=drift_count,
        resolved_at=resolved_at,
        first_seen_at=first_seen_at or datetime(2026, 7, 1),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _group_ids(queue):
    return [group.workflow_id for group in queue.groups]


def _group(queue, workflow_id):
    return next(g for g in queue.groups if g.workflow_id == workflow_id)


# ── Work item construction ──────────────────────────────────────────────────


def test_active_finding_becomes_a_work_item_with_presentation_fields():
    session = _session()
    _tenant(session)
    finding = _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS")

    queue = build_work_queue(session, tenant_id="t1")

    item = _group(queue, "OAUTH_REVIEW").items[0]
    assert item.id == finding.id
    assert item.tenant_id == "t1"
    assert item.tenant_name == "Contoso"
    assert item.related_control == "IDENTITY_ILLICIT_CONSENT_GRANTS"
    assert item.category == "IDENTITY"
    assert item.severity == "HIGH"
    assert item.priority == "HIGH"
    assert item.title
    assert item.recommended_action
    assert item.estimated_minutes > 0
    assert item.created_at == datetime(2026, 7, 1)


def test_work_item_title_is_human_readable_not_the_raw_control_id():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_USER_NO_MFA")

    queue = build_work_queue(session, tenant_id="t1")

    assert _group(queue, "IDENTITY_HYGIENE").items[0].title != "IDENTITY_USER_NO_MFA"


# ── Grouping ────────────────────────────────────────────────────────────────


def test_findings_sharing_a_workflow_are_grouped_together():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="a")
    _finding(session, "t1", "IDENTITY_USER_CONSENT_POLICY", resource_id="b")

    queue = build_work_queue(session, tenant_id="t1")

    assert _group_ids(queue) == ["OAUTH_REVIEW"]
    assert _group(queue, "OAUTH_REVIEW").item_count == 2


def test_findings_from_different_workflows_produce_separate_groups():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS")
    _finding(session, "t1", "IDENTITY_GUEST_INVITES_OPEN", severity="MEDIUM")

    queue = build_work_queue(session, tenant_id="t1")

    assert set(_group_ids(queue)) == {"OAUTH_REVIEW", "GUEST_REVIEW"}


def test_unmapped_control_still_surfaces_as_work():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "SOME_BRAND_NEW_CONTROL")

    queue = build_work_queue(session, tenant_id="t1")

    assert _group_ids(queue) == ["GENERAL_REVIEW"]


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_queue_never_contains_another_tenants_findings():
    session = _session()
    _tenant(session, "t1", "Contoso")
    _tenant(session, "t2", "Fabrikam")
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="mine")
    _finding(session, "t2", "IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="theirs")

    queue = build_work_queue(session, tenant_id="t1")

    all_items = [item for group in queue.groups for item in group.items]
    assert len(all_items) == 1
    assert {item.tenant_id for item in all_items} == {"t1"}


def test_completed_count_never_includes_another_tenants_resolved_findings():
    session = _session()
    _tenant(session, "t1")
    _tenant(session, "t2")
    _finding(
        session,
        "t2",
        "IDENTITY_UNUSED_ACCOUNT",
        exposure_status=ExposureStatus.RESOLVED.value,
        remediation_status=RemediationStatus.SUCCESS.value,
        resolved_at=datetime.utcnow() - timedelta(days=1),
    )

    queue = build_work_queue(session, tenant_id="t1")

    assert queue.summary.completed == 0


# ── Exclusions ──────────────────────────────────────────────────────────────


def test_passing_findings_are_not_work():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS", passed=True)

    assert build_work_queue(session, tenant_id="t1").groups == []


def test_resolved_findings_are_not_work():
    session = _session()
    _tenant(session)
    _finding(
        session,
        "t1",
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
        exposure_status=ExposureStatus.RESOLVED.value,
    )

    assert build_work_queue(session, tenant_id="t1").groups == []


def test_ignored_findings_are_not_work():
    session = _session()
    _tenant(session)
    _finding(
        session,
        "t1",
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
        remediation_status=RemediationStatus.IGNORED.value,
    )

    assert build_work_queue(session, tenant_id="t1").groups == []


def test_in_flight_remediation_is_not_presented_as_open_work():
    session = _session()
    _tenant(session)
    _finding(
        session,
        "t1",
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
        remediation_status=RemediationStatus.EXECUTING.value,
    )

    assert build_work_queue(session, tenant_id="t1").groups == []


# ── Priority ────────────────────────────────────────────────────────────────


def test_group_is_high_priority_when_it_contains_a_high_severity_finding():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_USER_NO_MFA", severity="LOW", resource_id="a")
    _finding(session, "t1", "IDENTITY_UNUSED_ACCOUNT", severity="CRITICAL", resource_id="b")

    queue = build_work_queue(session, tenant_id="t1")

    assert _group(queue, "IDENTITY_HYGIENE").priority == "HIGH"


def test_drifted_finding_raises_group_priority():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_UNUSED_ACCOUNT", severity="LOW", drift_count=2)

    queue = build_work_queue(session, tenant_id="t1")

    assert _group(queue, "IDENTITY_HYGIENE").priority == "HIGH"


def test_high_priority_groups_are_ordered_before_normal_priority_groups():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_GUEST_INVITES_OPEN", severity="LOW")
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS", severity="CRITICAL")

    queue = build_work_queue(session, tenant_id="t1")

    assert _group_ids(queue)[0] == "OAUTH_REVIEW"


# ── Summary ─────────────────────────────────────────────────────────────────


def test_summary_counts_groups_by_priority():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS", severity="CRITICAL")
    _finding(session, "t1", "IDENTITY_GUEST_INVITES_OPEN", severity="LOW")

    summary = build_work_queue(session, tenant_id="t1").summary

    assert summary.today_count == 2
    assert summary.high_priority == 1
    assert summary.normal_priority == 1
    assert summary.item_count == 2


def test_summary_estimated_minutes_is_the_sum_of_group_estimates():
    session = _session()
    _tenant(session)
    _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS")
    _finding(session, "t1", "IDENTITY_GUEST_INVITES_OPEN")

    queue = build_work_queue(session, tenant_id="t1")

    assert queue.summary.estimated_minutes == sum(group.estimated_minutes for group in queue.groups)


def test_completed_counts_findings_resolved_in_the_last_seven_days():
    session = _session()
    _tenant(session)
    _finding(
        session,
        "t1",
        "IDENTITY_UNUSED_ACCOUNT",
        resource_id="recent",
        exposure_status=ExposureStatus.RESOLVED.value,
        remediation_status=RemediationStatus.SUCCESS.value,
        resolved_at=datetime.utcnow() - timedelta(days=2),
    )
    _finding(
        session,
        "t1",
        "IDENTITY_UNUSED_ACCOUNT",
        resource_id="stale",
        exposure_status=ExposureStatus.RESOLVED.value,
        remediation_status=RemediationStatus.SUCCESS.value,
        resolved_at=datetime.utcnow() - timedelta(days=30),
    )

    assert build_work_queue(session, tenant_id="t1").summary.completed == 1


def test_empty_tenant_produces_an_empty_queue():
    session = _session()
    _tenant(session)

    queue = build_work_queue(session, tenant_id="t1")

    assert queue.groups == []
    assert queue.summary.today_count == 0
    assert queue.summary.estimated_minutes == 0
    assert queue.summary.high_priority == 0
    assert queue.summary.completed == 0


def test_queue_reports_the_tenant_it_was_built_for():
    session = _session()
    _tenant(session, "t1", "Contoso")

    queue = build_work_queue(session, tenant_id="t1")

    assert queue.tenant_id == "t1"
    assert queue.tenant_name == "Contoso"
    assert queue.generated_at is not None


# ── No mutation ─────────────────────────────────────────────────────────────


def test_building_the_queue_does_not_mutate_findings():
    session = _session()
    _tenant(session)
    finding = _finding(session, "t1", "IDENTITY_ILLICIT_CONSENT_GRANTS")
    before = (
        finding.remediation_status,
        finding.exposure_status,
        finding.acknowledged,
    )

    build_work_queue(session, tenant_id="t1")
    session.refresh(finding)

    assert (
        finding.remediation_status,
        finding.exposure_status,
        finding.acknowledged,
    ) == before
