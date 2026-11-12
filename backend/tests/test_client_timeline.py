"""Sprint 3 — the Client Timeline.

Aggregates existing operational systems into one chronological narrative.
Strictly read-only: it consumes existing data and never duplicates storage or
mutates a source system.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.audit_log import AuditLog
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.services.timeline.timeline_event import SourceSystem, TimelineEventType
from app.services.timeline.timeline_service import build_timeline, decode_cursor


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


BASE = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    for model in (
        Tenant,
        ComplianceResult,
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


# ── Seed helpers, one per source system ─────────────────────────────────────


def _review(
    session,
    *,
    tenant_id="t1",
    minutes_ago=0,
    decision=ReviewDecision.KEEP,
    control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
    resource_id="grant-1",
):
    entry = WorkflowReviewDecision(
        tenant_id=tenant_id,
        workflow_type="OAUTH_REVIEW",
        control_id=control_id,
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        decision=decision,
        reason="because",
        reviewed_by="tech@msp.example",
        reviewed_at=BASE - timedelta(minutes=minutes_ago),
        evidence_hash="a" * 64,
        created_at=BASE - timedelta(minutes=minutes_ago),
    )
    session.add(entry)
    session.commit()
    return entry


def _finding(session, tenant_id="t1"):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id="user-1",
        passed=False,
        severity="HIGH",
        evidence={},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _remediation(session, *, tenant_id="t1", minutes_ago=0, status="SUCCESS"):
    finding = _finding(session, tenant_id)
    entry = RemediationAuditLog(
        compliance_result_id=finding.id,
        tenant_id=tenant_id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id="user-1",
        decision="AUTO",
        confidence=0.9,
        execution_status=status,
        approved_by="tech@msp.example",
        created_at=BASE - timedelta(minutes=minutes_ago),
    )
    session.add(entry)
    session.commit()
    return entry


def _audit(session, *, tenant_id="t1", minutes_ago=0, action="OFFBOARDING"):
    entry = AuditLog(
        tenant_id=tenant_id,
        action=action,
        actor="tech@msp.example",
        target="user-1",
        status="SUCCESS",
        reason=None,
        details={},
        created_at=BASE - timedelta(minutes=minutes_ago),
        sequence_hash="b" * 64,
    )
    session.add(entry)
    session.commit()
    return entry


def _report(session, *, tenant_id="t1", minutes_ago=0, report_type="insurance"):
    entry = ReportPayload(
        tenant_id=tenant_id,
        report_type=report_type,
        payload={},
        content_hash="c" * 64,
        score=80,
        generated_at=BASE - timedelta(minutes=minutes_ago),
    )
    session.add(entry)
    session.commit()
    return entry


def _snapshot(session, *, tenant_id="t1", minutes_ago=0, score=72):
    entry = PostureSnapshot(
        tenant_id=tenant_id,
        posture={},
        security_score=score,
        created_at=BASE - timedelta(minutes=minutes_ago),
    )
    session.add(entry)
    session.commit()
    return entry


def _sources(page):
    return {event.source_system for event in page.events}


# ── Aggregation ─────────────────────────────────────────────────────────────


def test_an_empty_client_has_an_empty_timeline(session):
    page = build_timeline(session, tenant_id="t1")

    assert page.events == []
    assert page.next_cursor is None
    assert page.has_more is False


def test_review_decisions_appear_on_the_timeline(session):
    _review(session)

    page = build_timeline(session, tenant_id="t1")

    assert len(page.events) == 1
    event = page.events[0]
    assert event.source_system == SourceSystem.REVIEW_DECISIONS
    assert event.event_type == TimelineEventType.REVIEW_DECISION
    assert event.workflow_id == "OAUTH_REVIEW"
    assert event.actor == "tech@msp.example"
    assert event.outcome == ReviewDecision.KEEP


def test_remediation_executions_appear_on_the_timeline(session):
    _remediation(session)

    page = build_timeline(session, tenant_id="t1")

    assert SourceSystem.REMEDIATION in _sources(page)
    event = next(e for e in page.events if e.source_system == SourceSystem.REMEDIATION)
    assert event.event_type == TimelineEventType.REMEDIATION
    assert event.outcome == "SUCCESS"


def test_audit_events_appear_on_the_timeline(session):
    _audit(session)

    page = build_timeline(session, tenant_id="t1")

    assert SourceSystem.AUDIT_LOG in _sources(page)


def test_generated_reports_appear_on_the_timeline(session):
    _report(session)

    page = build_timeline(session, tenant_id="t1")

    assert SourceSystem.REPORTS in _sources(page)
    event = next(e for e in page.events if e.source_system == SourceSystem.REPORTS)
    assert event.evidence_reference == "c" * 64


def test_posture_snapshots_appear_on_the_timeline(session):
    _snapshot(session, score=72)

    page = build_timeline(session, tenant_id="t1")

    assert SourceSystem.POSTURE_SNAPSHOT in _sources(page)


def test_all_source_systems_merge_into_one_stream(session):
    _review(session, minutes_ago=10)
    _remediation(session, minutes_ago=20)
    _audit(session, minutes_ago=30)
    _report(session, minutes_ago=40)
    _snapshot(session, minutes_ago=50)

    page = build_timeline(session, tenant_id="t1", limit=50)

    assert _sources(page) == {
        SourceSystem.REVIEW_DECISIONS,
        SourceSystem.REMEDIATION,
        SourceSystem.AUDIT_LOG,
        SourceSystem.REPORTS,
        SourceSystem.POSTURE_SNAPSHOT,
    }


def test_every_event_exposes_the_required_narrative_fields(session):
    _review(session, minutes_ago=10)
    _remediation(session, minutes_ago=20)
    _audit(session, minutes_ago=30)
    _report(session, minutes_ago=40)

    for event in build_timeline(session, tenant_id="t1", limit=50).events:
        assert event.id
        assert event.timestamp is not None
        assert event.source_system
        assert event.event_type
        assert event.action
        assert event.title
        assert event.tenant_id == "t1"


# ── Ordering ────────────────────────────────────────────────────────────────


def test_events_are_ordered_newest_first(session):
    _review(session, minutes_ago=30)
    _audit(session, minutes_ago=10)
    _remediation(session, minutes_ago=20)

    page = build_timeline(session, tenant_id="t1", limit=50)
    timestamps = [event.timestamp for event in page.events]

    assert timestamps == sorted(timestamps, reverse=True)


def test_ordering_is_stable_when_timestamps_collide(session):
    """Two events at the same instant must always come back in the same order,
    otherwise pagination would skip or repeat rows."""
    _review(session, minutes_ago=10)
    _audit(session, minutes_ago=10)
    _remediation(session, minutes_ago=10)

    first = [e.id for e in build_timeline(session, tenant_id="t1", limit=50).events]
    second = [e.id for e in build_timeline(session, tenant_id="t1", limit=50).events]

    assert first == second


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_the_timeline_never_contains_another_tenants_events(session):
    _review(session, tenant_id="t2")
    _remediation(session, tenant_id="t2")
    _audit(session, tenant_id="t2")
    _report(session, tenant_id="t2")
    _snapshot(session, tenant_id="t2")

    page = build_timeline(session, tenant_id="t1", limit=50)

    assert page.events == []


def test_each_tenant_sees_only_its_own_events(session):
    _review(session, tenant_id="t1", resource_id="mine")
    _review(session, tenant_id="t2", resource_id="theirs")

    page = build_timeline(session, tenant_id="t1", limit=50)

    assert len(page.events) == 1
    assert all(event.tenant_id == "t1" for event in page.events)


# ── Pagination ──────────────────────────────────────────────────────────────


def test_a_page_is_limited_to_the_requested_size(session):
    for i in range(10):
        _audit(session, minutes_ago=i)

    page = build_timeline(session, tenant_id="t1", limit=4)

    assert len(page.events) == 4
    assert page.has_more is True
    assert page.next_cursor is not None


def test_the_last_page_reports_no_more_results(session):
    for i in range(3):
        _audit(session, minutes_ago=i)

    page = build_timeline(session, tenant_id="t1", limit=10)

    assert len(page.events) == 3
    assert page.has_more is False
    assert page.next_cursor is None


def test_paging_through_the_timeline_yields_every_event_exactly_once(session):
    for i in range(12):
        _audit(session, minutes_ago=i)
    for i in range(8):
        _review(session, minutes_ago=i, resource_id=f"grant-{i}")

    seen: list[str] = []
    cursor = None
    for _ in range(20):  # generous upper bound; loop breaks when exhausted
        page = build_timeline(session, tenant_id="t1", limit=5, cursor=cursor)
        seen.extend(event.id for event in page.events)
        if not page.has_more:
            break
        cursor = page.next_cursor

    assert len(seen) == 20
    assert len(set(seen)) == 20, "an event was returned on two pages"


def test_paging_preserves_newest_first_ordering_across_pages(session):
    for i in range(9):
        _audit(session, minutes_ago=i)

    timestamps = []
    cursor = None
    while True:
        page = build_timeline(session, tenant_id="t1", limit=2, cursor=cursor)
        timestamps.extend(event.timestamp for event in page.events)
        if not page.has_more:
            break
        cursor = page.next_cursor

    assert timestamps == sorted(timestamps, reverse=True)


def test_an_unreadable_cursor_is_rejected_rather_than_silently_ignored(session):
    with pytest.raises(ValueError):
        build_timeline(session, tenant_id="t1", cursor="not-a-real-cursor")


def test_a_cursor_round_trips(session):
    _audit(session, minutes_ago=1)
    _audit(session, minutes_ago=2)

    page = build_timeline(session, tenant_id="t1", limit=1)
    decoded = decode_cursor(page.next_cursor)

    assert decoded is not None
    assert "timestamp" in decoded and "source" in decoded and "id" in decoded


# ── Filtering ───────────────────────────────────────────────────────────────


def test_events_can_be_filtered_by_workflow(session):
    _review(session, minutes_ago=10)
    _audit(session, minutes_ago=20)

    page = build_timeline(session, tenant_id="t1", workflow_id="OAUTH_REVIEW", limit=50)

    assert page.events
    assert all(event.workflow_id == "OAUTH_REVIEW" for event in page.events)


def test_events_can_be_filtered_by_event_type(session):
    _review(session, minutes_ago=10)
    _audit(session, minutes_ago=20)

    page = build_timeline(session, tenant_id="t1", event_types=[TimelineEventType.REVIEW_DECISION], limit=50)

    assert page.events
    assert all(event.event_type == TimelineEventType.REVIEW_DECISION for event in page.events)


def test_events_can_be_filtered_by_date_range(session):
    _audit(session, minutes_ago=5)
    _audit(session, minutes_ago=500)

    page = build_timeline(
        session,
        tenant_id="t1",
        since=BASE - timedelta(minutes=60),
        limit=50,
    )

    assert len(page.events) == 1


def test_filters_combine(session):
    _review(session, minutes_ago=5)
    _review(session, minutes_ago=500, resource_id="old")
    _audit(session, minutes_ago=5)

    page = build_timeline(
        session,
        tenant_id="t1",
        workflow_id="OAUTH_REVIEW",
        since=BASE - timedelta(minutes=60),
        limit=50,
    )

    assert len(page.events) == 1


# ── Read-only guarantee ─────────────────────────────────────────────────────


def test_building_the_timeline_does_not_write_to_any_source_system(session):
    _review(session, minutes_ago=10)
    _remediation(session, minutes_ago=20)
    _audit(session, minutes_ago=30)

    counts_before = (
        session.query(WorkflowReviewDecision).count(),
        session.query(RemediationAuditLog).count(),
        session.query(AuditLog).count(),
    )

    build_timeline(session, tenant_id="t1", limit=50)

    counts_after = (
        session.query(WorkflowReviewDecision).count(),
        session.query(RemediationAuditLog).count(),
        session.query(AuditLog).count(),
    )
    assert counts_before == counts_after
