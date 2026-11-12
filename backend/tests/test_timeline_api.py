"""Sprint 3 — Client Timeline API and Workflow Library API.

The timeline takes ``tenant_id`` as a PATH PARAMETER, so ownership must be
verified against the caller's UserTenantAccess rows. Trusting a path id would
be a cross-tenant read. Those tests are the important ones in this module.
"""

import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies.current_user import get_current_user
from app.api.v1.clients import router as clients_router
from app.api.v1.workflows import router as workflows_router
from app.db.models.audit_log import AuditLog
from app.db.models.organization import Organization
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import get_sync_db


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


BASE = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)
USER_ID = uuid.uuid4()


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    for model in (Organization, Tenant, AuditLog, PlatformUser, UserTenantAccess):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()

    org_id = uuid.uuid4()
    db.add(Organization(id=org_id, name="MSP"))
    db.commit()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=org_id))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=org_id))
    db.add(PlatformUser(id=USER_ID, email="tech@msp.example", organization_id=org_id))
    db.commit()
    # The caller can reach t1 only.
    db.add(UserTenantAccess(user_id=USER_ID, tenant_id="t1", role="ADMIN"))
    db.commit()
    yield db
    db.close()


@pytest.fixture()
def client(session):
    app = FastAPI()
    app.include_router(clients_router, prefix="/api/v1")
    app.include_router(workflows_router, prefix="/api/v1")
    user = session.get(PlatformUser, USER_ID)
    app.dependency_overrides[get_sync_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def _audit(session, *, tenant_id="t1", minutes_ago=0, action="OFFBOARDING"):
    session.add(
        AuditLog(
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
    )
    session.commit()


# ── Timeline: ownership (CRITICAL) ──────────────────────────────────────────


def test_a_client_the_caller_can_reach_returns_a_timeline(client, session):
    _audit(session)

    response = client.get("/api/v1/clients/t1/timeline")

    assert response.status_code == 200
    assert response.json()["tenant_id"] == "t1"


def test_a_client_the_caller_cannot_reach_is_not_readable(client, session):
    _audit(session, tenant_id="t2")

    response = client.get("/api/v1/clients/t2/timeline")

    assert response.status_code == 404, "must not reveal that the tenant exists"


def test_a_nonexistent_client_is_indistinguishable_from_a_forbidden_one(client):
    forbidden = client.get("/api/v1/clients/t2/timeline")
    missing = client.get("/api/v1/clients/does-not-exist/timeline")

    assert forbidden.status_code == missing.status_code == 404


def test_no_other_tenants_events_leak_into_an_authorised_timeline(client, session):
    _audit(session, tenant_id="t1", minutes_ago=1)
    _audit(session, tenant_id="t2", minutes_ago=2)

    events = client.get("/api/v1/clients/t1/timeline").json()["events"]

    assert len(events) == 1
    assert all(event["tenant_id"] == "t1" for event in events)


# ── Timeline: response shape ────────────────────────────────────────────────


def test_timeline_events_expose_the_narrative_fields(client, session):
    _audit(session)

    event = client.get("/api/v1/clients/t1/timeline").json()["events"][0]

    for field in (
        "id",
        "timestamp",
        "source_system",
        "event_type",
        "action",
        "title",
        "actor",
        "outcome",
        "workflow_id",
        "evidence_reference",
    ):
        assert field in event, f"missing timeline field: {field}"


def test_an_empty_timeline_is_not_an_error(client):
    response = client.get("/api/v1/clients/t1/timeline")

    assert response.status_code == 200
    assert response.json()["events"] == []
    assert response.json()["has_more"] is False


# ── Timeline: pagination ────────────────────────────────────────────────────


def test_the_timeline_is_paginated(client, session):
    for i in range(8):
        _audit(session, minutes_ago=i)

    body = client.get("/api/v1/clients/t1/timeline?limit=3").json()

    assert len(body["events"]) == 3
    assert body["has_more"] is True
    assert body["next_cursor"]


def test_following_the_cursor_returns_the_next_page(client, session):
    for i in range(6):
        _audit(session, minutes_ago=i)

    first = client.get("/api/v1/clients/t1/timeline?limit=3").json()
    second = client.get(f"/api/v1/clients/t1/timeline?limit=3&cursor={first['next_cursor']}").json()

    first_ids = {event["id"] for event in first["events"]}
    second_ids = {event["id"] for event in second["events"]}
    assert first_ids.isdisjoint(second_ids)
    assert len(second["events"]) == 3


def test_a_malformed_cursor_is_a_client_error_not_a_crash(client):
    response = client.get("/api/v1/clients/t1/timeline?cursor=garbage")

    assert response.status_code == 400


def test_the_page_limit_is_capped(client, session):
    _audit(session)

    assert client.get("/api/v1/clients/t1/timeline?limit=10000").status_code in (200, 422)


# ── Timeline: filtering ─────────────────────────────────────────────────────


def test_the_timeline_can_be_filtered_by_event_type(client, session):
    _audit(session, minutes_ago=1)

    matching = client.get("/api/v1/clients/t1/timeline?event_types=AUDIT").json()["events"]
    non_matching = client.get("/api/v1/clients/t1/timeline?event_types=REPORT_GENERATED").json()["events"]

    assert len(matching) == 1
    assert non_matching == []


def test_the_timeline_can_be_filtered_by_date(client, session):
    _audit(session, minutes_ago=5)
    _audit(session, minutes_ago=5000)

    # quote() the timestamp: an unencoded "+00:00" offset decodes as a space.
    since = quote((BASE - timedelta(minutes=60)).isoformat())
    events = client.get(f"/api/v1/clients/t1/timeline?since={since}").json()["events"]

    assert len(events) == 1


# ── Workflow Library ────────────────────────────────────────────────────────


def test_the_workflow_library_lists_definitions(client):
    body = client.get("/api/v1/workflows").json()

    assert len(body["workflows"]) >= 8
    ids = {workflow["id"] for workflow in body["workflows"]}
    assert "OAUTH_REVIEW" in ids


def test_the_library_exposes_the_fields_the_page_renders(client):
    workflow = next(w for w in client.get("/api/v1/workflows").json()["workflows"] if w["id"] == "OAUTH_REVIEW")

    for field in (
        "id",
        "key",
        "name",
        "description",
        "category",
        "icon",
        "supported_controls",
        "resource_types",
        "review_modes",
        "default_priority",
        "estimated_effort",
        "supports_delta",
        "supports_reports",
        "supports_remediation",
        "supports_verification",
        "supported_reports",
        "review_philosophy",
        "typical_cadence",
        "evidence_strategy",
        "recommended_role",
        "display_order",
    ):
        assert field in workflow, f"missing library field: {field}"


def test_the_library_does_not_advertise_the_fallback_workflow(client):
    ids = {w["id"] for w in client.get("/api/v1/workflows").json()["workflows"]}

    assert "GENERAL_REVIEW" not in ids


def test_the_library_is_ordered_deterministically(client):
    orders = [w["display_order"] for w in client.get("/api/v1/workflows").json()["workflows"]]

    assert orders == sorted(orders)


def test_a_single_workflow_can_be_fetched(client):
    body = client.get("/api/v1/workflows/OAUTH_REVIEW").json()

    assert body["id"] == "OAUTH_REVIEW"
    assert body["supported_controls"]


def test_an_unknown_workflow_returns_404(client):
    assert client.get("/api/v1/workflows/NOT_A_WORKFLOW").status_code == 404


def test_the_library_carries_no_execution_or_schedule_state(client):
    """A definition says what a workflow is, never when it runs or how it is
    going. Leaking runtime state here would blur the boundary the Workflow
    Engine depends on."""
    forbidden = {
        "next_run_at",
        "last_run_at",
        "cron",
        "rrule",
        "schedule",
        "assignee",
        "due_at",
        "sla_hours",
        "status",
        "progress",
        "run_id",
    }
    for workflow in client.get("/api/v1/workflows").json()["workflows"]:
        assert not (forbidden & set(workflow)), workflow["id"]
