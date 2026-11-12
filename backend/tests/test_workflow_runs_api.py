"""Sprint 4 — the runtime API.

    POST  /api/v1/workflows/{definition_key}/runs
    GET   /api/v1/workflows/runs/active
    GET   /api/v1/workflows/runs/{run_id}
    PATCH /api/v1/workflows/runs/{run_id}/state

Generic by design: there is no per-workflow endpoint. Everything is expressed
as "a run of a definition".
"""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_user,
    require_write_access,
)
from app.api.v1.workflow_runs import router as runs_router
from app.api.v1.workflows import router as workflows_router
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.db.session import get_sync_db
from app.services.workflow_runtime.runtime_service import cancel_run, create_run
from app.services.workflow_runtime.state_machine import RunState


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover
    return "JSON"


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    for model in (Tenant, WorkflowRun, WorkflowStage, WorkflowReviewDecision):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    db.add(Tenant(id="t1", tenant_name="Contoso", organization_id=uuid.uuid4()))
    db.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    db.commit()
    yield db
    db.close()


def _app(session, *, write_allowed=True):
    from fastapi import HTTPException

    app = FastAPI()
    # Runs router is mounted FIRST so its concrete /workflows/runs/... paths
    # win over the library's /workflows/{workflow_id}.
    app.include_router(runs_router, prefix="/api/v1")
    app.include_router(workflows_router, prefix="/api/v1")
    tenant = session.get(Tenant, "t1")
    app.dependency_overrides[get_sync_db] = lambda: session
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=uuid.uuid4(), email="tech@msp.example")
    if write_allowed:
        app.dependency_overrides[require_write_access] = lambda: None
    else:

        def _deny():
            raise HTTPException(status_code=403, detail="read only")

        app.dependency_overrides[require_write_access] = _deny
    return app


@pytest.fixture()
def client(session):
    return TestClient(_app(session))


# ── Creating runs ───────────────────────────────────────────────────────────


def test_a_run_can_be_created_for_a_definition(client, session):
    response = client.post("/api/v1/workflows/OAUTH_REVIEW/runs")

    assert response.status_code == 201
    body = response.json()
    assert body["workflow_definition_key"] == "OAUTH_REVIEW"
    assert body["state"] == RunState.CREATED
    assert session.query(WorkflowRun).count() == 1


def test_creating_a_run_twice_returns_the_existing_active_run(client, session):
    first = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()
    second = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    assert first["id"] == second["id"]
    assert session.query(WorkflowRun).count() == 1


def test_creating_a_run_for_an_unknown_definition_is_rejected(client, session):
    response = client.post("/api/v1/workflows/NOT_A_WORKFLOW/runs")

    assert response.status_code == 404
    assert session.query(WorkflowRun).count() == 0


def test_the_creator_is_taken_from_the_session(client, session):
    client.post("/api/v1/workflows/OAUTH_REVIEW/runs")

    assert session.query(WorkflowRun).one().created_by == "tech@msp.example"


def test_creating_a_run_requires_write_access(session):
    read_only = TestClient(_app(session, write_allowed=False))

    response = read_only.post("/api/v1/workflows/OAUTH_REVIEW/runs")

    assert response.status_code == 403
    assert session.query(WorkflowRun).count() == 0


# ── Reading runs ────────────────────────────────────────────────────────────


def test_a_run_can_be_fetched_by_id(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    body = client.get(f"/api/v1/workflows/runs/{created['id']}").json()

    assert body["id"] == created["id"]
    assert body["workflow_definition_key"] == "OAUTH_REVIEW"


def test_a_run_exposes_its_definition_without_duplicating_it(client, session):
    """The response resolves the definition at read time; the row stores only
    the key."""
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    body = client.get(f"/api/v1/workflows/runs/{created['id']}").json()

    assert body["workflow_name"] == "OAuth Review"
    assert session.query(WorkflowRun).one().workflow_definition_key == "OAUTH_REVIEW"


def test_an_unknown_run_returns_404(client):
    assert client.get(f"/api/v1/workflows/runs/{uuid.uuid4()}").status_code == 404


def test_a_malformed_run_id_is_a_client_error(client):
    assert client.get("/api/v1/workflows/runs/not-a-uuid").status_code in (400, 404, 422)


def test_active_runs_can_be_listed(client, session):
    client.post("/api/v1/workflows/OAUTH_REVIEW/runs")
    client.post("/api/v1/workflows/GUEST_REVIEW/runs")

    body = client.get("/api/v1/workflows/runs/active").json()

    assert {run["workflow_definition_key"] for run in body["runs"]} == {
        "OAUTH_REVIEW",
        "GUEST_REVIEW",
    }


def test_a_terminal_run_is_not_listed_as_active(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()
    run = session.get(WorkflowRun, uuid.UUID(created["id"]))
    cancel_run(session, run=run)

    body = client.get("/api/v1/workflows/runs/active").json()

    assert body["runs"] == []


def test_the_active_runs_route_is_not_shadowed_by_the_definition_route(client):
    """`/workflows/runs/active` must reach the runtime, not be swallowed by
    `/workflows/{workflow_id}` from the library router."""
    response = client.get("/api/v1/workflows/runs/active")

    assert response.status_code == 200
    assert "runs" in response.json()


def test_the_library_route_still_works_alongside_the_runs_routes(client):
    body = client.get("/api/v1/workflows/OAUTH_REVIEW").json()

    assert body["id"] == "OAUTH_REVIEW"
    assert "supported_controls" in body


# ── Advancing state ─────────────────────────────────────────────────────────


def test_a_run_state_can_be_advanced(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    response = client.patch(
        f"/api/v1/workflows/runs/{created['id']}/state",
        json={"state": RunState.DISCOVERING},
    )

    assert response.status_code == 200
    assert response.json()["state"] == RunState.DISCOVERING


def test_an_illegal_transition_is_rejected(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    response = client.patch(
        f"/api/v1/workflows/runs/{created['id']}/state",
        json={"state": RunState.COMPLETED},
    )

    assert response.status_code == 409
    run = session.get(WorkflowRun, uuid.UUID(created["id"]))
    assert run.state == RunState.CREATED


def test_an_unknown_state_is_rejected(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    response = client.patch(
        f"/api/v1/workflows/runs/{created['id']}/state",
        json={"state": "BANANA"},
    )

    assert response.status_code in (400, 409, 422)


def test_a_run_can_be_completed_with_a_summary(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()
    run_id = created["id"]
    for state in (
        RunState.DISCOVERING,
        RunState.READY_FOR_REVIEW,
        RunState.IN_REVIEW,
    ):
        client.patch(f"/api/v1/workflows/runs/{run_id}/state", json={"state": state})

    response = client.patch(
        f"/api/v1/workflows/runs/{run_id}/state",
        json={"state": RunState.COMPLETED, "summary": {"reviewed": 10}},
    )

    assert response.status_code == 200
    assert response.json()["summary"] == {"reviewed": 10}
    assert response.json()["completed_at"] is not None


def test_a_run_can_be_cancelled_with_a_reason(client, session):
    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()

    response = client.patch(
        f"/api/v1/workflows/runs/{created['id']}/state",
        json={"state": RunState.CANCELLED, "reason": "client postponed"},
    )

    assert response.status_code == 200
    assert response.json()["state"] == RunState.CANCELLED


def test_advancing_state_requires_write_access(session):
    run = create_run(
        session,
        tenant_id="t1",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )
    read_only = TestClient(_app(session, write_allowed=False))

    response = read_only.patch(
        f"/api/v1/workflows/runs/{run.id}/state",
        json={"state": RunState.DISCOVERING},
    )

    assert response.status_code == 403
    session.refresh(run)
    assert run.state == RunState.CREATED


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_another_tenants_run_cannot_be_read(client, session):
    other = create_run(
        session,
        tenant_id="t2",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )

    response = client.get(f"/api/v1/workflows/runs/{other.id}")

    assert response.status_code == 404, "must not reveal that the run exists"


def test_another_tenants_run_cannot_be_advanced(client, session):
    other = create_run(
        session,
        tenant_id="t2",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )

    response = client.patch(
        f"/api/v1/workflows/runs/{other.id}/state",
        json={"state": RunState.DISCOVERING},
    )

    assert response.status_code == 404
    session.refresh(other)
    assert other.state == RunState.CREATED


def test_active_run_listing_never_crosses_tenants(client, session):
    create_run(
        session,
        tenant_id="t2",
        workflow_definition_key="OAUTH_REVIEW",
        created_by="tech@msp.example",
    )

    assert client.get("/api/v1/workflows/runs/active").json()["runs"] == []


# ── Stages on the run response ──────────────────────────────────────────────


def test_a_run_response_includes_its_stages(client, session):
    from app.services.workflow_runtime.runtime_service import start_stage

    created = client.post("/api/v1/workflows/OAUTH_REVIEW/runs").json()
    run = session.get(WorkflowRun, uuid.UUID(created["id"]))
    start_stage(session, run=run, stage_key="DISCOVER")

    body = client.get(f"/api/v1/workflows/runs/{created['id']}").json()

    assert len(body["stages"]) == 1
    assert body["stages"][0]["stage_key"] == "DISCOVER"
    assert body["stages"][0]["state"] == "ACTIVE"
    assert body["current_stage"] == "DISCOVER"
