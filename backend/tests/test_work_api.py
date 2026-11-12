"""Sprint 1 — GET /api/v1/work.

Uses a real in-memory database rather than mocks so the test exercises the
actual query and grouping path.
"""

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies.current_user import get_current_tenant
from app.api.v1.work import router as work_router
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.db.session import get_sync_db


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # pragma: no cover - test plumbing
    return "JSON"


@pytest.fixture()
def session():
    # StaticPool + check_same_thread=False: TestClient serves requests on a
    # different thread, and the default SQLite pool would hand that thread a
    # fresh (empty) in-memory database.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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
    db.commit()
    yield db
    db.close()


@pytest.fixture()
def client(session):
    app = FastAPI()
    app.include_router(work_router, prefix="/api/v1")

    tenant = session.get(Tenant, "t1")
    app.dependency_overrides[get_sync_db] = lambda: session
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    return TestClient(app)


def _seed(session, control_id, *, severity="HIGH", resource_id="r1", tenant_id="t1"):
    session.add(
        ComplianceResult(
            tenant_id=tenant_id,
            control_id=control_id,
            resource_type="TENANT",
            resource_id=resource_id,
            passed=False,
            severity=severity,
            evidence={},
            exposure_status=ExposureStatus.ACTIVE.value,
        )
    )
    session.commit()


def test_work_endpoint_returns_empty_queue_for_a_clean_tenant(client):
    response = client.get("/api/v1/work")

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "t1"
    assert body["groups"] == []
    assert body["summary"]["today_count"] == 0
    assert body["summary"]["estimated_minutes"] == 0


def test_work_endpoint_returns_grouped_work(client, session):
    _seed(session, "IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="a")
    _seed(session, "IDENTITY_USER_CONSENT_POLICY", resource_id="b")

    body = client.get("/api/v1/work").json()

    assert len(body["groups"]) == 1
    group = body["groups"][0]
    assert group["workflow_id"] == "OAUTH_REVIEW"
    assert group["workflow_name"] == "OAuth Review"
    assert group["item_count"] == 2
    assert group["priority"] == "HIGH"
    assert group["estimated_minutes"] > 0
    assert group["recommended_action"]
    assert group["tenant_name"] == "Contoso"


def test_work_endpoint_exposes_all_required_work_item_fields(client, session):
    _seed(session, "IDENTITY_ILLICIT_CONSENT_GRANTS")

    item = client.get("/api/v1/work").json()["groups"][0]["items"][0]

    for field in (
        "id",
        "tenant_id",
        "tenant_name",
        "title",
        "category",
        "severity",
        "priority",
        "estimated_minutes",
        "recommended_action",
        "related_control",
        "created_at",
        "compliance_result_id",
    ):
        assert field in item, f"missing work item field: {field}"


def test_work_endpoint_summary_reports_priority_split(client, session):
    _seed(session, "IDENTITY_ILLICIT_CONSENT_GRANTS", severity="CRITICAL")
    _seed(session, "IDENTITY_GUEST_INVITES_OPEN", severity="LOW")

    summary = client.get("/api/v1/work").json()["summary"]

    assert summary["today_count"] == 2
    assert summary["high_priority"] == 1
    assert summary["normal_priority"] == 1
    assert summary["item_count"] == 2
    assert "completed" in summary


def test_work_endpoint_only_returns_the_authenticated_tenants_work(client, session):
    session.add(Tenant(id="t2", tenant_name="Fabrikam", organization_id=uuid.uuid4()))
    session.commit()
    _seed(session, "IDENTITY_ILLICIT_CONSENT_GRANTS", tenant_id="t2", resource_id="theirs")

    body = client.get("/api/v1/work").json()

    assert body["groups"] == []


def test_work_endpoint_requires_authentication():
    """Without the auth dependency override the endpoint must not serve data."""
    app = FastAPI()
    app.include_router(work_router, prefix="/api/v1")
    unauthenticated = TestClient(app, raise_server_exceptions=False)

    assert unauthenticated.get("/api/v1/work").status_code in (401, 403, 422, 500)
