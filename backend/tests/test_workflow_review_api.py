"""The generic workflow review API.

The security assertions matter most here: the tenant is never taken from the
request, and a resource belonging to another tenant cannot be reviewed,
remediated or reported on.
"""

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.services.workflows.identity_hygiene  # noqa: F401 — registers projector
from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_user,
    require_write_access,
)
from app.api.v1.workflow_review import router
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.report_payload import ReportPayload
from app.db.models.tenant import Tenant
from app.db.models.workflow_review_decision import WorkflowReviewDecision
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.db.session import get_sync_db

CONTROL = "IDENTITY_USER_NO_MFA"
KEY = "identity-hygiene"


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
    # TestClient serves requests on its own thread, so the connection must be
    # shareable and pooled as one — the same harness tests/test_oauth_review_api
    # uses. Without it every request fails on SQLite's thread check.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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


@pytest.fixture()
def client(session):
    api = FastAPI()
    api.include_router(router, prefix="/api/v1")

    tenant = session.get(Tenant, "t1")
    user = type("U", (), {"email": "tech@msp.com", "id": uuid.uuid4()})()

    api.dependency_overrides[get_sync_db] = lambda: session
    api.dependency_overrides[get_current_tenant] = lambda: tenant
    api.dependency_overrides[get_current_user] = lambda: user
    api.dependency_overrides[require_write_access] = lambda: None
    return TestClient(api)


def _finding(session, *, resource_id="user-1", tenant_id="t1"):
    session.add(
        ComplianceResult(
            tenant_id=tenant_id,
            control_id=CONTROL,
            resource_type="USER",
            resource_id=resource_id,
            passed=False,
            severity="HIGH",
            exposure_status=ExposureStatus.ACTIVE.value,
            evidence={"user_principal_name": f"{resource_id}@contoso.com"},
        )
    )
    session.commit()


# ── Opening ─────────────────────────────────────────────────────────────────


def test_opening_a_review_returns_the_eight_panels_the_ui_renders(session, client):
    _finding(session)
    body = client.get(f"/api/v1/workflows/{KEY}/review").json()
    for panel in (
        "workflow",
        "run",
        "stages",
        "progress",
        "resources",
        "review_actions",
        "next_resource_id",
    ):
        assert panel in body


def test_the_workflow_definition_is_included_so_the_ui_needs_one_call(session, client):
    _finding(session)
    body = client.get(f"/api/v1/workflows/{KEY}/review").json()
    assert body["workflow"]["id"] == "IDENTITY_HYGIENE"
    assert body["workflow"]["name"]


def test_review_actions_carry_labels_for_this_workflow(session, client):
    _finding(session)
    body = client.get(f"/api/v1/workflows/{KEY}/review").json()
    labels = {a["decision"]: a["label"] for a in body["review_actions"]}
    assert labels["REVOKE"] == "Disable"


def test_an_unknown_workflow_key_is_404(client):
    assert client.get("/api/v1/workflows/not-a-workflow/review").status_code == 404


def test_the_workflows_internal_id_also_resolves_the_review(session, client):
    """The work-queue list links by the registry id (e.g. "IDENTITY_HYGIENE"),
    not the URL slug this API is otherwise keyed by. Both must resolve the
    same workflow, or every Review click from /work lands on a 404."""
    _finding(session)
    by_slug = client.get(f"/api/v1/workflows/{KEY}/review").json()
    by_id = client.get("/api/v1/workflows/IDENTITY_HYGIENE/review").json()
    assert by_slug["workflow"]["id"] == by_id["workflow"]["id"] == "IDENTITY_HYGIENE"


def test_resources_expose_delta_evidence_and_risk(session, client):
    _finding(session)
    [resource] = client.get(f"/api/v1/workflows/{KEY}/review").json()["resources"]
    for field_name in (
        "control_id",
        "resource_id",
        "title",
        "risk_level",
        "risk_explanation",
        "delta_state",
        "evidence",
        "evidence_hash",
        "facts",
    ):
        assert field_name in resource


# ── Decisions ───────────────────────────────────────────────────────────────


def test_submitting_a_decision_returns_the_refreshed_review(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/decisions",
        json={"control_id": CONTROL, "resource_id": "user-1", "decision": "KEEP"},
    )
    assert response.status_code == 200
    assert response.json()["progress"]["percent_complete"] == 100


def test_a_decision_this_workflow_does_not_offer_is_400(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/decisions",
        json={"control_id": CONTROL, "resource_id": "user-1", "decision": "FIX"},
    )
    assert response.status_code == 400


def test_a_nonsense_decision_is_400(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/decisions",
        json={"control_id": CONTROL, "resource_id": "user-1", "decision": "DELETE_ALL"},
    )
    assert response.status_code == 400


def test_the_reviewer_comes_from_the_session_not_the_request(session, client):
    """reviewed_by must be unspoofable."""
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    client.post(
        f"/api/v1/workflows/{KEY}/review/decisions",
        json={
            "control_id": CONTROL,
            "resource_id": "user-1",
            "decision": "KEEP",
            "reviewed_by": "attacker@evil.com",
        },
    )
    assert session.query(WorkflowReviewDecision).one().reviewed_by == "tech@msp.com"


def test_another_tenants_resource_cannot_be_decided(session, client):
    _finding(session, resource_id="theirs", tenant_id="t2")
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/decisions",
        json={"control_id": CONTROL, "resource_id": "theirs", "decision": "KEEP"},
    )
    assert response.status_code == 400
    assert session.query(WorkflowReviewDecision).count() == 0


# ── Completion and reporting ────────────────────────────────────────────────


def test_completing_with_outstanding_work_is_409(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(f"/api/v1/workflows/{KEY}/review/complete")
    assert response.status_code == 409


def test_completing_archives_a_report(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    client.post(
        f"/api/v1/workflows/{KEY}/review/decisions",
        json={"control_id": CONTROL, "resource_id": "user-1", "decision": "KEEP"},
    )
    assert client.post(f"/api/v1/workflows/{KEY}/review/complete").status_code == 200

    report = client.get(f"/api/v1/workflows/{KEY}/review/report").json()
    assert report["report_type"] == "IDENTITY_HYGIENE_SUMMARY"
    assert report["kept"] == 1


def test_asking_for_a_report_before_one_exists_is_404(session, client):
    assert client.get(f"/api/v1/workflows/{KEY}/review/report").status_code == 404


# ── Remediation ─────────────────────────────────────────────────────────────


def test_simulating_remediation_changes_nothing(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/remediate/simulate",
        json={"resource_ids": ["user-1"], "control_id": CONTROL},
    )
    assert response.status_code == 200
    assert response.json()["requires_confirmation"] is True
    assert session.query(WorkflowReviewDecision).count() == 0


def test_executing_without_confirmation_is_refused(session, client):
    _finding(session)
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/remediate",
        json={"resource_ids": ["user-1"], "control_id": CONTROL, "confirmed": False},
    )
    assert response.status_code == 400


def test_remediating_another_tenants_resource_is_refused(session, client):
    _finding(session, resource_id="theirs", tenant_id="t2")
    client.get(f"/api/v1/workflows/{KEY}/review")
    response = client.post(
        f"/api/v1/workflows/{KEY}/review/remediate/simulate",
        json={"resource_ids": ["theirs"], "control_id": CONTROL},
    )
    assert response.status_code == 400
