"""Sprint 2 — review API.

POST /api/v1/work/review        submit Keep / Ignore / Fix / Escalate
GET  /api/v1/work/{workflow}/delta   what changed since the last review
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
from app.api.v1.work import router as work_router
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.db.models.workflow_run import WorkflowRun, WorkflowStage
from app.db.models.workflow_review_decision import (
    ReviewDecision,
    WorkflowReviewDecision,
)
from app.db.session import get_sync_db


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


@pytest.fixture()
def client(session):
    app = FastAPI()
    app.include_router(work_router, prefix="/api/v1")
    tenant = session.get(Tenant, "t1")
    app.dependency_overrides[get_sync_db] = lambda: session
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=uuid.uuid4(), email="tech@msp.example")
    app.dependency_overrides[require_write_access] = lambda: None
    return TestClient(app)


def _grant(session, resource_id="grant-1", tenant_id="t1", scopes=None):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        passed=False,
        severity="HIGH",
        evidence={"client_id": "app-1", "scopes": scopes or ["Mail.Read"]},
        exposure_status=ExposureStatus.ACTIVE.value,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


# ── Submitting a review ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "decision",
    [ReviewDecision.KEEP, ReviewDecision.IGNORE, ReviewDecision.FIX, ReviewDecision.ESCALATE],
)
def test_every_decision_can_be_submitted(client, session, decision):
    finding = _grant(session)

    response = client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": decision},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == decision


def test_a_submitted_review_is_persisted(client, session):
    finding = _grant(session)

    client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": ReviewDecision.KEEP},
    )

    stored = session.query(WorkflowReviewDecision).one()
    assert stored.control_id == "IDENTITY_ILLICIT_CONSENT_GRANTS"
    assert stored.resource_id == "grant-1"
    assert stored.workflow_type == "OAUTH_REVIEW"


def test_an_optional_reason_is_stored(client, session):
    finding = _grant(session)

    client.post(
        "/api/v1/work/review",
        json={
            "compliance_result_id": finding.id,
            "decision": ReviewDecision.IGNORE,
            "reason": "Sanctioned by the client",
        },
    )

    assert session.query(WorkflowReviewDecision).one().reason == "Sanctioned by the client"


def test_the_workflow_is_derived_from_the_control_when_not_supplied(client, session):
    finding = _grant(session)

    body = client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": ReviewDecision.KEEP},
    ).json()

    assert body["workflow_type"] == "OAUTH_REVIEW"


def test_the_reviewer_is_taken_from_the_session_not_the_request(client, session):
    """A client must not be able to attribute a decision to someone else."""
    finding = _grant(session)

    client.post(
        "/api/v1/work/review",
        json={
            "compliance_result_id": finding.id,
            "decision": ReviewDecision.KEEP,
            "reviewed_by": "someone.else@evil.example",
        },
    )

    assert session.query(WorkflowReviewDecision).one().reviewed_by == "tech@msp.example"


def test_reviewing_twice_supersedes_rather_than_duplicating(client, session):
    finding = _grant(session)
    payload = {"compliance_result_id": finding.id, "decision": ReviewDecision.KEEP}

    client.post("/api/v1/work/review", json=payload)
    client.post("/api/v1/work/review", json={**payload, "decision": ReviewDecision.IGNORE})

    active = session.query(WorkflowReviewDecision).filter(WorkflowReviewDecision.superseded_at.is_(None)).all()
    assert session.query(WorkflowReviewDecision).count() == 2
    assert len(active) == 1
    assert active[0].decision == ReviewDecision.IGNORE


# ── Validation ──────────────────────────────────────────────────────────────


def test_an_unsupported_decision_is_rejected(client, session):
    finding = _grant(session)

    response = client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": "NUKE"},
    )

    assert response.status_code in (400, 422)
    assert session.query(WorkflowReviewDecision).count() == 0


def test_reviewing_an_unknown_finding_returns_404(client):
    response = client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": 999999, "decision": ReviewDecision.KEEP},
    )

    assert response.status_code == 404


# ── Tenant isolation (CRITICAL) ─────────────────────────────────────────────


def test_reviewing_another_tenants_finding_is_not_possible(client, session):
    other = _grant(session, resource_id="theirs", tenant_id="t2")

    response = client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": other.id, "decision": ReviewDecision.KEEP},
    )

    assert response.status_code == 404, "must not reveal that the finding exists"
    assert session.query(WorkflowReviewDecision).count() == 0


def test_the_delta_endpoint_is_tenant_scoped(client, session):
    _grant(session, resource_id="theirs", tenant_id="t2")

    body = client.get("/api/v1/work/OAUTH_REVIEW/delta").json()

    assert body["counts"]["NEW"] == 0


# ── Authorisation ───────────────────────────────────────────────────────────


def test_submitting_a_review_requires_write_access(session):
    """Suppressing a finding is a state change — preview/read-only must not."""
    from fastapi import HTTPException

    app = FastAPI()
    app.include_router(work_router, prefix="/api/v1")
    tenant = session.get(Tenant, "t1")

    def _deny():
        raise HTTPException(status_code=403, detail="read only")

    app.dependency_overrides[get_sync_db] = lambda: session
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=uuid.uuid4(), email="viewer@msp.example")
    app.dependency_overrides[require_write_access] = _deny
    read_only = TestClient(app)

    finding = _grant(session)
    response = read_only.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": ReviewDecision.IGNORE},
    )

    assert response.status_code == 403
    assert session.query(WorkflowReviewDecision).count() == 0


# ── Delta endpoint ──────────────────────────────────────────────────────────


def test_delta_reports_new_items(client, session):
    _grant(session, resource_id="a")
    _grant(session, resource_id="b")

    body = client.get("/api/v1/work/OAUTH_REVIEW/delta").json()

    assert body["workflow_id"] == "OAUTH_REVIEW"
    assert body["counts"]["NEW"] == 2
    assert body["counts"]["PREVIOUSLY_REVIEWED"] == 0


def test_delta_reports_previously_reviewed_items(client, session):
    finding = _grant(session, resource_id="a")
    _grant(session, resource_id="b")
    client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": ReviewDecision.KEEP},
    )

    body = client.get("/api/v1/work/OAUTH_REVIEW/delta").json()

    assert body["counts"]["PREVIOUSLY_REVIEWED"] == 1
    assert body["counts"]["NEW"] == 1


def test_delta_reports_changed_items(client, session):
    finding = _grant(session, resource_id="a", scopes=["Mail.Read"])
    client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": ReviewDecision.KEEP},
    )

    finding.evidence = {**finding.evidence, "scopes": ["Mail.Read", "Mail.ReadWrite"]}
    session.commit()

    body = client.get("/api/v1/work/OAUTH_REVIEW/delta").json()

    assert body["counts"]["CHANGED"] == 1
    assert body["counts"]["PREVIOUSLY_REVIEWED"] == 0


def test_delta_reports_resolved_items(client, session):
    """A finding leaves the queue by being marked RESOLVED — the scanner never
    deletes rows — so that is the path this exercises."""
    finding = _grant(session, resource_id="a")
    client.post(
        "/api/v1/work/review",
        json={"compliance_result_id": finding.id, "decision": ReviewDecision.KEEP},
    )

    finding.exposure_status = ExposureStatus.RESOLVED.value
    session.commit()

    body = client.get("/api/v1/work/OAUTH_REVIEW/delta").json()

    assert body["counts"]["RESOLVED"] == 1
    assert body["counts"]["PREVIOUSLY_REVIEWED"] == 0


def test_delta_lists_items_with_their_state(client, session):
    _grant(session, resource_id="a")

    body = client.get("/api/v1/work/OAUTH_REVIEW/delta").json()

    assert body["items"][0]["delta_state"] == "NEW"
    assert body["items"][0]["resource_id"] == "a"


def test_delta_for_an_unknown_workflow_is_rejected(client):
    assert client.get("/api/v1/work/NOT_A_WORKFLOW/delta").status_code == 404


def test_delta_for_a_workflow_with_no_findings_is_empty(client):
    body = client.get("/api/v1/work/GUEST_REVIEW/delta").json()

    assert body["items"] == []
    assert body["counts"]["NEW"] == 0
