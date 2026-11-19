"""Workflow Library API (GET /api/v1/workflows).

The client timeline tests left with the /clients route (MSP surface removed).
"""

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies.current_user import get_current_user
from app.api.v1.workflows import router as workflows_router
from app.db.models.platform_user import PlatformUser


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(workflows_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: PlatformUser(id=uuid.uuid4(), email="admin@example.com")
    return TestClient(app)


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
