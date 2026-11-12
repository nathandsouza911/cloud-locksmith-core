"""Integration tests for the Compliance Dashboard API endpoint.

Tests follow the FastAPI TestClient + dependency_overrides pattern used
throughout this codebase (e.g., test_license_optimizer_api.py).

The router is mounted locally so tests do NOT depend on it being registered
in main.py (that is Phase 3).
"""

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies.current_user import get_current_tenant
from app.api.v1.compliance_dashboard import router as compliance_dashboard_router
from app.db.session import get_sync_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(control_id: str, passed: bool):
    """Return a duck-typed compliance result row."""
    obj = MagicMock()
    obj.control_id = control_id
    obj.passed = passed
    obj.resource_id = "res-1"
    return obj


def _mock_tenant():
    t = MagicMock()
    t.id = "test-tenant-uuid"
    return t


def _mock_db_with_results(results):
    """Return a mock DB session whose query chain yields *results*."""
    mock_db = MagicMock()
    (mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value) = results
    return mock_db


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client():
    """TestClient with auth + DB overridden; DB returns an empty result set."""
    app = FastAPI()
    app.include_router(compliance_dashboard_router, prefix="/api/v1")

    app.dependency_overrides[get_current_tenant] = _mock_tenant
    app.dependency_overrides[get_sync_db] = lambda: _mock_db_with_results([])

    with TestClient(app) as client:
        yield client


@pytest.fixture()
def api_client_with_results():
    """TestClient with auth + DB overridden; DB returns real result objects.

    Injects two results for IDENTITY_USER_NO_MFA (maps to cis-m365) so that
    filter tests assert over non-empty data:
      - one FAIL result (passed=False, direct mapping → status FAIL)
      - one PASS result for a second control (passed=True → status PASS)
    """
    app = FastAPI()
    app.include_router(compliance_dashboard_router, prefix="/api/v1")

    results = [
        # IDENTITY_ADMIN_NO_MFA maps to cis-m365 with mapping_strength="direct",
        # so passed=False → status FAIL (not PARTIAL).
        _make_result("IDENTITY_ADMIN_NO_MFA", passed=False),
        # IDENTITY_USER_NO_MFA maps to cis-m365 with mapping_strength="evidence",
        # so passed=True → status PASS.
        _make_result("IDENTITY_USER_NO_MFA", passed=True),
    ]

    app.dependency_overrides[get_current_tenant] = _mock_tenant
    app.dependency_overrides[get_sync_db] = lambda: _mock_db_with_results(results)

    with TestClient(app) as client:
        yield client


# ---------------------------------------------------------------------------
# Test 1 — unauthenticated request must return 401
# ---------------------------------------------------------------------------


def test_unauthenticated_returns_401():
    """Request without an auth header must be rejected with 401."""
    # Fresh app with NO dependency overrides so get_current_tenant runs normally
    app = FastAPI()
    app.include_router(compliance_dashboard_router, prefix="/api/v1")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/compliance/dashboard")

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Test 2 — valid authenticated request → 200 with correct schema
# ---------------------------------------------------------------------------


def test_returns_200_with_valid_schema(api_client):
    """Authenticated request returns 200 and body contains frameworks + controls keys."""
    response = api_client.get("/api/v1/compliance/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert "frameworks" in body
    assert "controls" in body
    assert isinstance(body["frameworks"], list)
    assert isinstance(body["controls"], list)


# ---------------------------------------------------------------------------
# Test 3 — framework_id filter param narrows controls list
# ---------------------------------------------------------------------------


def test_framework_filter_param(api_client_with_results):
    """?framework_id=cis-m365 → 200; controls list is non-empty and every row has framework_id == 'cis-m365'."""
    response = api_client_with_results.get("/api/v1/compliance/dashboard?framework_id=cis-m365")

    assert response.status_code == 200
    body = response.json()
    assert len(body["controls"]) > 0, "Expected non-empty controls for cis-m365 filter"
    for control in body["controls"]:
        assert control["framework_id"] == "cis-m365"


# ---------------------------------------------------------------------------
# Test 4 — status filter param narrows controls list
# ---------------------------------------------------------------------------


def test_status_filter_param(api_client_with_results):
    """?status=FAIL → 200; controls list is non-empty and every row has status == 'FAIL'.

    With IDENTITY_ADMIN_NO_MFA injected as passed=False (direct mapping strength),
    the service computes status=FAIL for that control, so the filter returns results.
    """
    response = api_client_with_results.get("/api/v1/compliance/dashboard?status=FAIL")

    assert response.status_code == 200
    body = response.json()
    assert len(body["controls"]) > 0, "Expected non-empty controls for status=FAIL filter"
    for control in body["controls"]:
        assert control["status"] == "FAIL"


# ---------------------------------------------------------------------------
# Test 5 — invalid status value is graceful (200 with empty controls)
# ---------------------------------------------------------------------------


def test_invalid_status_still_returns_200_empty(api_client):
    """?status=NONSENSE must return 200 with an empty controls list, not 422."""
    response = api_client.get("/api/v1/compliance/dashboard?status=NONSENSE")

    assert response.status_code == 200
    body = response.json()
    assert body["controls"] == []


# ---------------------------------------------------------------------------
# Test 6 — frameworks list is always complete (unfiltered)
# ---------------------------------------------------------------------------


def test_frameworks_always_returned(api_client_with_results):
    """Even when filtering controls by framework_id, the frameworks list is full."""
    # First fetch all frameworks without a filter
    full_response = api_client_with_results.get("/api/v1/compliance/dashboard")
    assert full_response.status_code == 200
    all_frameworks = {fw["id"] for fw in full_response.json()["frameworks"]}

    # Now filter by a specific framework — controls list narrows but frameworks must not shrink
    filtered_response = api_client_with_results.get("/api/v1/compliance/dashboard?framework_id=cis-m365")
    assert filtered_response.status_code == 200
    filtered_frameworks = {fw["id"] for fw in filtered_response.json()["frameworks"]}

    # The frameworks list must not shrink when the controls list is filtered
    assert filtered_frameworks == all_frameworks
