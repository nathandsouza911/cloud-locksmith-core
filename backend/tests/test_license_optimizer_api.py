from datetime import date, timedelta
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies.current_user import get_current_tenant
from app.api.v1.license import router as license_router
from app.db.models.license_optimizer import LicenseFinding, LicenseSnapshot
from app.db.models.organization import Organization
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.db.session import get_sync_db
from app.services import license_analysis_service


@pytest.fixture()
def license_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Organization.__table__.create(engine)
    Tenant.__table__.create(engine)
    LicenseSnapshot.__table__.create(engine)
    LicenseFinding.__table__.create(engine)
    TenantOAuth.__table__.create(engine)

    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    tenant = Tenant(
        id="tenant-license-api",
        tenant_name="License API Tenant",
        oauth_token={"access_token": "test-token"},
    )
    session.add(tenant)
    session.commit()

    app = FastAPI()
    app.include_router(license_router, prefix="/api/v1")

    def override_get_db():
        yield session

    def override_get_current_tenant():
        return Tenant(id=tenant.id, tenant_name=tenant.tenant_name, oauth_token={"access_token": "test-token"})

    app.dependency_overrides[get_sync_db] = override_get_db
    app.dependency_overrides[get_current_tenant] = override_get_current_tenant

    with TestClient(app) as client:
        yield client

    session.close()
    engine.dispose()


def test_license_scan_and_read_endpoints(monkeypatch, license_client):
    async def fake_fetch_inputs(db, tenant):
        return {
            "users": [
                {
                    "id": "user-inactive",
                    "displayName": "Inactive User",
                    "mail": "inactive@contoso.com",
                    "userPrincipalName": "inactive@contoso.com",
                    "createdDateTime": "2025-01-01T00:00:00Z",
                    "assignedLicenses": [{"skuId": "sku-e3"}],
                },
                {
                    "id": "user-overlicensed",
                    "displayName": "Mailbox Only",
                    "mail": "mailbox@contoso.com",
                    "userPrincipalName": "mailbox@contoso.com",
                    "createdDateTime": "2025-01-01T00:00:00Z",
                    "assignedLicenses": [{"skuId": "sku-e5"}],
                },
            ],
            "subscribed_skus": [
                {
                    "skuId": "sku-e3",
                    "skuPartNumber": "SPE_E3",
                    "prepaidUnits": {"enabled": 10},
                    "consumedUnits": 7,
                },
                {
                    "skuId": "sku-e5",
                    "skuPartNumber": "SPE_E5",
                    "prepaidUnits": {"enabled": 5},
                    "consumedUnits": 5,
                },
            ],
            "office365_active_user_detail": [
                {
                    "user_principal_name": "inactive@contoso.com",
                    "last_activity_date": "2025-02-01",
                },
                {
                    "user_principal_name": "mailbox@contoso.com",
                    # Recent activity, relative to today so the test does not age.
                    "exchange_last_activity_date": (date.today() - timedelta(days=5)).isoformat(),
                    "sharepoint_last_activity_date": "",
                    "onedrive_last_activity_date": "",
                    "teams_last_activity_date": "",
                },
            ],
            "m365_app_user_counts": [],
        }

    monkeypatch.setattr(license_analysis_service, "fetch_license_optimizer_inputs", fake_fetch_inputs)
    # Delegated tokens live in tenant_oauth now; this test covers the cost logic, not the connection check.
    import app.api.v1.license as license_api

    monkeypatch.setattr(license_api, "has_delegated_oauth_token_sync", lambda tenant, db=None: True)

    scan_response = license_client.get("/api/v1/license/scan")
    assert scan_response.status_code == 200
    assert scan_response.json()["summary"] == {
        "currency": "USD",
        "total_waste": 216,
        "inactive_users_cost": 39,
        "overlicensed_cost": 60,
        "unused_license_cost": 117,
    }
    assert scan_response.json()["findings_count"] == 3

    summary_response = license_client.get("/api/v1/license/summary")
    assert summary_response.status_code == 200
    assert summary_response.json()["total_waste"] == 216
    assert summary_response.json()["currency"] == "USD"

    findings_response = license_client.get("/api/v1/license/findings")
    assert findings_response.status_code == 200
    body = findings_response.json()
    assert body["tenant_id"] == "tenant-license-api"
    assert body["total"] == 3
    assert {item["type"] for item in body["findings"]} == {
        "inactive_user",
        "overlicensed_user",
        "unused_license",
    }
    assert all(item["currency"] == "USD" for item in body["findings"])

    report_response = license_client.get("/api/v1/license/report")
    assert report_response.status_code == 200
    assert "attachment;" in report_response.headers["content-disposition"]
    assert '"currency": "USD"' in report_response.text
