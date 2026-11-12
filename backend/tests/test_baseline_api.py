import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies.current_user import get_current_tenant, require_write_access
from app.api.v1.baseline import router as baseline_router
from app.api.v1.msp_baseline import router as msp_baseline_router
from app.db.models.compliance_result import ComplianceResult
from app.db.models.msp_security_baseline import BaselineConfig
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.db.session import get_db, get_sync_db


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


class AsyncSessionAdapter:
    def __init__(self, session):
        self._session = session

    async def execute(self, *args, **kwargs):
        return self._session.execute(*args, **kwargs)

    def add(self, *args, **kwargs):
        return self._session.add(*args, **kwargs)

    async def commit(self):
        self._session.commit()

    async def refresh(self, *args, **kwargs):
        self._session.refresh(*args, **kwargs)


def test_apply_baseline_accepts_json_body_and_saves_config():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    BaselineConfig.__table__.create(engine)
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    PostureSnapshot.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    organization_uuid = uuid.uuid4()
    organization_id = str(organization_uuid)
    tenant = Tenant(
        id="tenant-a",
        tenant_name="Tenant A",
        organization_id=organization_uuid,
    )
    session.add(tenant)
    session.commit()

    app = FastAPI()
    app.include_router(baseline_router, prefix="/api/v1")

    def override_get_sync_db():
        yield session

    # organization_id is no longer accepted from the client; it is derived from
    # the authenticated tenant. Override the auth deps to supply that tenant.
    app.dependency_overrides[get_sync_db] = override_get_sync_db
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[require_write_access] = lambda: None

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/baseline/apply",
            json={
                "baseline_name": "Secure Identity",
                "controls": [
                    "IDENTITY_USER_NO_MFA",
                    "IDENTITY_GUEST_INVITES_OPEN",
                ],
            },
        )

    stored = session.query(BaselineConfig).one()

    assert response.status_code == 200
    assert response.json()["status"] == "baseline_applied"
    assert response.json()["tenant_count"] == 1
    assert stored.organization_id == organization_id
    assert stored.baseline_name == "Secure Identity"
    assert stored.is_active is True
    assert stored.controls == [
        "IDENTITY_USER_NO_MFA",
        "IDENTITY_GUEST_INVITES_OPEN",
    ]

    session.close()


def test_baseline_templates_get_creates_default_and_post_persists_template():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    BaselineConfig.__table__.create(engine)
    Tenant.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    organization_uuid = uuid.uuid4()
    tenant = Tenant(
        id="tenant-a",
        tenant_name="Tenant A",
        organization_id=organization_uuid,
    )
    session.add(tenant)
    session.commit()

    app = FastAPI()
    app.include_router(msp_baseline_router, prefix="/api/v1")

    async def override_get_db():
        yield AsyncSessionAdapter(session)

    def override_get_current_tenant():
        return tenant

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_tenant] = override_get_current_tenant
    app.dependency_overrides[require_write_access] = lambda: None

    with TestClient(app) as client:
        list_response = client.get("/api/v1/baseline/templates")
        create_response = client.post(
            "/api/v1/baseline/templates",
            json={
                "baseline_name": "Strict Identity",
                "controls": ["IDENTITY_ADMIN_NO_MFA"],
            },
        )
        refreshed_list_response = client.get("/api/v1/baseline/templates")

    assert list_response.status_code == 200
    assert len(list_response.json()) == 1
    assert list_response.json()[0]["baseline_name"] == "Default Secure Baseline"
    # The default template holds every customer-selectable control.
    from app.services.baseline_service import CUSTOMER_SELECTABLE_CONTROLS

    assert list_response.json()[0]["controls"] == list(CUSTOMER_SELECTABLE_CONTROLS)

    assert create_response.status_code == 200
    assert create_response.json()["baseline_name"] == "Strict Identity"
    assert create_response.json()["controls"] == ["IDENTITY_ADMIN_NO_MFA"]

    assert refreshed_list_response.status_code == 200
    assert [template["baseline_name"] for template in refreshed_list_response.json()] == [
        "Default Secure Baseline",
        "Strict Identity",
    ]

    session.close()
