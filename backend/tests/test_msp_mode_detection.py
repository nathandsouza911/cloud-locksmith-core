"""
TDD tests for MSP/SMB mode detection.

Tests are written BEFORE the implementation change. They should FAIL initially
because signup_password always creates SINGLE orgs and there is no is_msp field.

Covers:
- SMB signup creates SINGLE org (regression)
- MSP signup with is_msp=True creates MANAGED org
- session/context returns mode="MSP" for MANAGED org user with zero tenants
- session/context returns mode="SMB" for SINGLE org user with zero tenants
- session/context returns mode="MSP" for user with MSP_MANAGER access rows (regression)
- session/context returns mode="SMB" for user with SMB_OWNER access rows (regression)
"""

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://testclient.local")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api.v1.session import get_session_context  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.models.organization import Organization, OrganizationMode  # noqa: E402
from app.db.models.platform_user import PlatformUser  # noqa: E402
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole  # noqa: E402
from app.db.session import get_sync_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services.auth.password import hash_password  # noqa: E402
from app.utils.datetime import utc_now  # noqa: E402

ORIGIN = {"Origin": "http://testclient.local"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session():
    # StaticPool ensures create_all and the session share the same in-memory
    # SQLite connection. Without it, each new connection gets an empty database.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def fake_redis():
    store: dict = {}

    class _R:
        def incr(self, key):
            store[key] = store.get(key, 0) + 1
            return store[key]

        def expire(self, key, ttl):
            return True

        def get(self, key):
            return store.get(key)

        def delete(self, key):
            store.pop(key, None)
            return 1

        def exists(self, key):
            return 1 if key in store else 0

        def set(self, key, value, ex=None):
            store[key] = value

    return _R(), store


@pytest.fixture()
def client(db_session, fake_redis):
    redis_obj, _ = fake_redis
    app.dependency_overrides[get_sync_db] = lambda: db_session
    with patch.dict(
        "sys.modules",
        {"app.core.redis_client": MagicMock(redis_client=redis_obj)},
    ):
        c = TestClient(app, raise_server_exceptions=True)
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _post(client, path, **kwargs):
    headers = dict(ORIGIN)
    headers.update(kwargs.pop("headers", {}))
    return client.post(path, headers=headers, **kwargs)


def _make_org(db, mode=OrganizationMode.SINGLE):
    org = Organization(name="TestOrg", mode=mode)
    db.add(org)
    db.flush()
    return org


def _make_user(db, org, email="user@example.com"):
    user = PlatformUser(
        email=email,
        password_hash=hash_password("testpass123"),
        auth_provider="password",
        verified_at=utc_now(),
        role="ADMIN",
        organization_id=org.id,
    )
    db.add(user)
    db.flush()
    return user


def _add_access(db, user, tenant_id, access_type, role=UserTenantRole.ADMIN):
    row = UserTenantAccess(
        user_id=user.id,
        tenant_id=tenant_id,
        role=role,
        access_type=access_type,
        organization_id=user.organization_id,
    )
    db.add(row)
    db.flush()
    return row


# ---------------------------------------------------------------------------
# signup-password: is_msp flag
# ---------------------------------------------------------------------------


class TestSignupMspFlag:
    def test_smb_signup_creates_single_org(self, client, db_session):
        """Default signup (no is_msp) creates SINGLE mode org — regression."""
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "smb@example.com",
                "password": "strongpass1",
                "name": "SMB Corp",
            },
        )
        assert resp.status_code == 200

        user = db_session.query(PlatformUser).filter_by(email="smb@example.com").one()
        org = db_session.query(Organization).filter_by(id=user.organization_id).one()
        assert org.mode == OrganizationMode.SINGLE

    def test_msp_signup_with_flag_creates_managed_org(self, client, db_session):
        """Signup with is_msp=True must create MANAGED mode org."""
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "msp@example.com",
                "password": "strongpass1",
                "name": "MSP Corp",
                "is_msp": True,
            },
        )
        assert resp.status_code == 200

        user = db_session.query(PlatformUser).filter_by(email="msp@example.com").one()
        org = db_session.query(Organization).filter_by(id=user.organization_id).one()
        assert org.mode == OrganizationMode.MANAGED

    def test_msp_flag_false_creates_single_org(self, client, db_session):
        """Explicit is_msp=False behaves identically to omitting the field."""
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "smb2@example.com",
                "password": "strongpass1",
                "name": "SMB Corp 2",
                "is_msp": False,
            },
        )
        assert resp.status_code == 200

        user = db_session.query(PlatformUser).filter_by(email="smb2@example.com").one()
        org = db_session.query(Organization).filter_by(id=user.organization_id).one()
        assert org.mode == OrganizationMode.SINGLE


# ---------------------------------------------------------------------------
# session/context: mode resolution (direct function calls — avoids UUID/SQLite issues)
# ---------------------------------------------------------------------------


class TestSessionContextModeResolution:
    def test_smb_user_zero_tenants_returns_smb(self, db_session):
        """SINGLE org, no tenant rows → mode must be SMB."""
        org = _make_org(db_session, mode=OrganizationMode.SINGLE)
        user = _make_user(db_session, org, email="smb_zero@example.com")
        db_session.commit()

        result = get_session_context(db=db_session, current_user=user)
        assert result.mode == "SMB"

    def test_msp_user_zero_tenants_returns_msp(self, db_session):
        """MANAGED org, no tenant rows → mode must be MSP (the keystone case)."""
        org = _make_org(db_session, mode=OrganizationMode.MANAGED)
        user = _make_user(db_session, org, email="msp_zero@example.com")
        db_session.commit()

        result = get_session_context(db=db_session, current_user=user)
        assert result.mode == "MSP"

    def test_msp_user_with_msp_manager_rows_returns_msp(self, db_session):
        """MSP_MANAGER access rows → mode must be MSP (existing behavior, regression)."""
        org = _make_org(db_session, mode=OrganizationMode.MANAGED)
        user = _make_user(db_session, org, email="msp_rows@example.com")
        _add_access(db_session, user, "tenant-abc", TenantAccessType.MSP_MANAGER)
        db_session.commit()

        result = get_session_context(db=db_session, current_user=user)
        assert result.mode == "MSP"

    def test_smb_user_with_smb_owner_rows_returns_smb(self, db_session):
        """SMB_OWNER access rows → mode must be SMB (existing behavior, regression)."""
        org = _make_org(db_session, mode=OrganizationMode.SINGLE)
        user = _make_user(db_session, org, email="smb_rows@example.com")
        _add_access(db_session, user, "tenant-xyz", TenantAccessType.SMB_OWNER)
        db_session.commit()

        result = get_session_context(db=db_session, current_user=user)
        assert result.mode == "SMB"

    def test_msp_user_with_multiple_tenants_returns_msp(self, db_session):
        """MANAGED org with multiple MSP_MANAGER rows → mode is MSP, tenant_id is None."""
        org = _make_org(db_session, mode=OrganizationMode.MANAGED)
        user = _make_user(db_session, org, email="msp_multi@example.com")
        _add_access(db_session, user, "tenant-1", TenantAccessType.MSP_MANAGER)
        _add_access(db_session, user, "tenant-2", TenantAccessType.MSP_MANAGER)
        db_session.commit()

        result = get_session_context(db=db_session, current_user=user)
        assert result.mode == "MSP"
        assert result.tenant_id is None  # MSP never returns a pre-selected tenant
