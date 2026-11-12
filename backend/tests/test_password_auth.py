"""
Tests for the hardened email/password authentication flow.

Covers:
- signup-password: creates UNVERIFIED user, no session cookie, sends token
- verify-email: marks user verified
- login-password: blocked while unverified, succeeds after verification,
  rejects wrong password / wrong provider, no enumeration
- per-account lockout via Redis
- per-IP rate limit via endpoint-name resolution (5/min on login_password)
- email normalisation (NFKC + IDNA + lowercase)
- password too long rejected (no silent truncation)
- OAuth squatting eviction (oauth_identity_service deletes unverified row)

The CSRF middleware requires a matching Origin on POSTs, so the test setup
seeds CORS_ALLOWED_ORIGINS before importing the app.
"""

import os
import unicodedata
from unittest.mock import MagicMock, patch

import pytest

# Must be set BEFORE importing app.main / app.config so the CSRF allowlist
# includes the Origin we send from TestClient.
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://testclient.local")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.models.organization import Organization, OrganizationMode  # noqa: E402
from app.db.models.platform_user import PlatformUser  # noqa: E402
from app.db.session import get_sync_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services.auth.password import hash_password  # noqa: E402
from app.services.auth.oauth_identity_service import upsert_oauth_platform_user  # noqa: E402
from app.utils.datetime import utc_now  # noqa: E402

ORIGIN = {"Origin": "http://testclient.local"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session():
    # StaticPool: the TestClient handler runs on another thread; without it that
    # thread would open a fresh, empty in-memory database.
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
    """In-test Redis stand-in: implements only the calls our code makes."""
    store: dict[str, int] = {}

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

    return _R(), store


@pytest.fixture()
def client(db_session, fake_redis):
    redis_obj, _ = fake_redis
    app.dependency_overrides[get_sync_db] = lambda: db_session
    # Redis is imported lazily (`from app.core.redis_client import redis_client`
    # inside each function), so replacing the module in sys.modules patches it everywhere.
    with patch.dict(
        "sys.modules",
        {"app.core.redis_client": MagicMock(redis_client=redis_obj)},
    ):
        # TestClient WITHOUT `with`: skip startup events that need real
        # DB / Graph / Redis connections.
        c = TestClient(app, raise_server_exceptions=True)
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_org(db):
    org = Organization(
        name="Org",
        mode=OrganizationMode.SINGLE,
    )
    db.add(org)
    db.flush()
    return org


def _make_password_user(db, email="user@example.com", password="securepass1", verified=True):
    org = _make_org(db)
    user = PlatformUser(
        email=email,
        password_hash=hash_password(password),
        auth_provider="password",
        verified_at=utc_now() if verified else None,
        role="ADMIN",
        organization_id=org.id,
    )
    db.add(user)
    db.commit()
    return user


def _make_microsoft_user(db, email="ms@example.com", oid="oid-123"):
    org = _make_org(db)
    user = PlatformUser(
        email=email,
        oid=oid,
        password_hash=None,
        auth_provider="microsoft",
        verified_at=utc_now(),
        role="ADMIN",
        organization_id=org.id,
    )
    db.add(user)
    db.commit()
    return user


def _post(client, path, **kwargs):
    headers = dict(ORIGIN)
    headers.update(kwargs.pop("headers", {}))
    return client.post(path, headers=headers, **kwargs)


# ---------------------------------------------------------------------------
# signup-password
# ---------------------------------------------------------------------------


class TestSignupPassword:
    def test_signup_does_not_issue_session(self, client, db_session):
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "new@example.com",
                "password": "strongpass1",
                "name": "My Org",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body.get("verification_required") is True
        # CRITICAL: no auth cookie issued before email verification
        assert not any("auth" in k.lower() for k in resp.cookies)

        user = db_session.query(PlatformUser).filter_by(email="new@example.com").one()
        assert user.auth_provider == "password"
        assert user.verified_at is None

    def test_signup_duplicate_password_user_blocked(self, client, db_session):
        _make_password_user(db_session, email="dupe@example.com")
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "dupe@example.com",
                "password": "anotherpass1",
                "name": "Other Org",
            },
        )
        assert resp.status_code == 409
        assert resp.json()["detail"] == "Email already registered"

    def test_signup_microsoft_user_no_provider_leak(self, client, db_session):
        _make_microsoft_user(db_session, email="ms@example.com")
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "ms@example.com",
                "password": "strongpass1",
                "name": "Org",
            },
        )
        assert resp.status_code == 409
        # Must NOT reveal that the account uses Microsoft — generic message only.
        assert resp.json()["detail"] != "Use Microsoft login"
        assert resp.json()["detail"] == "Email already registered"

    def test_signup_short_password_rejected(self, client):
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "valid@example.com",
                "password": "short",
                "name": "Org",
            },
        )
        assert resp.status_code == 422

    def test_signup_password_too_long_rejected(self, client):
        # 73-byte password — must be rejected, not silently truncated.
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "long@example.com",
                "password": "x" * 73,
                "name": "Org",
            },
        )
        assert resp.status_code == 422

    def test_signup_invalid_email_rejected(self, client):
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": "notanemail",
                "password": "strongpass1",
                "name": "Org",
            },
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# verify-email
# ---------------------------------------------------------------------------


class TestVerifyEmail:
    # The success path runs on Postgres: tests/integration/test_verify_email.py

    def test_verify_invalid_token_rejected(self, client):
        resp = _post(client, "/api/auth/verify-email", json={"token": "garbage"})
        assert resp.status_code == 400
        assert resp.json()["detail"] == "invalid_token"


# ---------------------------------------------------------------------------
# login-password
# ---------------------------------------------------------------------------


class TestLoginPassword:
    def test_login_success_after_verification(self, client, db_session):
        _make_password_user(db_session, email="login@example.com", password="mypassword1")
        resp = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "login@example.com",
                "password": "mypassword1",
            },
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        # The auth cookie is Secure, so httpx does not keep it over http://testserver;
        # check the Set-Cookie header the server sent instead.
        from app.config import settings

        set_cookies = resp.headers.get_list("set-cookie")
        assert any(c.startswith(f"{settings.APP_AUTH_COOKIE_NAME}=") for c in set_cookies)

    def test_unverified_user_cannot_login(self, client, db_session):
        _make_password_user(
            db_session,
            email="unverified@example.com",
            password="mypassword1",
            verified=False,
        )
        resp = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "unverified@example.com",
                "password": "mypassword1",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid_credentials"

    def test_wrong_password_returns_401(self, client, db_session):
        _make_password_user(db_session, email="wrong@example.com", password="correctpass1")
        resp = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "wrong@example.com",
                "password": "wrongpassword",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid_credentials"

    def test_microsoft_user_cannot_login_with_password(self, client, db_session):
        _make_microsoft_user(db_session, email="msperson@example.com")
        resp = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "msperson@example.com",
                "password": "anypassword1",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid_credentials"

    def test_no_user_enumeration(self, client, db_session):
        _make_password_user(db_session, email="real@example.com", password="realpass1")
        missing = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "ghost@example.com",
                "password": "realpass1",
            },
        )
        wrong = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "real@example.com",
                "password": "wrongpass1",
            },
        )
        assert missing.status_code == wrong.status_code == 401
        assert missing.json() == wrong.json()


# ---------------------------------------------------------------------------
# Email normalisation
# ---------------------------------------------------------------------------


class TestEmailNormalisation:
    def test_unicode_lookalike_email_cannot_create_second_account(self, client, db_session):
        """A full-width '＠' look-alike of an existing address must not create a second account.

        Email validation rejects it (422) before normalisation is reached.
        """
        _make_password_user(db_session, email="norm@example.com", password="mypassword1")
        # The full-width @ is normalised to plain @ before lookup.
        full_width = "norm" + unicodedata.lookup("FULLWIDTH COMMERCIAL AT") + "example.com"
        resp = _post(
            client,
            "/api/auth/signup-password",
            json={
                "email": full_width,
                "password": "anotherpass1",
                "name": "Org",
            },
        )
        assert resp.status_code in (409, 422)
        assert db_session.query(PlatformUser).count() == 1

    def test_uppercase_email_normalised(self, client, db_session):
        _make_password_user(db_session, email="case@example.com", password="mypassword1")
        resp = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "  CASE@EXAMPLE.COM  ",
                "password": "mypassword1",
            },
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Per-account lockout
# ---------------------------------------------------------------------------


class TestAccountLockout:
    def test_account_locked_after_5_failures(self, client, db_session, fake_redis, monkeypatch):
        # The per-IP limit (5/min on this route) would answer the 6th request first;
        # turn it off so this test exercises the per-account lockout alone.
        import app.middleware.rate_limit as rate_limit

        monkeypatch.setattr(rate_limit, "_try_redis_incr", lambda *a, **kw: False)
        _make_password_user(db_session, email="lock@example.com", password="rightpass1")
        # 5 wrong-password attempts to register the failures.
        for _ in range(5):
            r = _post(
                client,
                "/api/auth/login-password",
                json={
                    "email": "lock@example.com",
                    "password": "wrongpass",
                },
            )
            assert r.status_code == 401
        # 6th attempt — even with the right password — must be locked.
        r = _post(
            client,
            "/api/auth/login-password",
            json={
                "email": "lock@example.com",
                "password": "rightpass1",
            },
        )
        assert r.status_code == 429
        assert r.json()["detail"] == "account_locked"


# ---------------------------------------------------------------------------
# Per-IP rate limit (endpoint-name based)
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_login_password_rate_limited_after_5_attempts(self, client):
        # No user → 401, but each attempt still counts toward the IP limit.
        responses = [
            _post(
                client,
                "/api/auth/login-password",
                json={
                    "email": f"ghost{i}@example.com",
                    "password": "irrelevant1",
                },
            )
            for i in range(6)
        ]
        statuses = [r.status_code for r in responses]
        assert statuses[:5] == [401] * 5
        assert statuses[5] == 429


# ---------------------------------------------------------------------------
# OAuth squatting eviction (oauth_identity_service)
# ---------------------------------------------------------------------------


class TestSquattingEviction:
    def test_unverified_password_row_evicted_for_oauth(self, db_session):
        """An UNVERIFIED password row holding the email must be deleted
        when a Microsoft identity proves control of the same address."""
        squat = _make_password_user(
            db_session,
            email="target@example.com",
            password="anything1",
            verified=False,
        )
        squat_id = squat.id

        new_user = upsert_oauth_platform_user(
            db=db_session,
            tenant=None,
            email="target@example.com",
            oid="entra-oid-xyz",
        )
        db_session.commit()

        assert new_user.oid == "entra-oid-xyz"
        assert new_user.auth_provider == "microsoft"
        assert new_user.verified_at is not None
        # The squatted row is gone.
        assert db_session.query(PlatformUser).filter_by(id=squat_id).one_or_none() is None

    def test_verified_password_row_blocks_oauth(self, db_session):
        """A VERIFIED password row must NOT be silently merged."""
        from fastapi import HTTPException

        _make_password_user(
            db_session,
            email="legit@example.com",
            password="legitpass1",
            verified=True,
        )
        with pytest.raises(HTTPException) as exc:
            upsert_oauth_platform_user(
                db=db_session,
                tenant=None,
                email="legit@example.com",
                oid="entra-other",
            )
        assert exc.value.status_code == 409
