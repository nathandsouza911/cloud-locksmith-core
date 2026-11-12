"""M2 — the legacy unverified /auth/signup endpoint is disabled.

The legacy endpoint issued an authenticated session with no email verification
(and created accounts that could never log in again). It must now refuse with
410 Gone and create no Organization / PlatformUser / session. The verified
/auth/signup-password -> verify-email flow remains the only signup path.
"""

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.v1 import auth
from app.db.base import Base
from app.db.models.organization import Organization
from app.db.models.platform_user import PlatformUser
from app.schemas.auth import PasswordSignupRequest, SignupRequest


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_legacy_signup_returns_410_and_creates_nothing():
    session = _make_session()
    response = Response()

    with pytest.raises(HTTPException) as exc_info:
        auth.signup(
            data=SignupRequest(
                email="new@example.com",
                password="averylongpassword",
                name="Acme IT",
            ),
            response=response,
            db=session,
        )

    assert exc_info.value.status_code == 410
    # Fail closed: no org, no user, no session cookie.
    assert session.query(PlatformUser).count() == 0
    assert session.query(Organization).count() == 0
    assert "set-cookie" not in {k.lower() for k in response.headers.keys()}
    session.close()


def test_verified_password_signup_still_requires_verification(monkeypatch):
    session = _make_session()
    monkeypatch.setattr(auth, "send_verification_email", lambda *a, **k: None)

    result = auth.signup_password(
        data=PasswordSignupRequest(
            email="owner@example.com",
            password="averylongpassword",
            name="Acme IT",
        ),
        db=session,
    )

    assert result["verification_required"] is True
    user = session.query(PlatformUser).one()
    assert user.auth_provider == "password"
    # No session until the email is verified.
    assert user.verified_at is None
    session.close()
