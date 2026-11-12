"""POST /api/auth/verify-email on Postgres.

Kept here rather than in tests/test_password_auth.py: the route looks the user up by
the token's string user id against a UUID column, which SQLite's non-native UUID type
cannot bind (Postgres casts it).
"""

from app.db.models.platform_user import PlatformUser
from app.services.auth.email_verification import create_email_verification_token
from app.services.auth.password import hash_password
from tests.integration.utils import TEST_ORIGIN, seed_organization


def test_verify_marks_user_verified(client, db_session):
    org = seed_organization(db_session)
    user = PlatformUser(
        email="v@example.com",
        password_hash=hash_password("securepass1"),
        auth_provider="password",
        verified_at=None,
        role="ADMIN",
        organization_id=org.id,
    )
    db_session.add(user)
    db_session.commit()

    token = create_email_verification_token(user.id)
    resp = client.post("/api/auth/verify-email", json={"token": token}, headers={"Origin": TEST_ORIGIN})

    assert resp.status_code == 200
    db_session.refresh(user)
    assert user.verified_at is not None
