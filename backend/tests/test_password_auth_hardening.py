import pytest
from unittest.mock import MagicMock, patch

# auth.py calls hash_password() at module level to pre-compute _DUMMY_HASH.
# The local dev environment has a passlib/bcrypt version mismatch that makes
# this crash.  Patch hash_password before the first import so the module can
# be loaded safely in unit tests.
_MOCK_HASH = "$2b$12$mockedhashfortest"
_hash_patch = patch(
    "app.services.auth.password.hash_password",
    return_value=_MOCK_HASH,
)
_hash_patch.start()

# Import auth module now that the patch is active.

_hash_patch.stop()


def test_signup_password_microsoft_collision_no_provider_leak():
    """
    If email is registered via Microsoft OAuth, signup-password must NOT
    reveal the provider — return generic 409, not 'Use Microsoft login'.
    """
    from app.api.v1.auth import signup_password
    from app.schemas.auth import PasswordSignupRequest

    mock_user = MagicMock()
    mock_user.auth_provider = "microsoft"

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    req = PasswordSignupRequest(email="user@example.com", password="Passw0rd!", name="Org")

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        signup_password(data=req, db=mock_db)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail != "Use Microsoft login"
    assert "registered" in exc_info.value.detail.lower() or "email" in exc_info.value.detail.lower()


def test_verify_email_token_single_use():
    """After a token is used once, a second use must fail."""
    from app.services.auth.email_verification import (
        is_verification_token_used,
        mark_verification_token_used,
        create_email_verification_token,
    )

    token = create_email_verification_token(user_id=42)

    # Mock Redis to simulate single-use tracking
    used_keys = set()
    mock_redis = MagicMock()
    mock_redis.exists.side_effect = lambda key: 1 if key in used_keys else 0
    mock_redis.set.side_effect = lambda key, val, ex=None: used_keys.add(key)

    with patch("app.core.redis_client.redis_client", mock_redis):
        assert not is_verification_token_used(token)
        mark_verification_token_used(token)
        assert is_verification_token_used(token)


def test_verify_email_token_used_check_uses_hash_not_raw():
    """Token is stored as a hash, not the raw token value."""
    import hashlib
    from app.services.auth.email_verification import _token_used_key

    token = "some-jwt-token-value"
    key = _token_used_key(token)
    expected_hash = hashlib.sha256(token.encode()).hexdigest()

    assert token not in key  # raw token not in the key
    assert expected_hash in key  # hash is in the key


def test_signup_password_password_collision_returns_409():
    """If email is already registered with password auth, return 409."""
    from app.api.v1.auth import signup_password
    from app.schemas.auth import PasswordSignupRequest
    from fastapi import HTTPException

    mock_user = MagicMock()
    mock_user.auth_provider = "password"

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    req = PasswordSignupRequest(email="user@example.com", password="Passw0rd!", name="Org")

    # Patch hash_password so the function body (not just module import) also
    # avoids the bcrypt mismatch in this environment.
    with patch("app.api.v1.auth.hash_password", return_value=_MOCK_HASH):
        with pytest.raises(HTTPException) as exc_info:
            signup_password(data=req, db=mock_db)

    assert exc_info.value.status_code == 409
