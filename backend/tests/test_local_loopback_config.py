"""LOCAL_LOOPBACK_ONLY: production mode served over http://localhost.

Settings are built with _env_file=None and explicit values so no developer .env is read.
(app.main cannot be imported in tests; see test_rate_limit_config.py.)
"""

import pytest

from app.config import Settings

LOCAL = {
    "BACKEND_PUBLIC_URL": "http://localhost:8000",
    "FRONTEND_URL": "http://localhost:3000",
    "MICROSOFT_REDIRECT_URI": "http://localhost:8000/api/v1/auth/microsoft/callback",
    # conftest.py exports CORS_ALLOWED_ORIGINS; pin it so the process env cannot leak in.
    "CORS_ALLOWED_ORIGINS": "http://localhost:3000",
}


def _settings(**overrides) -> Settings:
    values = {
        "ENVIRONMENT": "production",
        "DATABASE_URL": "postgresql://u:p@localhost/db",
        "MICROSOFT_CLIENT_ID": "client-id",
        "MICROSOFT_CLIENT_SECRET": "client-secret",
        "SESSION_SECRET": "s" * 40,
        "APP_JWT_SECRET": "j" * 40,
        "ENCRYPTION_KEY": "e" * 40,
        "REPORT_SIGNING_SECRET": "r" * 40,
        **LOCAL,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_enforces_https_by_default():
    assert _settings().enforce_https is True


def test_loopback_only_disables_https_enforcement():
    assert _settings(LOCAL_LOOPBACK_ONLY=True).enforce_https is False


def test_development_never_enforces_https():
    assert _settings(ENVIRONMENT="development").enforce_https is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("BACKEND_PUBLIC_URL", "https://cl.example.com"),
        ("FRONTEND_URL", "https://cl.example.com"),
        ("MICROSOFT_REDIRECT_URI", "https://cl.example.com/api/v1/auth/microsoft/callback"),
        ("CORS_ALLOWED_ORIGINS", "http://localhost:3000,https://cl.example.com"),
        ("FRONTEND_URL", "http://localhost.evil.com"),
        ("FRONTEND_URL", "http://localhost@evil.com"),
    ],
)
def test_loopback_only_refuses_non_loopback_url(field, value):
    with pytest.raises(ValueError, match="LOCAL_LOOPBACK_ONLY"):
        _settings(LOCAL_LOOPBACK_ONLY=True, **{field: value})


def test_non_loopback_urls_allowed_without_the_flag():
    s = _settings(FRONTEND_URL="https://cl.example.com")
    assert s.enforce_https is True


def test_loopback_only_accepts_127_0_0_1():
    s = _settings(
        LOCAL_LOOPBACK_ONLY=True,
        BACKEND_PUBLIC_URL="http://127.0.0.1:8000",
        FRONTEND_URL="http://127.0.0.1:3000",
        MICROSOFT_REDIRECT_URI="http://127.0.0.1:8000/api/v1/auth/microsoft/callback",
        CORS_ALLOWED_ORIGINS="http://127.0.0.1:3000",
    )
    assert s.enforce_https is False
