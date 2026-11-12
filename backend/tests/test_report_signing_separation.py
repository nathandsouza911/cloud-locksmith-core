import pytest


def test_report_signing_secret_differs_from_jwt_secret():
    """report_signing_secret must differ from APP_JWT_SECRET."""
    from app.config import Settings

    s = Settings(
        DATABASE_URL="postgresql://x",
        MICROSOFT_CLIENT_ID="x",
        MICROSOFT_CLIENT_SECRET="x",
        MICROSOFT_REDIRECT_URI="http://localhost",
        SESSION_SECRET="x",
        APP_JWT_SECRET="jwt-secret-test",
        ENCRYPTION_KEY="test-encryption-key-32-bytes-long!!",
        BACKEND_PUBLIC_URL="http://localhost",
        FRONTEND_URL="http://localhost",
        REPORT_SIGNING_SECRET="report-secret-different",
    )
    assert s.report_signing_secret == "report-secret-different"
    assert s.report_signing_secret != s.secret_key


def test_report_signing_secret_cannot_equal_jwt_secret():
    """Startup must reject REPORT_SIGNING_SECRET == APP_JWT_SECRET."""
    from app.config import Settings

    s = Settings(
        DATABASE_URL="postgresql://x",
        MICROSOFT_CLIENT_ID="x",
        MICROSOFT_CLIENT_SECRET="x",
        MICROSOFT_REDIRECT_URI="http://localhost",
        SESSION_SECRET="x",
        APP_JWT_SECRET="shared-secret",
        ENCRYPTION_KEY="test-encryption-key-32-bytes-long!!",
        BACKEND_PUBLIC_URL="http://localhost",
        FRONTEND_URL="http://localhost",
        REPORT_SIGNING_SECRET="shared-secret",
    )
    with pytest.raises(ValueError, match="must differ"):
        _ = s.report_signing_secret


def test_report_signing_secret_non_production_fallback():
    """In non-production, a fallback derived key is used if REPORT_SIGNING_SECRET not set."""
    from app.config import Settings

    s = Settings(
        DATABASE_URL="postgresql://x",
        MICROSOFT_CLIENT_ID="x",
        MICROSOFT_CLIENT_SECRET="x",
        MICROSOFT_REDIRECT_URI="http://localhost",
        SESSION_SECRET="x",
        APP_JWT_SECRET="jwt-secret",
        ENCRYPTION_KEY="test-encryption-key-32-bytes-long!!",
        BACKEND_PUBLIC_URL="http://localhost",
        FRONTEND_URL="http://localhost",
        ENVIRONMENT="development",
        REPORT_SIGNING_SECRET=None,
    )
    result = s.report_signing_secret
    assert result != "jwt-secret"  # Fallback differs from JWT secret
    assert "jwt-secret" in result  # Derived from JWT secret with suffix


def test_report_signing_secret_required_in_production():
    """In production, REPORT_SIGNING_SECRET must be set — validated at startup."""
    from app.config import Settings

    with pytest.raises(Exception, match="REPORT_SIGNING_SECRET"):
        Settings(
            DATABASE_URL="postgresql://x",
            MICROSOFT_CLIENT_ID="x",
            MICROSOFT_CLIENT_SECRET="x",
            MICROSOFT_REDIRECT_URI="http://localhost",
            SESSION_SECRET="x",
            APP_JWT_SECRET="jwt-secret",
            ENCRYPTION_KEY="A" * 44,
            BACKEND_PUBLIC_URL="http://localhost",
            FRONTEND_URL="http://localhost",
            ENVIRONMENT="production",
            # REPORT_SIGNING_SECRET intentionally absent
        )
