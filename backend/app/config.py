import json
import logging

from pydantic import AnyUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Cloud Locksmith"
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    REMEDIATION_DRY_RUN: bool = True
    ENABLE_SCHEDULER: bool = True
    # Verification lifecycle confirmation thresholds (Phase C)
    VERIFICATION_CONFIRMATION_READS: int = 2
    VERIFICATION_CONFIRMATION_DELAY_SECONDS: float = 30.0
    BACKEND_PUBLIC_URL: AnyUrl
    FRONTEND_URL: AnyUrl

    # Database
    DATABASE_URL: str

    # OAuth
    MICROSOFT_CLIENT_ID: str
    MICROSOFT_CLIENT_SECRET: str
    MICROSOFT_TENANT: str = "common"
    MICROSOFT_REDIRECT_URI: AnyUrl

    # Security
    SESSION_SECRET: str
    APP_JWT_SECRET: str
    # AES-256 Fernet key for encrypting OAuth tokens at rest.
    # Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY: str
    # Dedicated HMAC key for signing report download URLs.
    # MUST differ from APP_JWT_SECRET — key compartmentalization prevents a report
    # signing key compromise from enabling JWT session forgery.
    # Generate: python -c "import secrets; print(secrets.token_hex(32))"
    REPORT_SIGNING_SECRET: str | None = None
    APP_JWT_ALGORITHM: str = "HS256"
    APP_JWT_TTL_HOURS: int = 24
    APP_AUTH_COOKIE_NAME: str = "clx_access_token"
    APP_AUTH_COOKIE_SECURE: bool | None = None

    # Redis — prefer REDIS_URL (Railway); fall back to REDIS_HOST + REDIS_PORT
    REDIS_URL: str | None = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    TRUSTED_PROXY_HOSTS: str = "127.0.0.1,::1"
    RESEND_API_KEY: str | None = None
    SUPPORT_ALERT_EMAIL: str | None = None

    # CORS
    CORS_ALLOWED_ORIGINS: str = ""

    # Domain used for the "from" address of outgoing email (verification, alerts, reports).
    EMAIL_FROM_DOMAIN: str = "example.com"

    # Demo mode: serves a recorded scan of a fictional tenant (see app/demo). It makes no
    # Microsoft calls, accepts only the reserved demo tenant, and refuses every write except
    # sign-in, sign-out and the fix simulation. Never enable it on a real deployment.
    DEMO_MODE: bool = False

    # Optional flags
    # Auto-remediation is OFF by default. Set to true only in production with explicit sign-off.
    ENABLE_AUTO_REMEDIATION: bool = False
    ALLOW_ADMIN_OFFBOARDING: bool = False
    DORMANT_DAYS: int = 60
    UNUSED_ACCOUNT_HIGH_DAYS: int = 90
    CLX_INJECT_TEST_TENANT_CONTROL: bool = False
    REQUIRED_GRAPH_REMEDIATION_PERMISSIONS: list[str] = ["User.EnableDisableAccount.All"]

    @model_validator(mode="after")
    def _validate_signing_secrets(self) -> "Settings":
        if self.ENVIRONMENT.lower() == "production":
            # Force eager evaluation in production — catches missing/invalid
            # REPORT_SIGNING_SECRET at startup, not at first use.
            _ = self.report_signing_secret
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="allow",
    )

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        url = self.DATABASE_URL
        # Railway injects plain `postgresql://` or `postgres://` — rewrite to
        # the asyncpg scheme required by SQLAlchemy's async engine.
        url = url.replace("postgres://", "postgresql://", 1)
        if "+asyncpg" not in url:
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    @property
    def sqlalchemy_sync_database_uri(self) -> str:
        url = self.DATABASE_URL
        url = url.replace("postgres://", "postgresql://", 1)
        # Ensure sync driver — strip asyncpg if present, add psycopg2
        url = url.replace("+asyncpg", "")
        if "+psycopg2" not in url:
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    @property
    def app_auth_cookie_secure(self) -> bool:
        if self.APP_AUTH_COOKIE_SECURE is not None:
            return self.APP_AUTH_COOKIE_SECURE
        return self.ENVIRONMENT.lower() == "production"

    @property
    def trusted_proxy_hosts(self) -> list[str]:
        hosts = [item.strip() for item in (self.TRUSTED_PROXY_HOSTS or "").split(",") if item.strip()]
        if not hosts:
            return ["127.0.0.1", "::1"]
        if "*" in hosts and self.ENVIRONMENT.lower() == "production":
            raise ValueError("TRUSTED_PROXY_HOSTS='*' is not allowed in production")
        return hosts

    @property
    def cors_allowed_origins(self) -> list[str]:
        raw_value = (self.CORS_ALLOWED_ORIGINS or "").strip()
        configured: list[str] = []

        if raw_value:
            try:
                if raw_value.startswith("["):
                    parsed = json.loads(raw_value)
                    if isinstance(parsed, list):
                        configured = [str(origin).strip() for origin in parsed]
                    else:
                        logger.warning("CORS_ALLOWED_ORIGINS JSON value was not a list; falling back to CSV parsing")
                if not configured:
                    configured = [origin.strip() for origin in raw_value.split(",")]
            except Exception:
                logger.warning(
                    "Failed to parse CORS_ALLOWED_ORIGINS=%r; falling back to CSV parsing",
                    raw_value,
                )
                configured = [origin.strip() for origin in raw_value.split(",")]

        normalized: list[str] = []
        for origin in configured:
            cleaned = origin.strip().strip("\"'").rstrip("/")
            if cleaned:
                normalized.append(cleaned)

        configured = list(dict.fromkeys(normalized))
        if configured:
            return configured

        frontend_origin = str(self.FRONTEND_URL).rstrip("/")
        logger.warning(
            "No valid CORS origins configured; falling back to FRONTEND_URL: %s",
            frontend_origin,
        )
        defaults = [frontend_origin]
        if self.ENVIRONMENT.lower() != "production":
            defaults.extend(
                [
                    "http://localhost:3000",
                    "http://localhost:5173",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:5173",
                ]
            )
        return defaults

    @property
    def microsoft_login_base_url(self) -> str:
        tenant = self.MICROSOFT_TENANT.strip() or "common"
        return f"https://login.microsoftonline.com/{tenant}"

    @property
    def microsoft_authorize_url(self) -> str:
        return f"{self.microsoft_login_base_url}/oauth2/v2.0/authorize"

    @property
    def microsoft_token_url(self) -> str:
        return f"{self.microsoft_login_base_url}/oauth2/v2.0/token"

    @property
    def microsoft_admin_consent_url(self) -> str:
        return f"{self.microsoft_login_base_url}/adminconsent"

    @property
    def microsoft_admin_consent_redirect_uri(self) -> str:
        return f"{str(self.BACKEND_PUBLIC_URL).rstrip('/')}/api/v1/auth/microsoft/adminconsent/callback"

    @property
    def secret_key(self) -> str:
        return self.APP_JWT_SECRET

    @property
    def report_signing_secret(self) -> str:
        secret = self.REPORT_SIGNING_SECRET
        if not secret:
            if self.ENVIRONMENT.lower() == "production":
                raise ValueError(
                    "REPORT_SIGNING_SECRET must be set in production. "
                    'Generate: python -c "import secrets; print(secrets.token_hex(32))"'
                )
            # Non-production fallback: append suffix so it differs from APP_JWT_SECRET.
            return self.APP_JWT_SECRET + ":report-signing-v1"
        if secret == self.APP_JWT_SECRET:
            raise ValueError(
                "REPORT_SIGNING_SECRET must differ from APP_JWT_SECRET. "
                "Using the same key removes key compartmentalization."
            )
        return secret


settings = Settings()
