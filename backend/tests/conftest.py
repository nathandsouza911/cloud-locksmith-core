import pytest
import os
import sys
import types
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import JSONB

from app.db.base import Base
from app.db.models.tenant_oauth import TenantOAuth  # noqa: F401 — registers table with Base.metadata
from app.db.models.campaign_audit_event import CampaignAuditEvent  # noqa: F401
from app.db.models.campaign_notarization_receipt import CampaignNotarizationReceipt  # noqa: F401
from app.db.models.signing_key_metadata import SigningKeyMetadata  # noqa: F401
from app.db.models.campaign_scheduled_job import CampaignScheduledJob  # noqa: F401
from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.constants import PRIVILEGED_ROLE_IDS


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(element, compiler, **kw):
    return compiler.visit_JSON(element, **kw)


try:
    import pydantic_settings as _pydantic_settings  # noqa: F401
except Exception:
    from pydantic import BaseSettings as _PydanticBaseSettings

    class _CompatBaseSettings(_PydanticBaseSettings):
        class Config:
            extra = "allow"

        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            model_config = getattr(cls, "model_config", None) or {}
            config_updates = {}
            if "env_file" in model_config:
                config_updates["env_file"] = model_config["env_file"]
            if "extra" in model_config:
                config_updates["extra"] = model_config["extra"]
            if config_updates:
                base_config = getattr(cls, "Config", object)
                cls.Config = type("Config", (base_config,), config_updates)

    shim = types.ModuleType("pydantic_settings")
    shim.BaseSettings = _CompatBaseSettings
    shim.SettingsConfigDict = dict
    sys.modules["pydantic_settings"] = shim


os.environ.setdefault("BACKEND_PUBLIC_URL", "http://localhost:8000")
os.environ.setdefault("FRONTEND_URL", "http://localhost:3000")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/testdb")
os.environ.setdefault("MICROSOFT_CLIENT_ID", "test-client-id")
os.environ.setdefault("MICROSOFT_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("MICROSOFT_REDIRECT_URI", "http://localhost:8000/callback")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("APP_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!!")
# Origin used by the TestClient-based auth tests. Set here (the first conftest loaded) so it is
# in place before any test module imports app.main and the settings are built.
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://testclient.local")

_CA_TENANT_ID = "ca-test-tenant-123"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture()
def tenant():
    class Tenant:
        id = "tenant-123"

    return Tenant()


# ---------------------------------------------------------------------------
# CA / GraphContext fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_tenant_context_minimal():
    return TenantGraphContext(
        tenant_id=_CA_TENANT_ID,
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=[],
        break_glass_accounts=[],
    )


@pytest.fixture()
def mock_ca_policy_enabled_mfa_all_users():
    return {
        "id": "policy-mfa-all-users",
        "displayName": "Require MFA for All Users",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }


@pytest.fixture()
def mock_ca_policy_admin_mfa():
    return {
        "id": "policy-mfa-admins",
        "displayName": "Require MFA for Admins",
        "state": "enabled",
        "conditions": {
            "users": {"includeRoles": sorted(PRIVILEGED_ROLE_IDS)},
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }


@pytest.fixture()
def mock_ca_policy_legacy_auth_block():
    return {
        "id": "policy-block-legacy-auth",
        "displayName": "Block Legacy Authentication",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["exchangeActiveSync", "other"],
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"builtInControls": ["block"]},
    }


@pytest.fixture()
def mock_ca_policy_device_code_block():
    return {
        "id": "policy-block-device-code",
        "displayName": "Block Device Code Flow",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "authenticationFlows": {"transferMethods": ["deviceCodeFlow"]},
        },
        "grantControls": None,
    }


@pytest.fixture()
def mock_ca_policy_authentication_transfer_block():
    return {
        "id": "policy-block-auth-transfer",
        "displayName": "Block Authentication Transfer",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "authenticationFlows": {"transferMethods": ["authenticationTransfer"]},
        },
        "grantControls": {"builtInControls": ["block"]},
    }


@pytest.fixture()
def mock_ca_policy_guest_mfa():
    return {
        "id": "policy-guest-mfa",
        "displayName": "Require MFA for Guests",
        "state": "enabled",
        "conditions": {
            "users": {
                "includeGuestsOrExternalUsers": {
                    "externalTenants": {"membershipKind": "all"},
                    "guestOrExternalUserTypes": (
                        "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,"
                        "b2bDirectConnectUser,otherExternalUser,serviceProvider"
                    ),
                }
            },
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }


class _UnavailableRedis:
    """Stands in for Redis during tests: every command fails at once, as when Redis is down.

    Without this, each call waits out the real client's connect timeout and retries
    against localhost:6379. Tests that need Redis behaviour patch redis_client themselves.
    """

    def __getattr__(self, name):
        def _fail(*args, **kwargs):
            import redis

            raise redis.exceptions.ConnectionError("Redis is not available in the test suite")

        return _fail


@pytest.fixture(autouse=True)
def _redis_unavailable(monkeypatch):
    import app.core.redis_client as redis_module

    monkeypatch.setattr(redis_module, "redis_client", _UnavailableRedis())
