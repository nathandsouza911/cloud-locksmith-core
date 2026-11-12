"""Demo mode: a recorded, read-only scan of one fictional tenant.

When ``DEMO_MODE=true``:

* the process makes no outbound HTTP calls at all (``guards.install_outbound_block``);
* Microsoft Graph reads for the demo tenant are answered from ``recorded_graph``;
* only the reserved demo tenant is accepted, and every write is refused except
  sign-in, sign-out and the fix simulation (``guards.DemoModeMiddleware``);
* the app refuses to start next to real credentials, production settings, the
  scheduler or auto-remediation (``guards.validate_demo_settings``).

Outside demo mode the reserved demo tenant ID is refused everywhere.
"""

# A syntactically valid Entra tenant GUID reserved for the demo. Real code paths
# refuse it unless DEMO_MODE is on; demo mode refuses every other tenant.
DEMO_TENANT_ID = "00000000-0000-4000-8000-00000000de30"
DEMO_TENANT_NAME = "Contoso (fictional demo)"
DEMO_TENANT_DOMAIN = "contoso.example"
DEMO_ORGANIZATION_NAME = "Contoso (fictional demo)"
DEMO_OWNER_EMAIL = "demo.owner@contoso.example"
DEMO_OWNER_OID = "00000000-0000-4000-8000-0000000000a1"

# The only Microsoft app credentials demo mode will start with: obviously not real.
DEMO_MICROSOFT_CLIENT_ID = "demo-mode-no-microsoft-app"
DEMO_MICROSOFT_CLIENT_SECRET = "demo-mode-no-microsoft-secret"
# Public, demo-only Fernet key used by the demo docker-compose file. It is base64 of
# b"demo-mode-only-not-a-secret-key!". Production refuses to start with it.
DEMO_ENCRYPTION_KEY = "ZGVtby1tb2RlLW9ubHktbm90LWEtc2VjcmV0LWtleSE="

# State-changing requests allowed in demo mode (everything else gets 403).
DEMO_ALLOWED_WRITES = frozenset(
    {
        ("POST", "/api/v1/demo/login"),
        ("POST", "/api/auth/logout"),
        ("POST", "/api/v1/simulations/run"),
    }
)

DEMO_DISABLED_DETAIL = "disabled_in_demo_mode"


class DemoModeViolation(RuntimeError):
    """Raised when code tries to do something demo mode does not allow."""


def demo_mode_enabled() -> bool:
    from app.config import settings

    return bool(getattr(settings, "DEMO_MODE", False))
