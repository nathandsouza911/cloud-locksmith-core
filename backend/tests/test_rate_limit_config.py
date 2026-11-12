"""H3 — rate-limit coverage for state-changing remediation endpoints, plus
user-scoped keying. (The middleware-ordering half of H3 is fixed in app.main
by registering ProxyHeadersMiddleware outermost; it cannot be imported here
because app.main pulls in a passlib/bcrypt path that errors in this env.)
"""

from types import SimpleNamespace

from app.middleware.rate_limit import RATE_LIMITS, _rate_limit_key, RateLimitRule


def test_remediation_execute_endpoints_are_rate_limited_per_user():
    for route_name in (
        "execute_remediation_endpoint",
        "create_break_glass_accounts",
        "execute_attack_path_step_endpoint",
        "execute_attack_path_all_endpoint",
    ):
        assert route_name in RATE_LIMITS, f"{route_name} must be rate limited"
        assert (
            RATE_LIMITS[route_name].scope == "user"
        ), f"{route_name} mutates a tenant and must be keyed per authenticated user"


def test_login_remains_ip_scoped():
    assert RATE_LIMITS["login_password"].scope == "ip"


def test_user_scoped_key_uses_auth_subject(monkeypatch):
    rule = RateLimitRule(limit=30, window_seconds=60, scope="user")
    request = SimpleNamespace(
        state=SimpleNamespace(auth_payload={"sub": "user-123"}),
        headers={},
        cookies={},
        client=SimpleNamespace(host="9.9.9.9"),
    )
    key = _rate_limit_key(request, "execute_remediation_endpoint", rule)
    assert key == "user:user-123:execute_remediation_endpoint"
    # Must NOT fall back to the (shared, proxy) IP for authenticated mutations.
    assert "9.9.9.9" not in key
