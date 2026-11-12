"""Gate 0 (H1): app.services.tenant_service must never export a tenant
resolver that bypasses UserTenantAccess ownership verification.

Regression: get_tenant_sync / get_tenant_with_fresh_auth read tenant_id out
of the raw session cookie and returned the Tenant row directly, with no
UserTenantAccess check and no get_current_user call at all. They were dead
(no live mounted route depended on them), but their signature was a
drop-in-looking replacement for the verified get_current_tenant family,
making them a landmine for a future cross-tenant IDOR. This test proves
they cannot be silently reintroduced.

The canonical, verified tenant-resolution mechanism remains
get_current_tenant / get_explicit_current_tenant /
get_current_tenant_with_fresh_auth in app.api.dependencies.current_user.
"""

import app.services.tenant_service as tenant_service


def test_get_tenant_sync_is_not_exported():
    assert not hasattr(tenant_service, "get_tenant_sync")


def test_get_tenant_with_fresh_auth_is_not_exported():
    assert not hasattr(tenant_service, "get_tenant_with_fresh_auth")


def test_verified_tenant_dependencies_remain_the_canonical_mechanism():
    from app.api.dependencies.current_user import (
        get_current_tenant,
        get_explicit_current_tenant,
        get_current_tenant_with_fresh_auth,
    )

    assert callable(get_current_tenant)
    assert callable(get_explicit_current_tenant)
    assert callable(get_current_tenant_with_fresh_auth)
