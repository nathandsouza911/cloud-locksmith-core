"""Register an existing break-glass account (ROADMAP 2.7, live-run gap G1).

Before this, the pre-flight check only knew accounts the product created itself, so
every Conditional Access fix was refused until someone inserted a database row by
hand. The registration service checks with Graph that the account is an enabled
member and a current Global Administrator of *this* tenant, stores its object id,
and audits the change.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.db.models.audit_log import AuditLog
from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.tenant import Tenant
from app.services import break_glass_registration as reg
from app.services.graph_client import GraphAPIError

TENANT_A = "tenant-bg-a"
TENANT_B = "tenant-bg-b"
GA_ROLE = {"id": "role-ga", "displayName": "Global Administrator"}
USER_ID = "11111111-1111-1111-1111-111111111111"


def _user(**overrides) -> dict:
    user = {
        "id": USER_ID,
        "userPrincipalName": "bg1@contoso.example",
        "displayName": "Emergency 1",
        "accountEnabled": True,
        "userType": "Member",
        "onPremisesSyncEnabled": None,
    }
    user.update(overrides)
    return user


def _graph_error(status: int) -> GraphAPIError:
    return GraphAPIError(method="GET", path="/users/x", status_code=status, response_body="{}", category="x")


@pytest.fixture()
def tenants(db_session):
    a = Tenant(id=TENANT_A, tenant_name="a")
    b = Tenant(id=TENANT_B, tenant_name="b")
    db_session.add_all([a, b])
    db_session.commit()
    return a, b


def _patched(user=None, user_error=None, admins=(USER_ID,)):
    graph_get = AsyncMock(side_effect=user_error) if user_error else AsyncMock(return_value=user or _user())
    roles = AsyncMock(return_value=[GA_ROLE])
    members = AsyncMock(return_value=[{"id": admin} for admin in admins])
    return (
        (
            patch.object(reg, "graph_get", graph_get),
            patch.object(reg, "fetch_directory_roles", roles),
            patch.object(reg, "fetch_role_members", members),
        ),
        graph_get,
        members,
    )


def _register(db, tenant, user_ref=USER_ID, **kw):
    patches, graph_get, members = _patched(**kw)
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(reg.register_existing(db, tenant, user_ref, actor="owner@contoso.example"))
    return result, graph_get, members


def _audit(db, action):
    return db.query(AuditLog).filter(AuditLog.action == action).all()


def test_registers_active_global_admin_and_audits(db_session, tenants):
    a, _ = tenants
    result, _, _ = _register(db_session, a)

    rows = db_session.query(BreakGlassAccount).all()
    assert [(r.tenant_id, r.user_external_id) for r in rows] == [(TENANT_A, USER_ID)]
    assert result["user_external_id"] == USER_ID
    assert result["user_principal_name"] == "bg1@contoso.example"
    assert result["warnings"] == []
    audit = _audit(db_session, "BREAK_GLASS_REGISTERED")
    assert len(audit) == 1
    assert audit[0].tenant_id == TENANT_A
    assert audit[0].target == USER_ID
    assert audit[0].actor == "owner@contoso.example"


@pytest.mark.parametrize(
    "user, code",
    [
        (_user(accountEnabled=False), "ACCOUNT_DISABLED"),
        (_user(userType="Guest"), "GUEST_ACCOUNT"),
    ],
)
def test_refuses_accounts_that_cannot_sign_in_as_members(db_session, tenants, user, code):
    a, _ = tenants
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a, user=user)
    assert exc.value.code == code
    assert exc.value.status_code == 400
    assert db_session.query(BreakGlassAccount).count() == 0
    assert _audit(db_session, "BREAK_GLASS_REGISTERED") == []


def test_refuses_non_global_admin(db_session, tenants):
    a, _ = tenants
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a, admins=("someone-else",))
    assert exc.value.code == "NOT_GLOBAL_ADMIN"
    assert db_session.query(BreakGlassAccount).count() == 0


def test_user_not_found_maps_404(db_session, tenants):
    a, _ = tenants
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a, user_error=_graph_error(404))
    assert (exc.value.code, exc.value.status_code) == ("USER_NOT_FOUND", 404)


def test_graph_error_maps_502_and_stores_nothing(db_session, tenants):
    a, _ = tenants
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a, user_error=_graph_error(503))
    assert (exc.value.code, exc.value.status_code) == ("GRAPH_UNAVAILABLE", 502)
    assert db_session.query(BreakGlassAccount).count() == 0


def test_duplicate_is_409(db_session, tenants):
    a, _ = tenants
    _register(db_session, a)
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a)
    assert (exc.value.code, exc.value.status_code) == ("ALREADY_REGISTERED", 409)
    assert db_session.query(BreakGlassAccount).count() == 1


def test_upn_and_object_id_are_the_same_account(db_session, tenants):
    a, _ = tenants
    _, graph_get, _ = _register(db_session, a, user_ref="  BG1@contoso.example ")
    assert graph_get.await_args.args[2].startswith("/users/BG1@contoso.example?")
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a, user_ref=USER_ID)
    assert exc.value.code == "ALREADY_REGISTERED"


def test_invalid_reference_is_refused_before_graph(db_session, tenants):
    a, _ = tenants
    for bad in ("", "   ", "a/b", "x?y", "x" * 300):
        with pytest.raises(reg.BreakGlassRegistrationError) as exc:
            _register(db_session, a, user_ref=bad)
        assert exc.value.code == "INVALID_USER"


def test_synced_account_registers_with_warning(db_session, tenants):
    a, _ = tenants
    result, _, _ = _register(db_session, a, user=_user(onPremisesSyncEnabled=True))
    assert result["warnings"] == ["synced_from_on_premises"]
    assert db_session.query(BreakGlassAccount).count() == 1


def test_list_is_scoped_to_the_tenant(db_session, tenants):
    a, b = tenants
    db_session.add_all(
        [
            BreakGlassAccount(tenant_id=TENANT_A, user_external_id="a-1"),
            BreakGlassAccount(tenant_id=TENANT_B, user_external_id="b-1"),
        ]
    )
    db_session.commit()
    assert [r["user_external_id"] for r in reg.list_registered(db_session, a)] == ["a-1"]
    assert [r["user_external_id"] for r in reg.list_registered(db_session, b)] == ["b-1"]


def test_remove_deletes_and_audits(db_session, tenants):
    a, _ = tenants
    result, _, _ = _register(db_session, a)
    reg.remove_registered(db_session, a, result["id"], actor="owner@contoso.example")
    assert db_session.query(BreakGlassAccount).count() == 0
    removed = _audit(db_session, "BREAK_GLASS_REMOVED")
    assert len(removed) == 1 and removed[0].target == USER_ID


def test_remove_other_tenants_row_is_not_found(db_session, tenants):
    a, _ = tenants
    other = BreakGlassAccount(tenant_id=TENANT_B, user_external_id="b-1")
    db_session.add(other)
    db_session.commit()
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        reg.remove_registered(db_session, a, other.id, actor="owner@contoso.example")
    assert (exc.value.code, exc.value.status_code) == ("NOT_FOUND", 404)
    assert db_session.query(BreakGlassAccount).count() == 1
    assert _audit(db_session, "BREAK_GLASS_REMOVED") == []


def test_global_admin_of_other_tenant_is_checked_against_this_tenant(db_session, tenants):
    """Graph calls use the session tenant; a GA of tenant B is not a GA of tenant A."""
    a, _ = tenants
    with pytest.raises(reg.BreakGlassRegistrationError) as exc:
        _register(db_session, a, admins=("a-admin-only",))
    assert exc.value.code == "NOT_GLOBAL_ADMIN"


def test_graph_is_called_with_the_session_tenant(db_session, tenants):
    a, _ = tenants
    _, graph_get, members = _register(db_session, a)
    assert graph_get.await_args.args[1] is a
    assert members.await_args.args[1] is a


def test_audit_failure_aborts_registration(db_session, tenants):
    """Register/remove are critical audit events: no durable record, no change."""
    from app.services.audit.critical_events import AuditPersistenceError

    a, _ = tenants
    with patch("app.services.audit.audit_logger._compute_sequence_hash", side_effect=RuntimeError("boom")):
        with pytest.raises(AuditPersistenceError):
            _register(db_session, a)
    assert db_session.query(BreakGlassAccount).count() == 0
