"""Offboarding never removes emergency access (review 2026-11-19, R1-7).

remove_admin_roles stripped every directory role from any user, and disable_account
was then allowed because the user had no roles left. Nothing checked for registered
break-glass accounts or for the last Global Administrator, and a failed memberOf read
returned [] ("no roles"), which let disable_account through.

Now both offboarding paths refuse a registered break-glass account before any Graph
write, refuse to remove Global Administrator from the last Global Admin who is not a
break-glass account, and treat an unreadable role list as a failure.
"""

import asyncio
from types import SimpleNamespace

import pytest

from app.services import offboarding_service
from app.services.offboarding import offboarding_execute, offboarding_guard
from app.services.offboarding.offboarding_guard import GLOBAL_ADMIN_ROLE_TEMPLATE_ID, OffboardingRefused

TENANT = SimpleNamespace(id="tenant-offboard-guard")
GA_ROLE = {
    "id": "ga-role-object",
    "displayName": "Global Administrator",
    "roleTemplateId": GLOBAL_ADMIN_ROLE_TEMPLATE_ID,
}


@pytest.fixture()
def graph(monkeypatch):
    state = SimpleNamespace(
        break_glass=set(),
        roles_by_user={},
        ga_members=[],
        memberof_fails=False,
        calls=[],
    )

    async def fake_roles(db, tenant, user_id, *, raise_on_error=False):
        state.calls.append(("memberOf", user_id, raise_on_error))
        if state.memberof_fails:
            if raise_on_error:
                raise RuntimeError("Graph 503")
            return []
        return list(state.roles_by_user.get(user_id, []))

    async def fake_get_all(db, tenant, path):
        state.calls.append(("get_all", path))
        assert path.startswith(f"/directoryRoles/{GA_ROLE['id']}/members")
        return [{"id": member} for member in state.ga_members]

    async def fake_post(db, tenant, path, payload):
        state.calls.append(("post", path))
        return {}

    class _Executor:
        async def execute(self, graph_client, evidence):
            state.calls.append(("remove_roles", evidence["user_id"]))
            return {"status": "SUCCESS"}

    class _Verifier:
        def __init__(self, **kwargs):
            pass

        async def verify_with_retries(self, **kwargs):
            return SimpleNamespace(verified=True)

    class _GraphClient:
        def __init__(self, **kwargs):
            pass

        async def set_user_account_enabled(self, user_id, enabled):
            state.calls.append(("disable", user_id))

    async def no_log(**kwargs):
        return None

    monkeypatch.setattr(
        offboarding_guard, "list_break_glass_user_ids", lambda *, db, tenant_id: sorted(state.break_glass)
    )
    monkeypatch.setattr(offboarding_guard, "graph_get_all", fake_get_all)
    monkeypatch.setattr(offboarding_service, "fetch_user_memberof_directory_roles", fake_roles)
    monkeypatch.setattr(offboarding_service, "graph_post", fake_post)
    monkeypatch.setattr(offboarding_service, "AdminRoleExecutor", _Executor)
    monkeypatch.setattr(offboarding_service, "AdminRoleVerifier", _Verifier)
    monkeypatch.setattr(offboarding_service, "RemediationGraphClient", _GraphClient)
    monkeypatch.setattr(offboarding_service, "_log_offboarding_step_context", no_log)
    return state


def _step(action, user_id):
    return asyncio.run(offboarding_service._execute_user_action(db=None, tenant=TENANT, action=action, user_id=user_id))


@pytest.mark.parametrize("action", ["revoke_sessions", "remove_admin_roles", "disable_account"])
def test_a_break_glass_account_is_refused_before_any_graph_call(graph, action):
    graph.break_glass = {"bg-1"}
    graph.roles_by_user["bg-1"] = [GA_ROLE]
    with pytest.raises(OffboardingRefused, match="BREAK_GLASS"):
        _step(action, "bg-1")
    assert graph.calls == []


def test_the_last_global_admin_keeps_the_role(graph):
    graph.roles_by_user["admin-1"] = [GA_ROLE]
    graph.ga_members = ["admin-1", "bg-1"]  # only a break-glass account would be left
    graph.break_glass = {"bg-1"}
    with pytest.raises(OffboardingRefused, match="LAST_GLOBAL_ADMIN"):
        _step("remove_admin_roles", "admin-1")
    assert ("remove_roles", "admin-1") not in graph.calls


def test_a_global_admin_can_be_offboarded_when_another_remains(graph):
    graph.roles_by_user["admin-1"] = [GA_ROLE]
    graph.ga_members = ["admin-1", "admin-2"]
    _step("remove_admin_roles", "admin-1")
    assert ("remove_roles", "admin-1") in graph.calls


def test_disable_fails_closed_when_roles_cannot_be_read(graph):
    graph.memberof_fails = True
    with pytest.raises(Exception):
        _step("disable_account", "user-1")
    assert ("disable", "user-1") not in graph.calls


def test_one_click_offboarding_refuses_a_break_glass_account(monkeypatch, graph):
    graph.break_glass = {"bg-1"}

    async def must_not_snapshot(*args, **kwargs):
        raise AssertionError("no Graph call for a break-glass account")

    monkeypatch.setattr(offboarding_execute, "snapshot_user_state", must_not_snapshot)
    result = asyncio.run(
        offboarding_execute.execute_offboarding(None, TENANT, "bg-1", options={}, reason="test", force=True)
    )
    assert result["status"] == "blocked"
    assert "break-glass" in result["reason"].lower()


def test_one_click_offboarding_refuses_the_last_global_admin_before_any_write(monkeypatch, graph):
    graph.ga_members = ["admin-1"]

    async def snapshot(db, tenant, user_id):
        return {"user_id": user_id, "account_enabled": True, "roles": [GA_ROLE]}

    async def must_not_get_token(*args, **kwargs):
        raise AssertionError("nothing may run after the refusal")

    monkeypatch.setattr(offboarding_execute, "snapshot_user_state", snapshot)
    monkeypatch.setattr(offboarding_execute, "get_valid_access_token", must_not_get_token)
    monkeypatch.setattr(offboarding_execute.settings, "ALLOW_ADMIN_OFFBOARDING", True)
    result = asyncio.run(
        offboarding_execute.execute_offboarding(None, TENANT, "admin-1", options={}, reason="test", force=True)
    )
    assert result["status"] == "blocked"
    assert "LAST_GLOBAL_ADMIN" in result["reason"]
