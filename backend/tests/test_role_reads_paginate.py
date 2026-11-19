"""Review R2-11: directory role reads must follow @odata.nextLink.

Before the fix, /directoryRoles/{id}/members and /users/{id}/memberOf were
read with a single graph_get, so role holders (or roles) on the second page
were missed: the scan under-counted admins, and the "never disable a
privileged user" safeguard saw no roles for a user in many groups.
"""

from types import SimpleNamespace

import pytest

from app.services import graph_client

GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
NEXT = "https://graph.microsoft.com/v1.0/next-page"
GA_ROLE = {
    "@odata.type": "#microsoft.graph.directoryRole",
    "id": "role-ga",
    "displayName": "Global Administrator",
    "roleTemplateId": GA_TEMPLATE,
}


def _group(n: int) -> dict:
    return {"@odata.type": "#microsoft.graph.group", "id": f"group-{n}", "displayName": f"Group {n}"}


def _member(uid: str) -> dict:
    return {"@odata.type": "#microsoft.graph.user", "id": uid, "displayName": uid}


@pytest.fixture()
def fake_graph(monkeypatch):
    """Serve a first page for any path that has one, and the second page at NEXT."""
    pages: dict[str, dict] = {}

    async def fake_request(*, method, path, headers, payload=None):
        if path == NEXT:
            body = pages[NEXT]
        else:
            key = next((k for k in pages if k != NEXT and path.startswith(k)), None)
            body = pages[key] if key else {"value": []}
        return SimpleNamespace(status_code=200, text="{}", json=lambda: body, headers={})

    async def token(*args, **kwargs):
        return "token"

    async def connected(*args, **kwargs):
        return True

    monkeypatch.setattr(graph_client, "_graph_request", fake_request)
    monkeypatch.setattr(graph_client, "get_valid_access_token", token)
    monkeypatch.setattr(graph_client, "has_delegated_oauth_token", connected)
    monkeypatch.setattr(graph_client, "_validate_access_token_tenant", lambda **kwargs: None)
    return pages


TENANT = SimpleNamespace(id="tenant-paging")


def _two_page_memberof(pages: dict, user_id: str) -> None:
    pages[f"/users/{user_id}/memberOf"] = {"value": [_group(1), _group(2)], "@odata.nextLink": NEXT}
    pages[NEXT] = {"value": [GA_ROLE]}


def _two_page_members(pages: dict, role_id: str, second_page_user: str) -> None:
    pages[f"/directoryRoles/{role_id}/members"] = {"value": [_member("first-page-user")], "@odata.nextLink": NEXT}
    pages[NEXT] = {"value": [_member(second_page_user)]}


@pytest.mark.asyncio
async def test_fetch_role_members_reads_every_page(fake_graph):
    from app.services.graph_role_members_service import fetch_role_members

    _two_page_members(fake_graph, "role-ga", "second-page-user")

    members = await fetch_role_members(None, TENANT, "role-ga")

    assert {m["id"] for m in members} == {"first-page-user", "second-page-user"}


@pytest.mark.asyncio
async def test_scan_role_map_reads_every_page_of_members(fake_graph):
    from app.services.identity_scan_service import _build_role_map

    fake_graph["/directoryRoles/role-ga/members"] = {
        "value": [_member("first-page-user")],
        "@odata.nextLink": NEXT,
    }
    fake_graph["/directoryRoles"] = {"value": [GA_ROLE]}
    fake_graph[NEXT] = {"value": [_member("second-page-user")]}

    role_map = await _build_role_map(None, TENANT)

    assert "second-page-user" in role_map


@pytest.mark.asyncio
async def test_overprivileged_role_evidence_reads_every_page_of_memberof(fake_graph):
    from app.services.detection.identity_overprivileged_admin import load_overprivileged_role_evidence

    _two_page_memberof(fake_graph, "user-many-groups")

    evidence = await load_overprivileged_role_evidence(db=None, tenant=TENANT, user_id="user-many-groups")

    assert [r["role_name"] for r in evidence["current_roles"]] == ["Global Administrator"]


@pytest.mark.asyncio
async def test_fetch_user_memberof_directory_roles_reads_every_page(fake_graph):
    _two_page_memberof(fake_graph, "user-many-groups")

    roles = await graph_client.fetch_user_memberof_directory_roles(None, TENANT, "user-many-groups")

    assert [r["id"] for r in roles] == ["role-ga"]


@pytest.mark.asyncio
async def test_privileged_user_safeguard_sees_roles_on_later_pages(fake_graph):
    _two_page_memberof(fake_graph, "user-many-groups")

    roles = await graph_client.get_user_directory_roles_with_token(access_token="token", user_id="user-many-groups")

    assert [r["id"] for r in roles] == ["role-ga"]
