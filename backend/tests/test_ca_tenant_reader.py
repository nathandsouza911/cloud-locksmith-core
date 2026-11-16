"""Graph reader for CA coverage / Simulate Fix: reads everything for the session tenant,
expands groups transitively, keys roles by template ID, and fails closed."""

import pytest

from app.services.graph_client import GraphAPIError
from app.simulation import tenant_reader as tr

pytestmark = pytest.mark.asyncio

G_EXCL = "11111111-1111-4111-8111-111111111111"
G_ROLE = "22222222-2222-4222-8222-222222222222"
G_GONE = "33333333-3333-4333-8333-333333333333"
GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
USER = "#microsoft.graph.user"
GROUP = "#microsoft.graph.group"


def _graph(overrides=None):
    data = {
        tr.CA_POLICIES_PATH: [
            {
                "id": "p1",
                "conditions": {"users": {"includeUsers": ["All"], "excludeGroups": [G_EXCL, G_GONE]}},
            }
        ],
        tr.SECURITY_DEFAULTS_PATH: {"isEnabled": False},
        tr.USERS_PATH: [{"id": "u1", "userType": "Member"}, {"id": "u2", "userType": "Guest"}],
        "/directoryRoles": [{"id": "44444444-4444-4444-8444-444444444444", "displayName": "Global Administrator", "roleTemplateId": GA_TEMPLATE}],
        "/directoryRoles/44444444-4444-4444-8444-444444444444/members?$select=id": [
            {"@odata.type": USER, "id": "u1"},
            {"@odata.type": GROUP, "id": G_ROLE},
        ],
        f"/groups/{G_EXCL}?$select=id,displayName": {"id": G_EXCL, "displayName": "CA exclusions"},
        f"/groups/{G_EXCL}/transitiveMembers?$select=id": [
            {"@odata.type": USER, "id": "u2"},
            {"@odata.type": "#microsoft.graph.device", "id": "dev-1"},
        ],
        f"/groups/{G_ROLE}?$select=id,displayName": {"id": G_ROLE, "displayName": "Admins group"},
        f"/groups/{G_ROLE}/transitiveMembers?$select=id": [{"@odata.type": USER, "id": "u3"}],
    }
    data.update(overrides or {})
    calls = []

    async def graph_get(db, tenant, path):
        calls.append(("get", tenant.id, path))
        if path == f"/groups/{G_GONE}?$select=id,displayName":
            raise GraphAPIError(method="GET", path=path, status_code=404, response_body="", category="not_found")
        value = data[path]
        if isinstance(value, Exception):
            raise value
        return value

    async def graph_get_all(db, tenant, path):
        calls.append(("all", tenant.id, path))
        value = data[path]
        if isinstance(value, Exception):
            raise value
        return value

    return graph_get, graph_get_all, calls


class _Tenant:
    id = "tenant-a"


@pytest.fixture()
def patch_graph(monkeypatch):
    def apply(overrides=None):
        graph_get, graph_get_all, calls = _graph(overrides)
        monkeypatch.setattr(tr, "graph_get", graph_get)
        monkeypatch.setattr(tr, "graph_get_all", graph_get_all)
        return calls

    return apply


async def test_reads_everything_for_the_session_tenant(patch_graph):
    calls = patch_graph()
    identity = await tr.read_tenant_identity(None, _Tenant())

    assert {c[1] for c in calls} == {"tenant-a"}
    # Collections are read with paging.
    assert ("all", "tenant-a", tr.CA_POLICIES_PATH) in calls
    assert ("all", "tenant-a", tr.USERS_PATH) in calls
    assert identity.user_ids() == ["u1", "u2"]
    assert identity.guest_ids() == {"u2"}
    assert identity.security_defaults_enabled is False
    assert identity.groups[G_EXCL] == {"name": "CA exclusions", "member_ids": ["u2"]}
    # A deleted group (404) has no members; it is not a read failure.
    assert identity.groups[G_GONE] == {"name": "(deleted group)", "member_ids": []}
    # Roles are keyed by template ID; members through a group are expanded.
    assert identity.roles[GA_TEMPLATE] == {"name": "Global Administrator", "member_ids": ["u1", "u3"]}


async def test_extra_group_ids_are_read(patch_graph):
    patch_graph()
    identity = await tr.read_tenant_identity(None, _Tenant(), extra_group_ids=[G_ROLE])
    assert identity.groups[G_ROLE]["member_ids"] == ["u3"]


@pytest.mark.parametrize(
    "path",
    [
        "CA_POLICIES_PATH",
        "USERS_PATH",
        "SECURITY_DEFAULTS_PATH",
        "/directoryRoles/44444444-4444-4444-8444-444444444444/members?$select=id",
        f"/groups/{G_EXCL}/transitiveMembers?$select=id",
    ],
)
async def test_any_read_failure_raises(patch_graph, path):
    key = getattr(tr, path, path)
    patch_graph({key: GraphAPIError(method="GET", path=key, status_code=403, response_body="", category="forbidden")})
    with pytest.raises(GraphAPIError):
        await tr.read_tenant_identity(None, _Tenant())


@pytest.mark.parametrize("bad_id", ["../users", G_EXCL + "\n", G_EXCL + "/members"])
async def test_group_id_that_is_not_a_guid_is_refused(patch_graph, bad_id):
    patch_graph({tr.CA_POLICIES_PATH: [{"id": "p", "conditions": {"users": {"includeGroups": [bad_id]}}}]})
    with pytest.raises(ValueError):
        await tr.read_tenant_identity(None, _Tenant())
