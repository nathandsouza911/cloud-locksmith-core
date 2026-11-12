import asyncio
from unittest.mock import AsyncMock, MagicMock

from app.db.models.managed_rollout_group import ManagedRolloutGroup
from app.services.rollout_group_service import (
    RolloutGroupOwnershipError,
    assert_group_is_managed,
    create_rollout_group,
    get_group_members,
)


def test_managed_rollout_group_model_fields():
    group = ManagedRolloutGroup(
        tenant_id="tenant-abc",
        graph_group_id="graph-group-xyz",
        control_id="CA_MFA_ADMINS",
    )
    assert group.tenant_id == "tenant-abc"
    assert group.graph_group_id == "graph-group-xyz"
    assert group.control_id == "CA_MFA_ADMINS"
    assert group.managed is True


def make_db(managed_group=None):
    db = MagicMock()
    q = MagicMock()
    db.query.return_value = q
    q.filter.return_value = q
    q.one_or_none.return_value = managed_group
    return db


def test_create_rollout_group_registers_in_db():
    graph_client = MagicMock()
    graph_client.get = AsyncMock(return_value={"value": []})
    graph_client.post = AsyncMock(return_value={"id": "new-group-id"})
    db = make_db()
    tenant = MagicMock()
    tenant.id = "t1"

    result = asyncio.run(create_rollout_group(graph_client, tenant, "CA_MFA_ADMINS", db=db))

    assert result["id"] == "new-group-id"
    db.add.assert_called_once()
    added = db.add.call_args[0][0]
    assert isinstance(added, ManagedRolloutGroup)
    assert added.tenant_id == "t1"
    assert added.graph_group_id == "new-group-id"
    assert added.control_id == "CA_MFA_ADMINS"
    assert added.managed is True


def test_create_rollout_group_existing_graph_group_requires_db_record():
    """If Graph has a same-named group but no DB record, raise ownership error."""
    graph_client = MagicMock()
    graph_client.get = AsyncMock(
        return_value={"value": [{"id": "stale-id", "displayName": "CLX-CA_MFA_ADMINS-ROLLOUT"}]}
    )
    db = make_db(managed_group=None)  # no DB record
    tenant = MagicMock()
    tenant.id = "t1"

    try:
        asyncio.run(create_rollout_group(graph_client, tenant, "CA_MFA_ADMINS", db=db))
        assert False, "Expected RolloutGroupOwnershipError"
    except RolloutGroupOwnershipError as exc:
        assert "Refusing to adopt" in str(exc)


def test_assert_group_is_managed_rejects_unknown_group():
    db = make_db(managed_group=None)
    try:
        assert_group_is_managed(db, tenant_id="t1", graph_group_id="arbitrary-id", control_id="CA_MFA_ADMINS")
        assert False, "Expected RolloutGroupOwnershipError"
    except RolloutGroupOwnershipError:
        pass


def test_get_group_members_paginates():
    """get_group_members follows @odata.nextLink."""
    graph_client = MagicMock()
    graph_client.get = AsyncMock(
        side_effect=[
            {
                "value": [{"id": "u1", "@odata.type": "#microsoft.graph.user"}],
                "@odata.nextLink": "https://graph/next",
            },
            {"value": [{"id": "u2", "@odata.type": "#microsoft.graph.user"}]},
        ]
    )

    members = asyncio.run(get_group_members(graph_client, "group-id"))
    assert members == ["u1", "u2"]
    assert graph_client.get.call_count == 2


def test_control_apply_request_does_not_forward_target_group_id():
    """
    target_group_id from the frontend must not be forwarded to apply_control_dispatch
    or apply_control. Verify by checking both signatures.
    """
    import inspect
    from app.services.ca_policy_engine import apply_control_dispatch, apply_control

    sig_dispatch = inspect.signature(apply_control_dispatch)
    sig_apply = inspect.signature(apply_control)
    assert "target_group_id" not in sig_dispatch.parameters, "apply_control_dispatch must not accept target_group_id"
    assert (
        "target_group_id" not in sig_apply.parameters
    ), "apply_control (locked wrapper) must not accept target_group_id"


def test_create_rollout_group_returns_existing_when_owned():
    """If Graph has the group AND DB record exists, return the existing group without re-registering."""
    existing_group = {"id": "owned-group-id", "displayName": "CLX-CA_MFA_ADMINS-ROLLOUT"}
    graph_client = MagicMock()
    graph_client.get = AsyncMock(return_value={"value": [existing_group]})

    # DB has an ownership record for this group
    existing_record = MagicMock(spec=ManagedRolloutGroup)
    existing_record.tenant_id = "t1"
    existing_record.graph_group_id = "owned-group-id"
    existing_record.control_id = "CA_MFA_ADMINS"
    db = make_db(managed_group=existing_record)

    tenant = MagicMock()
    tenant.id = "t1"

    result = asyncio.run(create_rollout_group(graph_client, tenant, "CA_MFA_ADMINS", db=db))

    assert result["id"] == "owned-group-id"
    # Must NOT call db.add again — group already exists
    db.add.assert_not_called()
    # Must NOT create a new group in Graph
    graph_client.post.assert_not_called()
