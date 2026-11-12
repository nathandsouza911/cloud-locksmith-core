from __future__ import annotations

from urllib.parse import quote

from sqlalchemy.orm import Session

from app.db.models.managed_rollout_group import ManagedRolloutGroup


class RolloutGroupOwnershipError(RuntimeError):
    pass


def _rollout_group_name(control_id: str) -> str:
    return f"CLX-{control_id}-ROLLOUT"


def _mail_nickname(control_id: str) -> str:
    nickname = f"clx-{control_id.lower().replace('_', '-')}-rollout"
    return nickname[:64]


def assert_group_is_managed(
    db: Session,
    *,
    tenant_id: str,
    graph_group_id: str,
    control_id: str,
) -> ManagedRolloutGroup:
    """
    Raises RolloutGroupOwnershipError if the group is not DB-tracked as
    Cloud Locksmith-managed for this tenant and control.
    """
    record = (
        db.query(ManagedRolloutGroup)
        .filter(
            ManagedRolloutGroup.tenant_id == tenant_id,
            ManagedRolloutGroup.graph_group_id == graph_group_id,
            ManagedRolloutGroup.control_id == control_id,
            ManagedRolloutGroup.managed.is_(True),
        )
        .one_or_none()
    )
    if record is None:
        raise RolloutGroupOwnershipError(
            f"Group {graph_group_id!r} for control {control_id!r} is not owned by Cloud Locksmith"
            f" in tenant {tenant_id!r}. Refusing to mutate."
        )
    return record


async def create_rollout_group(
    graph_client,
    tenant,
    control_id: str,
    *,
    db: Session,
) -> dict:
    """
    Create (or verify ownership of) the CLX rollout group for this control.

    - If Graph has no matching group: create it, register in DB.
    - If Graph has a matching group AND DB has an ownership record: return it.
    - If Graph has a matching group but NO DB record: FAIL CLOSED.
    """
    display_name = _rollout_group_name(control_id)
    escaped_name = display_name.replace("'", "''")
    payload = await graph_client.get(
        "/groups?$filter=" + quote(f"displayName eq '{escaped_name}'", safe="=$' ") + "&$select=id,displayName"
    )
    values = payload.get("value", []) if isinstance(payload, dict) else []
    for group in values:
        if not (isinstance(group, dict) and group.get("id")):
            continue
        # Graph has a group with this name — verify we own it.
        existing_record = (
            db.query(ManagedRolloutGroup)
            .filter(
                ManagedRolloutGroup.tenant_id == str(tenant.id),
                ManagedRolloutGroup.graph_group_id == group["id"],
                ManagedRolloutGroup.control_id == control_id,
                ManagedRolloutGroup.managed.is_(True),
            )
            .one_or_none()
        )
        if existing_record is None:
            raise RolloutGroupOwnershipError(
                f"Group '{display_name}' (id={group['id']}) already exists in tenant"
                f" {tenant.id} but is not owned by Cloud Locksmith. Refusing to adopt."
            )
        return group

    # Group does not exist in Graph — create it and register ownership.
    new_group = await graph_client.post(
        "/groups",
        {
            "displayName": display_name,
            "mailEnabled": False,
            "mailNickname": _mail_nickname(control_id),
            "securityEnabled": True,
        },
    )
    group_id = new_group.get("id") if isinstance(new_group, dict) else None
    if not isinstance(group_id, str) or not group_id:
        raise RolloutGroupOwnershipError(
            f"Graph did not return a group id when creating rollout group for {control_id!r}"
        )

    record = ManagedRolloutGroup(
        tenant_id=str(tenant.id),
        graph_group_id=group_id,
        control_id=control_id,
        managed=True,
    )
    db.add(record)
    db.flush()
    return new_group


async def add_users_to_group(
    graph_client,
    group_id: str,
    user_ids: list[str],
    *,
    db: Session,
    tenant_id: str,
    control_id: str,
) -> list[str]:
    """Add users only to a Cloud Locksmith-owned rollout group."""
    assert_group_is_managed(db, tenant_id=tenant_id, graph_group_id=group_id, control_id=control_id)
    added_user_ids: list[str] = []
    for user_id in user_ids:
        if not isinstance(user_id, str) or not user_id:
            continue
        await graph_client.post(
            f"/groups/{group_id}/members/$ref",
            {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"},
        )
        added_user_ids.append(user_id)
    return added_user_ids


async def remove_users_from_group(
    graph_client,
    group_id: str,
    user_ids: list[str],
    *,
    db: Session,
    tenant_id: str,
    control_id: str,
) -> list[str]:
    """Remove users only from a Cloud Locksmith-owned rollout group."""
    assert_group_is_managed(db, tenant_id=tenant_id, graph_group_id=group_id, control_id=control_id)
    removed_user_ids: list[str] = []
    for user_id in user_ids:
        if not isinstance(user_id, str) or not user_id:
            continue
        await graph_client.delete(f"/groups/{group_id}/members/{user_id}/$ref")
        removed_user_ids.append(user_id)
    return removed_user_ids


async def get_group_members(graph_client, group_id: str) -> list[str]:
    """Paginate-safe group member fetch."""
    results: list[str] = []
    path: str | None = f"/groups/{group_id}/members?$select=id"
    while path:
        payload = await graph_client.get(path)
        if not isinstance(payload, dict):
            break
        values = payload.get("value", [])
        for member in values:
            if (
                isinstance(member, dict)
                and member.get("@odata.type") in (None, "#microsoft.graph.user")
                and isinstance(member.get("id"), str)
                and member.get("id")
            ):
                results.append(member["id"])
        path = payload.get("@odata.nextLink")
    return results
