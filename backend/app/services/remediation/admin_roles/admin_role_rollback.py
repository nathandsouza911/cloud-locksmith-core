from app.services.graph_client import GraphAPIError
from app.services.identity_providers import get_identity_provider_adapter


async def rollback_admin_roles(db, tenant, snapshot_state: dict):
    """
    Restore admin roles removed during remediation.
    Uses directoryRole instance IDs captured at snapshot time.
    """
    if tenant is None:
        raise RuntimeError("Rollback called without tenant context")

    user_id = snapshot_state["user_id"]
    roles = snapshot_state.get("roles", [])
    restored = []
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)

    for role in roles:
        role_id = role.get("role_id")
        if not role_id:
            continue

        try:
            await adapter.add_directory_role_member(role_id, user_id)
        except GraphAPIError as exc:
            body = (exc.response_body or "").lower()
            if exc.status_code in {400, 409} and (
                "already exist" in body
                or "object references already exist" in body
                or "one or more added object references already exist" in body
            ):
                restored.append(role_id)
                continue
            raise
        restored.append(role_id)

    return {"restored_roles": restored}
