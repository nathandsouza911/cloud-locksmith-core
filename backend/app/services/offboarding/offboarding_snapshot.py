from app.services.graph_client import fetch_user_memberof_directory_roles, graph_get


async def snapshot_user_state(db, tenant, user_id: str):
    user = await graph_get(db, tenant, f"/users/{user_id}")
    roles = await fetch_user_memberof_directory_roles(db, tenant, user_id)

    return {
        "user_id": user_id,
        "account_enabled": user.get("accountEnabled"),
        "roles": roles,
        "is_global_admin": any(r.get("displayName") == "Global Administrator" for r in roles),
    }
