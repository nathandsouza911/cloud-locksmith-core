from app.services.graph_client import graph_get


async def fetch_role_members(db, tenant, role_id: str) -> list[dict]:
    response = await graph_get(
        db,
        tenant,
        f"/directoryRoles/{role_id}/members",
    )
    return response.get("value", [])
