from app.services.graph_client import graph_get_all


async def fetch_role_members(db, tenant, role_id: str) -> list[dict]:
    # Every page: a role holder on a later page must never be missed.
    return await graph_get_all(db, tenant, f"/directoryRoles/{role_id}/members")
