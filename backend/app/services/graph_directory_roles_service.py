from app.services.graph_client import graph_get_all


async def fetch_directory_roles(db, tenant) -> list[dict]:
    return await graph_get_all(db, tenant, "/directoryRoles")
