from app.services.graph_client import graph_delete, graph_get_all, graph_post


async def fetch_conditional_access_policies(graph_client):
    return await graph_client.get_all("/identity/conditionalAccess/policies")


async def create_conditional_access_policy(db, tenant, payload: dict):
    return await graph_post(
        db,
        tenant,
        "/identity/conditionalAccess/policies",
        payload,
    )


async def list_conditional_access_policies(db, tenant):
    return await graph_get_all(
        db,
        tenant,
        "/identity/conditionalAccess/policies",
    )


async def delete_conditional_access_policy(db, tenant, policy_id: str):
    return await graph_delete(
        db,
        tenant,
        f"/identity/conditionalAccess/policies/{policy_id}",
    )
