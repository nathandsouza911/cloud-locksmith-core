from app.services.microsoft_graph import MicrosoftGraphClient


async def fetch_current_identity(graph: MicrosoftGraphClient):
    return await graph.get("/me")
