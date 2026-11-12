import httpx
from app.config import settings

TOKEN_URL = f"https://login.microsoftonline.com/{settings.MICROSOFT_TENANT}/oauth2/v2.0/token"


async def get_graph_app_token() -> str:
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(TOKEN_URL, data=data)

    if resp.status_code != 200:
        raise Exception(f"App token failed: {resp.text}")

    token = resp.json()
    return token["access_token"]
