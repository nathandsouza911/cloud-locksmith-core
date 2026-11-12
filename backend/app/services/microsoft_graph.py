import httpx


class MicrosoftGraphClient:
    def __init__(self, access_token: str, api_version: str = "v1.0"):
        self.base_url = f"https://graph.microsoft.com/{api_version}"
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    async def get(self, path: str) -> dict:
        return await self._request("GET", path)

    async def get_all(self, path: str) -> list:
        """Fetch all pages of a collection, following @odata.nextLink."""
        results = []
        # First page: path is relative; subsequent pages: nextLink is absolute.
        current: str | None = path
        is_first = True
        async with httpx.AsyncClient(timeout=30) as client:
            while current:
                url = f"{self.base_url}{current}" if is_first else current
                is_first = False
                resp = await client.get(url, headers=self.headers)
                if resp.status_code >= 400:
                    raise Exception(
                        f"Graph GET failed\nEndpoint: {url}\n" f"Status: {resp.status_code}\nResponse: {resp.text}"
                    )
                data = resp.json() if resp.content else {}
                results.extend(data.get("value", []))
                current = data.get("@odata.nextLink")
        return results

    async def post(self, path: str, payload: dict) -> dict:
        return await self._request("POST", path, payload)

    async def _request(self, method: str, path: str, payload: dict | None = None):
        url = f"{self.base_url}{path}"

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(
                method,
                url,
                headers=self.headers,
                json=payload,
            )

        if resp.status_code >= 400:
            raise Exception(
                "Graph WRITE failed\n" f"Endpoint: {path}\n" f"Status: {resp.status_code}\n" f"Response: {resp.text}"
            )

        if resp.content:
            return resp.json()

        return {}
