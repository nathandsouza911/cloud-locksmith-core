from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from app.services.graph.tenant_graph_context import TenantGraphContext

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com"


async def _fetch_paginated(access_token: str, url: str) -> list[dict]:
    headers = {"Authorization": f"Bearer {access_token}"}
    results: list[dict] = []
    async with httpx.AsyncClient(timeout=30) as client:
        while url:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 403:
                logger.warning("graph_fetcher_403 url=%s", url)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
    return results


async def _safe_fetch_paginated(access_token: str, url: str, field_name: str) -> list[dict] | None:
    try:
        return await _fetch_paginated(access_token, url)
    except Exception:
        logger.warning("graph_fetcher_field_failed field=%s url=%s", field_name, url, exc_info=True)
        return None


class GraphFetcher:
    async def build_context(
        self,
        tenant_id: str,
        access_token: str,
        *,
        break_glass_accounts: list[str] | None = None,
        security_defaults_enabled: bool | None = None,
    ) -> TenantGraphContext:
        ca_url = f"{_GRAPH_BASE}/beta/identity/conditionalAccess/policies"

        ca_policies = await _safe_fetch_paginated(access_token, ca_url, "conditional_access_policies")

        logger.info(
            "graph_fetcher_context_built tenant_id=%s ca_policies=%s",
            tenant_id,
            len(ca_policies) if ca_policies is not None else "FAILED",
        )

        return TenantGraphContext(
            tenant_id=tenant_id,
            fetched_at=datetime.now(tz=timezone.utc),
            conditional_access_policies=ca_policies,
            break_glass_accounts=break_glass_accounts or [],
            security_defaults_enabled=security_defaults_enabled,
        )
