from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TenantGraphContext:
    tenant_id: str
    fetched_at: datetime

    # CA checks (Phase 2)
    conditional_access_policies: list[dict] | None  # None = fetch failed

    # Injected from DB (not fetched from Graph)
    break_glass_accounts: list[str] = field(default_factory=list)  # object IDs

    # Injected by the caller (already fetched once earlier in the scan) rather
    # than re-fetched here. True/False = known state, None = unknown/unfetched.
    security_defaults_enabled: bool | None = None
