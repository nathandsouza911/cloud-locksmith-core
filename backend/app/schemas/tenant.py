from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel


class TenantBase(BaseModel):
    tenant_name: Optional[str] = None
    tenant_identifier: str


class TenantCreate(TenantBase):
    pass


class TenantOut(TenantBase):
    id: str
    created_at: Optional[datetime] = None

    # Capability / feature detection flags
    asset_flags: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}
