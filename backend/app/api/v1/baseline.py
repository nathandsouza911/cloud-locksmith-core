from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.api.dependencies.current_user import get_current_tenant, require_write_access
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.baseline.baseline_enforcement_service import (
    apply_baseline_configuration,
)

router = APIRouter()


class ApplyBaselineRequest(BaseModel):
    baseline_name: str
    controls: list[str] = Field(default_factory=list)


@router.post("/baseline/apply")
def apply_baseline(
    payload: ApplyBaselineRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    # SECURITY: organization_id is derived from the authenticated tenant, never
    # taken from client input. Trusting a client-supplied org id would allow a
    # caller to overwrite another organization's baseline (cross-tenant IDOR).
    return apply_baseline_configuration(
        db,
        organization_id=str(current_tenant.organization_id),
        baseline_name=payload.baseline_name,
        controls=payload.controls,
    )
