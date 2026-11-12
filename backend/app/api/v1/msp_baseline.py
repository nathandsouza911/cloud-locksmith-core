from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies.current_user import get_current_tenant, require_write_access
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.services.baseline_service import (
    ensure_default_baseline_template,
    list_baseline_templates,
    save_baseline_template,
)


router = APIRouter()


class CreateBaselineRequest(BaseModel):
    baseline_name: str
    controls: list[str] = Field(default_factory=list)


class BaselineTemplateResponse(BaseModel):
    id: str
    baseline_name: str
    controls: list[str] = Field(default_factory=list)


def _serialize_template(template) -> BaselineTemplateResponse:
    return BaselineTemplateResponse(
        id=str(template.id),
        baseline_name=template.baseline_name,
        controls=template.controls or [],
    )


@router.post("/baseline/templates", response_model=BaselineTemplateResponse)
async def create_baseline_template(
    payload: CreateBaselineRequest,
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    baseline = await save_baseline_template(
        db,
        organization_id=current_tenant.organization_id,
        baseline_name=payload.baseline_name,
        controls=payload.controls,
    )
    return _serialize_template(baseline)


@router.get("/baseline/templates", response_model=list[BaselineTemplateResponse])
async def get_baseline_templates(
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    await ensure_default_baseline_template(db, current_tenant.organization_id)
    templates = await list_baseline_templates(db, current_tenant.organization_id)
    return [_serialize_template(template) for template in templates]


@router.post("/msp/baseline", response_model=BaselineTemplateResponse)
async def create_baseline(
    payload: CreateBaselineRequest,
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    baseline = await save_baseline_template(
        db,
        organization_id=current_tenant.organization_id,
        baseline_name=payload.baseline_name,
        controls=payload.controls,
    )
    return _serialize_template(baseline)
