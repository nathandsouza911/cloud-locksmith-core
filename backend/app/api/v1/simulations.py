from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models.tenant import Tenant
from app.simulation.models import SimulationRunRequest, SimulationRunResponse
from app.simulation.service import SimulationService


router = APIRouter(
    prefix="/simulations",
    tags=["Simulations"],
)


@router.post("/run", response_model=SimulationRunResponse)
async def run_simulation(
    payload: dict,
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    required_keys = {"tenant_snapshot", "proposed_change", "role_mapping"}
    if not isinstance(payload, dict) or not required_keys.issubset(payload):
        raise HTTPException(
            status_code=400,
            detail="tenant_snapshot, proposed_change, and role_mapping are required",
        )

    try:
        request = SimulationRunRequest.model_validate(payload)
        service = SimulationService()
        return service.run_simulation(request=request, tenant=current_tenant)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
