from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.graph_client import GraphAPIError
from app.simulation.models import SimulationRunRequest, SimulationRunResponse
from app.simulation.service import SimulationService, check_simulation_control


router = APIRouter(
    prefix="/simulations",
    tags=["Simulations"],
)


@router.post("/run", response_model=SimulationRunResponse)
async def run_simulation(
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    # Only {"control_id"} is accepted: users, groups, roles and policies are read from
    # Graph for the session tenant, never taken from the request.
    try:
        request = SimulationRunRequest.model_validate(payload)
        check_simulation_control(request.control_id)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        return await SimulationService().run_for_tenant(
            db=db, tenant=current_tenant, control_id=request.control_id
        )
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail={"code": "GRAPH_READ_FAILED", "category": exc.category}) from exc
