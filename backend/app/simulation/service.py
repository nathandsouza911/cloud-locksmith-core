from __future__ import annotations

from app.db.models.tenant import Tenant
from app.simulation.constants import SIMULATION_ALLOWED_CONTROLS
from app.simulation.engine import SimulationEngine
from app.simulation.models import SimulationRunRequest, SimulationRunResponse


class SimulationService:
    """Application service facade for simulation requests."""

    def __init__(self, engine: SimulationEngine | None = None) -> None:
        self.engine = engine or SimulationEngine()

    def run_simulation(
        self,
        *,
        request: SimulationRunRequest,
        tenant: Tenant | None = None,
    ) -> SimulationRunResponse:
        tenant_snapshot = request.tenant_snapshot
        proposed_change = request.proposed_change
        role_mapping = request.role_mapping

        if not isinstance(tenant_snapshot, dict) or not isinstance(proposed_change, dict):
            raise ValueError("tenant_snapshot and proposed_change must be objects")
        if "id" not in proposed_change:
            raise ValueError("proposed_change.id is required")
        if not isinstance(role_mapping, dict):
            raise ValueError("role_mapping must be an object")

        control_id = proposed_change.get("control_id")
        if not control_id or not isinstance(control_id, str):
            raise ValueError("proposed_change.control_id is required")
        if control_id not in SIMULATION_ALLOWED_CONTROLS:
            raise ValueError(
                f"Control '{control_id}' is not supported by the simulation engine. "
                f"Simulation is only available for: {sorted(SIMULATION_ALLOWED_CONTROLS)}"
            )

        result = self.engine.run_simulation(
            tenant_snapshot=tenant_snapshot,
            proposed_change=proposed_change,
            role_mapping=role_mapping,
        )

        return SimulationRunResponse.model_validate(result)
