from __future__ import annotations

from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.tenant import Tenant
from app.services.ca_policy_engine import _default_rollout_phase, build_policy_document
from app.simulation.constants import SIMULATION_ALLOWED_CONTROLS
from app.simulation.engine import SimulationEngine
from app.simulation.models import SimulationRunResponse
from app.simulation.tenant_reader import read_tenant_identity

_SIMULATED_MODE = "enforced"  # show the effect once enforced, not the report-only first step


def check_simulation_control(control_id: object) -> str:
    if not isinstance(control_id, str) or not control_id:
        raise ValueError("control_id is required")
    if control_id not in SIMULATION_ALLOWED_CONTROLS:
        raise ValueError(
            f"Control '{control_id}' is not supported by the simulation engine. "
            f"Simulation is only available for: {sorted(SIMULATION_ALLOWED_CONTROLS)}"
        )
    return control_id


class SimulationService:
    """Simulate Fix: the policy Apply would send, evaluated against the session tenant's
    users, groups, roles and existing policies, all read server-side."""

    def __init__(self, engine: SimulationEngine | None = None) -> None:
        self.engine = engine or SimulationEngine()

    async def run_for_tenant(self, *, db, tenant: Tenant, control_id: str) -> SimulationRunResponse:
        control_id = check_simulation_control(control_id)
        identity = await read_tenant_identity(db, tenant)
        break_glass_ids = [
            row.user_external_id
            for row in db.query(BreakGlassAccount).filter(BreakGlassAccount.tenant_id == tenant.id).all()
        ]
        proposed = build_policy_document(
            control_id, _SIMULATED_MODE, _default_rollout_phase(control_id), break_glass_ids
        )
        proposed["id"] = f"sim-{control_id}"

        result = self.engine.run_simulation(
            tenant_snapshot={
                "policies": identity.policies,
                "users": identity.user_ids(),
                "groups": identity.group_map(),
                "roles": identity.role_map(),
                "guests": sorted(identity.guest_ids()),
            },
            proposed_change=proposed,
            # Admin impact is reported by role name.
            role_mapping={role["name"]: list(role["member_ids"]) for role in identity.roles.values()},
            # Security defaults already require MFA for every user (as on the CA Coverage page).
            baseline_floor="MFA_REQUIRED" if identity.security_defaults_enabled else None,
        )
        result["security_defaults_enabled"] = identity.security_defaults_enabled
        return SimulationRunResponse.model_validate(result)
