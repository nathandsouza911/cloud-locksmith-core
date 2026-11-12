"""
V1 hardening: SimulationService must reject control IDs that the
simulation engine cannot meaningfully model.

Allowed:  CA_MFA_ALL_USERS, CA_MFA_ADMINS
Rejected: everything else — fail closed.
"""

import pytest

from app.simulation.service import SimulationService
from app.simulation.constants import SIMULATION_ALLOWED_CONTROLS


# ── helpers ──────────────────────────────────────────────────────────────────


def _minimal_snapshot():
    return {
        "users": ["user-1", "user-2"],
        "groups": {},
        "roles": {},
    }


def _mfa_proposed_change(control_id: str) -> dict:
    return {
        "id": "sim-test-001",
        "control_id": control_id,
        "conditions": {
            "users": {"includeUsers": ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
        "state": "enabled",
    }


def _run(control_id: str):
    service = SimulationService()
    request_data = {
        "tenant_snapshot": _minimal_snapshot(),
        "proposed_change": _mfa_proposed_change(control_id),
        "role_mapping": {},
    }
    from app.simulation.models import SimulationRunRequest

    request = SimulationRunRequest.model_validate(request_data)
    return service.run_simulation(request=request, tenant=None)


# ── allowed controls ──────────────────────────────────────────────────────────


class TestAllowedControls:
    def test_ca_mfa_all_users_is_allowed(self):
        result = _run("CA_MFA_ALL_USERS")
        assert result.status == "completed"

    def test_ca_mfa_admins_is_allowed(self):
        result = _run("CA_MFA_ADMINS")
        assert result.status == "completed"


# ── rejected controls ─────────────────────────────────────────────────────────


class TestRejectedControls:
    @pytest.mark.parametrize(
        "control_id",
        [
            "CA_LEGACY_AUTH_BLOCK",
            "CA_DEVICE_CODE_FLOW_BLOCK",
            "CA_AUTHENTICATION_TRANSFER_BLOCK",
            "CA_BREAK_GLASS_EXCLUSION",
            "CA_GUEST_MFA",
            "IDENTITY_USER_CONSENT_ALLOWED",
            "IDENTITY_BREAK_GLASS_ACCOUNT",
            "IDENTITY_LEGACY_AUTH_ALLOWED",
            "IDENTITY_MFA_NOT_ENFORCED",
            "IDENTITY_PASSWORD_PROTECTION_WEAK",
            "IDENTITY_OVERPRIVILEGED_USER",
            "IDENTITY_OVERPRIVILEGED_ADMIN",
        ],
    )
    def test_unsupported_control_is_rejected(self, control_id: str):
        with pytest.raises(ValueError, match="not supported"):
            _run(control_id)

    def test_missing_control_id_is_rejected(self):
        service = SimulationService()
        from app.simulation.models import SimulationRunRequest

        request = SimulationRunRequest.model_validate(
            {
                "tenant_snapshot": _minimal_snapshot(),
                "proposed_change": {
                    "id": "sim-no-control",
                    "conditions": {"users": {"includeUsers": ["All"]}},
                    "grantControls": {"builtInControls": ["mfa"]},
                    "state": "enabled",
                    # no control_id
                },
                "role_mapping": {},
            }
        )
        with pytest.raises(ValueError, match="control_id"):
            service.run_simulation(request=request, tenant=None)

    def test_empty_string_control_id_is_rejected(self):
        with pytest.raises(ValueError):
            _run("")


# ── constants surface ─────────────────────────────────────────────────────────


class TestAllowedControlsConstant:
    def test_allowed_set_contains_ca_mfa_all_users(self):
        assert "CA_MFA_ALL_USERS" in SIMULATION_ALLOWED_CONTROLS

    def test_allowed_set_contains_ca_mfa_admins(self):
        assert "CA_MFA_ADMINS" in SIMULATION_ALLOWED_CONTROLS

    def test_allowed_set_does_not_contain_block_controls(self):
        assert "CA_LEGACY_AUTH_BLOCK" not in SIMULATION_ALLOWED_CONTROLS
        assert "CA_DEVICE_CODE_FLOW_BLOCK" not in SIMULATION_ALLOWED_CONTROLS
        assert "CA_AUTHENTICATION_TRANSFER_BLOCK" not in SIMULATION_ALLOWED_CONTROLS

    def test_allowed_set_does_not_contain_guest_mfa(self):
        assert "CA_GUEST_MFA" not in SIMULATION_ALLOWED_CONTROLS

    def test_allowed_set_does_not_contain_identity_controls(self):
        assert "IDENTITY_BREAK_GLASS_ACCOUNT" not in SIMULATION_ALLOWED_CONTROLS
        assert "IDENTITY_MFA_NOT_ENFORCED" not in SIMULATION_ALLOWED_CONTROLS
