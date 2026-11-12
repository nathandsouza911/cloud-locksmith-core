from app.api.v1.control import ControlApplyRequest


def test_control_apply_request_defaults_mode_to_audit():
    payload = ControlApplyRequest(control_id="CA_MFA_ADMINS")
    assert payload.mode == "audit"


def test_control_apply_request_requires_explicit_mode():
    payload = ControlApplyRequest(control_id="CA_MFA_ADMINS", mode="enforced")

    assert payload.mode == "enforced"
