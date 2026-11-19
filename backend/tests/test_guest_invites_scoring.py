"""Review R2-15: guest-invite scoring uses Graph's real allowInvitesFrom values.

Graph values: none, adminsAndGuestInviters, adminsGuestInvitersAndAllMembers,
everyone. "none" (the strictest) was scored FAIL, and the passing set held
"adminsOnly", which Graph never returns.
"""

import pytest

from app.services.detection.identity_risky_defaults_detector import evaluate_identity_default_controls


def _guest_result(allow_invites_from):
    results = evaluate_identity_default_controls({"authorization_policy": {"allowInvitesFrom": allow_invites_from}})
    return next(r for r in results if r["control_id"] == "IDENTITY_GUEST_INVITES_OPEN")


@pytest.mark.parametrize("value", ["none", "adminsAndGuestInviters"])
def test_restricted_settings_pass(value):
    assert _guest_result(value)["passed"] is True


@pytest.mark.parametrize("value", ["adminsGuestInvitersAndAllMembers", "everyone", "adminsOnly"])
def test_open_or_unknown_settings_fail(value):
    assert _guest_result(value)["passed"] is False
