"""Simulate Fix builds the same policy document Apply sends (ROADMAP 3.1).

build_policy keeps its break-glass gate (a mutation must never lock admins out);
build_policy_document is the gate-free builder it uses, for read-only simulation.
"""

import pytest

from app.services.ca_policy_engine import ControlEngineError, build_policy, build_policy_document

BG = ["bg-1"]


@pytest.mark.parametrize("control_id,phase", [("CA_MFA_ALL_USERS", "full"), ("CA_MFA_ADMINS", "admins")])
def test_document_is_the_policy_apply_sends(control_id, phase):
    assert build_policy_document(control_id, "enforced", phase, BG) == build_policy(control_id, "enforced", phase, BG)


def test_document_without_break_glass_is_allowed_for_simulation():
    doc = build_policy_document("CA_MFA_ALL_USERS", "enforced", "full", [])
    assert doc["conditions"]["users"]["includeUsers"] == ["All"]
    assert doc["conditions"]["users"]["excludeUsers"] == []
    assert doc["state"] == "enabled"


def test_build_policy_still_requires_break_glass():
    with pytest.raises(ControlEngineError, match="Break-glass"):
        build_policy("CA_MFA_ALL_USERS", "enforced", "full", [])
