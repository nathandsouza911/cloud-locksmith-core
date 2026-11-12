"""Capability-map completeness tests.

Every executable control in CONTROL_REGISTRY must have a non-None entry in the
provider capability map. Missing entries cause evaluate_action() to return
allowed=False / reason="capability_not_defined" before any Graph call is made,
blocking the control permanently as POLICY_RESTRICTION.

These tests are the safety net for that invariant. They also verify that the
four controls that were absent — IDENTITY_BREAK_GLASS_ACCOUNT,
IDENTITY_GUEST_INVITES_OPEN, IDENTITY_USER_CONSENT_POLICY,
CA_BREAK_GLASS_EXCLUSION — are now correctly registered and that
evaluate_action returns allowed=True for each, identical to the working CA path.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services.control_enforcement_service import evaluate_action
from app.services.identity_providers.base import (
    normalize_control_capability_id,
)
from app.services.identity_providers.microsoft import MicrosoftIdentityProviderAdapter
from app.services.remediation.control_registry import CONTROL_REGISTRY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _adapter():
    """Return an adapter instance without a real DB/tenant."""
    return MicrosoftIdentityProviderAdapter(db=None, tenant=None)


def _capability_map():
    return _adapter().get_control_capabilities()


def _make_tenant_and_db():
    tenant = SimpleNamespace(id="tenant-1", organization=None)
    db = SimpleNamespace()
    return tenant, db


# ---------------------------------------------------------------------------
# 1. Capability lookup: the four previously-missing controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "control_id",
    [
        "IDENTITY_BREAK_GLASS_ACCOUNT",
        "IDENTITY_GUEST_INVITES_OPEN",
        "IDENTITY_USER_CONSENT_POLICY",
        "CA_BREAK_GLASS_EXCLUSION",
    ],
)
def test_previously_missing_control_has_capability_entry(control_id):
    caps = _capability_map()
    normalized = normalize_control_capability_id(control_id)
    assert normalized in caps, (
        f"{control_id} (normalized: {normalized}) is not in the capability map. "
        "evaluate_action will return capability_not_defined and block execution."
    )
    assert isinstance(caps[normalized], dict), f"Capability entry for {control_id} is not a dict."


@pytest.mark.parametrize(
    "control_id",
    [
        "IDENTITY_BREAK_GLASS_ACCOUNT",
        "IDENTITY_GUEST_INVITES_OPEN",
        "IDENTITY_USER_CONSENT_POLICY",
        "CA_BREAK_GLASS_EXCLUSION",
    ],
)
def test_previously_missing_control_has_remediate_true(control_id):
    caps = _capability_map()
    normalized = normalize_control_capability_id(control_id)
    cap = caps.get(normalized, {})
    assert cap.get("remediate") is True, f"{control_id}: remediate must be True for the control to be executable"


# ---------------------------------------------------------------------------
# 2. evaluate_action returns allowed=True (not capability_not_defined)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "control_id",
    [
        "IDENTITY_BREAK_GLASS_ACCOUNT",
        "IDENTITY_GUEST_INVITES_OPEN",
        "IDENTITY_USER_CONSENT_POLICY",
        "CA_BREAK_GLASS_EXCLUSION",
    ],
)
def test_evaluate_action_returns_allowed_for_previously_missing_controls(control_id):
    tenant, db = _make_tenant_and_db()
    adapter = _adapter()

    with patch(
        "app.services.control_enforcement_service.get_identity_provider_adapter",
        return_value=adapter,
    ):
        result = asyncio.run(evaluate_action(tenant, control_id, "execute", db=db))

    assert result.get("reason") != "capability_not_defined", (
        f"{control_id}: evaluate_action returned capability_not_defined — "
        "control is still missing from the capability map."
    )
    assert result.get("allowed") is True, (
        f"{control_id}: evaluate_action returned allowed=False (reason={result.get('reason')}). "
        "Fix Now will be blocked before reaching Graph."
    )


# ---------------------------------------------------------------------------
# 3. No executable control hits capability_not_defined
# ---------------------------------------------------------------------------


def test_no_executable_control_is_missing_from_capability_map():
    """Exhaustive check: every is_executable=True control in CONTROL_REGISTRY
    must resolve to a dict in the Microsoft adapter capability map."""
    caps = _capability_map()
    missing = []
    for ctrl_id, ctrl in CONTROL_REGISTRY.items():
        if not ctrl.get("is_executable"):
            continue
        normalized = normalize_control_capability_id(ctrl_id)
        if not isinstance(caps.get(normalized), dict):
            missing.append(f"{ctrl_id} (normalized: {normalized})")

    assert missing == [], (
        "Executable controls missing from the capability map — "
        "evaluate_action will block them with POLICY_RESTRICTION:\n" + "\n".join(f"  - {m}" for m in missing)
    )


# ---------------------------------------------------------------------------
# 4. Existing CA license-gating behavior is unchanged
# ---------------------------------------------------------------------------


def test_ca_controls_still_resolve_via_tenant_conditional_access_policy_alias():
    """The CA control aliases must still map to TENANT_CONDITIONAL_ACCESS_POLICY
    (not directly registered as individual keys) so the CA license gate path
    in api/v1/control.py is unaffected."""
    ca_controls = [
        "CA_MFA_ALL_USERS",
        "CA_MFA_ADMINS",
        "CA_LEGACY_AUTH_BLOCK",
        "CA_DEVICE_CODE_FLOW_BLOCK",
        "CA_AUTHENTICATION_TRANSFER_BLOCK",
        "CA_GUEST_MFA",
    ]
    for ctrl_id in ca_controls:
        normalized = normalize_control_capability_id(ctrl_id)
        assert normalized == "TENANT_CONDITIONAL_ACCESS_POLICY", (
            f"{ctrl_id} must still alias to TENANT_CONDITIONAL_ACCESS_POLICY, " f"got: {normalized}"
        )


def test_tenant_conditional_access_policy_capability_entry_unchanged():
    caps = _capability_map()
    cap = caps.get("TENANT_CONDITIONAL_ACCESS_POLICY")
    assert isinstance(cap, dict), "TENANT_CONDITIONAL_ACCESS_POLICY missing"
    assert cap["remediate"] is True
    assert cap["auto_remediate"] is False
    assert cap["requires_approval"] is True


# ---------------------------------------------------------------------------
# 5. Completeness summary — full executable control list
# ---------------------------------------------------------------------------


def test_print_all_executable_controls_with_capability_status():
    """Non-failing inventory test: prints the complete matrix for human review.
    Always passes; failures show up in the parametrized tests above."""
    caps = _capability_map()
    rows = []
    for ctrl_id in sorted(CONTROL_REGISTRY):
        ctrl = CONTROL_REGISTRY[ctrl_id]
        is_exec = ctrl.get("is_executable", False)
        normalized = normalize_control_capability_id(ctrl_id)
        in_map = isinstance(caps.get(normalized), dict)
        alias_used = ctrl_id != normalized
        rows.append(
            {
                "control_id": ctrl_id,
                "executable": is_exec,
                "normalized": normalized,
                "alias_used": alias_used,
                "in_map": in_map,
            }
        )

    print("\n=== Executable Control Capability Map Coverage ===")
    for r in rows:
        if not r["executable"]:
            continue
        status = "OK" if r["in_map"] else "MISSING"
        alias_note = f" (alias->{r['normalized']})" if r["alias_used"] else ""
        print(f"  [{status}] {r['control_id']}{alias_note}")
