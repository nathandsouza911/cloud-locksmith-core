from app.services.identity_providers.base import build_control_capability


def test_auto_remediate_produces_auto_mode():
    cap = build_control_capability(
        detect=True,
        remediate=True,
        auto_remediate=True,
        requires_approval=False,
        notes="auto note",
    )
    assert cap["mode"] == "auto"
    assert cap["allowed"] is True
    assert cap["reason"] == "auto_remediate"
    # Existing fields preserved
    assert cap["detect"] is True
    assert cap["auto_remediate"] is True
    assert cap["notes"] == "auto note"


def test_manual_with_approval_produces_manual_mode():
    cap = build_control_capability(
        detect=True,
        remediate=True,
        auto_remediate=False,
        requires_approval=True,
        notes="guarded workflow note",
    )
    assert cap["mode"] == "manual"
    assert cap["allowed"] is True
    assert cap["reason"] == "requires_approval"


def test_no_remediate_produces_blocked_mode():
    cap = build_control_capability(
        detect=True,
        remediate=False,
        auto_remediate=False,
        requires_approval=False,
        notes="",
    )
    assert cap["mode"] == "blocked"
    assert cap["allowed"] is False
    assert cap["reason"] == "capability_unavailable"


def test_manual_without_approval_produces_manual_remediate_reason():
    cap = build_control_capability(
        detect=True,
        remediate=True,
        auto_remediate=False,
        requires_approval=False,
        notes="manual",
    )
    assert cap["mode"] == "manual"
    assert cap["allowed"] is True
    assert cap["reason"] == "manual_remediate"


def test_ca_policy_capability_returns_manual_mode():
    """TENANT_CONDITIONAL_ACCESS_POLICY is remediate=True, auto_remediate=False,
    requires_approval=True — must produce mode=manual so the frontend enables the button."""
    cap = build_control_capability(
        detect=True,
        remediate=True,
        auto_remediate=False,
        requires_approval=True,
        notes="Microsoft supports creating and modifying Conditional Access policies through existing guarded workflows.",
    )
    assert cap["mode"] == "manual"
    assert cap["allowed"] is True
