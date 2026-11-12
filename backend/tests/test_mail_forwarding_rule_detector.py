from app.services.detection.mail_forwarding_rule_detector import (
    CONTROL_ID,
    evaluate_user_forwarding_rules,
)


def _user(user_id: str, upn: str, display_name: str = "Test User") -> dict:
    return {
        "id": user_id,
        "userPrincipalName": upn,
        "displayName": display_name,
    }


def _rule(
    rule_id: str,
    *,
    display_name: str = "Auto forward",
    is_enabled: bool = True,
    forward_to: list[str] | None = None,
    redirect_to: list[str] | None = None,
    forward_as_attachment_to: list[str] | None = None,
) -> dict:
    def _recipients(addresses: list[str] | None) -> list[dict]:
        return [{"emailAddress": {"address": a}} for a in (addresses or [])]

    return {
        "id": rule_id,
        "displayName": display_name,
        "isEnabled": is_enabled,
        "actions": {
            "forwardTo": _recipients(forward_to),
            "redirectTo": _recipients(redirect_to),
            "forwardAsAttachmentTo": _recipients(forward_as_attachment_to),
        },
    }


TENANT_DOMAINS = {"contoso.com"}


def test_passes_when_user_has_no_rules():
    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), [], TENANT_DOMAINS)

    assert result is None


def test_passes_when_rule_forwards_internally():
    rules = [_rule("r1", forward_to=["bob@contoso.com"])]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, TENANT_DOMAINS)

    assert result is None


def test_passes_when_disabled_rule_forwards_externally():
    rules = [_rule("r1", is_enabled=False, forward_to=["attacker@evil.com"])]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, TENANT_DOMAINS)

    assert result is None


def test_flags_enabled_rule_forwarding_to_external_domain():
    rules = [_rule("r1", forward_to=["attacker@evil.com"])]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, TENANT_DOMAINS)

    assert result["control_id"] == CONTROL_ID
    assert result["passed"] is False
    assert result["severity"] == "CRITICAL"
    assert result["resource_id"] == "u1"
    assert result["evidence"]["flagged_rule_count"] == 1
    assert result["evidence"]["flagged_rules"][0]["external_targets"] == ["attacker@evil.com"]


def test_flags_redirect_and_forward_as_attachment_actions():
    rules = [
        _rule("r1", forward_to=[], redirect_to=["a@evil.com"]),
        _rule("r2", forward_as_attachment_to=["b@evil.com"]),
    ]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, TENANT_DOMAINS)

    assert result["evidence"]["flagged_rule_count"] == 2


def test_deduplicates_and_sorts_external_targets_per_rule():
    rules = [
        _rule(
            "r1",
            forward_to=["z@evil.com", "a@evil.com"],
            redirect_to=["a@evil.com"],
        )
    ]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, TENANT_DOMAINS)

    assert result["evidence"]["flagged_rules"][0]["external_targets"] == [
        "a@evil.com",
        "z@evil.com",
    ]


def test_ignores_rules_with_no_forward_or_redirect_action():
    rules = [{"id": "r1", "displayName": "Move to folder", "isEnabled": True, "actions": {}}]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, TENANT_DOMAINS)

    assert result is None


def test_domain_match_is_case_insensitive():
    rules = [_rule("r1", forward_to=["Bob@CONTOSO.COM"])]

    result = evaluate_user_forwarding_rules(_user("u1", "alice@contoso.com"), rules, {"Contoso.com"})

    assert result is None
