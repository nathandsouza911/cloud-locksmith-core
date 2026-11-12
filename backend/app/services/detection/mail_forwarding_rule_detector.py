"""Detection logic for IDENTITY_MAIL_FORWARDING_RULE.

Pure functions only — no DB, no Graph. The scanner in identity_scan_service.py
supplies each user's inbox message rules (``GET /users/{id}/mailFolders/inbox/messageRules``)
and the tenant's own domains.

Flags inbox rules that forward or redirect mail to an address outside the
tenant's own domains. External auto-forwarding is one of the most common
indicators of business email compromise (an attacker who gains access to a
mailbox creates a silent forwarding rule to exfiltrate mail — e.g. invoices,
wire-transfer approvals — without the account owner noticing).

Detection only (MANUAL, no auto-remediation): removing or disabling a mail
rule is a destructive action on customer-owned mail configuration and is not
automated in V1.
"""

from __future__ import annotations

CONTROL_ID = "IDENTITY_MAIL_FORWARDING_RULE"


def _rule_forward_targets(rule: dict) -> list[str]:
    """Return lowercased email addresses from any forward/redirect action on a rule."""
    actions = rule.get("actions") or {}
    targets: list[str] = []
    for action_key in ("forwardTo", "forwardAsAttachmentTo", "redirectTo"):
        for recipient in actions.get(action_key) or []:
            address = ((recipient or {}).get("emailAddress") or {}).get("address")
            if address:
                targets.append(address.lower())
    return targets


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def evaluate_user_forwarding_rules(
    user: dict,
    rules: list[dict],
    tenant_domains: set[str],
) -> dict | None:
    """Evaluate one user's inbox rules for auto-forwarding to an external address.

    Returns a finding dict if any enabled rule forwards/redirects to an address
    whose domain is not in ``tenant_domains``, else None (the user passes).
    """
    tenant_domains_lower = {d.lower() for d in tenant_domains}
    flagged_rules: list[dict] = []

    for rule in rules:
        if rule.get("isEnabled") is False:
            continue
        targets = _rule_forward_targets(rule)
        if not targets:
            continue
        external_targets = [t for t in targets if _domain_of(t) not in tenant_domains_lower]
        if not external_targets:
            continue
        flagged_rules.append(
            {
                "rule_id": rule.get("id"),
                "rule_name": rule.get("displayName"),
                "external_targets": sorted(set(external_targets)),
            }
        )

    if not flagged_rules:
        return None

    return {
        "control_id": CONTROL_ID,
        "passed": False,
        "severity": "CRITICAL",
        "resource_id": user.get("id"),
        "evidence": {
            "user_id": user.get("id"),
            "user_principal_name": user.get("userPrincipalName"),
            "display_name": user.get("displayName"),
            "flagged_rule_count": len(flagged_rules),
            "flagged_rules": flagged_rules,
        },
    }
