# app/services/remediation/admin_roles/constants.py

# Hard guardrails for roles we never auto-remove or auto-restore.
NON_REMOVABLE_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
}


def is_role_removable(role_name: str | None) -> bool:
    if not isinstance(role_name, str):
        return False
    normalized = role_name.strip()
    if not normalized:
        return False
    return normalized not in NON_REMOVABLE_ROLES


# Backward-compatible export used by older call sites.
REMOVABLE_ROLES = {
    "Global Reader",
    "Security Administrator",
    "Security Reader",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}
