from __future__ import annotations

from typing import Any

from app.services.identity_providers import get_identity_provider_adapter
from app.services.identity_providers.base import normalize_control_capability_id


async def evaluate_action(tenant, control_id: str, action_type: str, *, db) -> dict[str, Any]:
    normalized_action_type = str(action_type or "").strip().lower()
    if normalized_action_type not in {"execute", "auto_execute"}:
        raise ValueError(f"Unsupported action_type: {action_type}")

    normalized_control_id = normalize_control_capability_id(control_id)
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    capabilities = adapter.get_control_capabilities() or {}
    capability = capabilities.get(normalized_control_id)

    if not isinstance(capability, dict):
        return {
            "allowed": False,
            "mode": "blocked",
            "reason": "capability_not_defined",
            "notes": "This control is not defined in the provider capability map.",
        }

    notes = str(capability.get("notes") or "")
    if not bool(capability.get("remediate")):
        return {
            "allowed": False,
            "mode": "blocked",
            "reason": "provider_remediation_not_supported",
            "notes": notes,
        }

    if normalized_action_type == "auto_execute" and not bool(capability.get("auto_remediate")):
        return {
            "allowed": False,
            "mode": "blocked",
            "reason": "auto_remediation_not_supported",
            "notes": notes,
        }

    if bool(capability.get("requires_approval")):
        return {
            "allowed": True,
            "mode": "manual",
            "reason": "approval_required",
            "notes": notes,
        }

    return {
        "allowed": True,
        "mode": "auto",
        "reason": "allowed",
        "notes": notes,
    }
