"""Bulk-fleet-remediation security core (CRITICAL-C3 guard).

Pure functions only — no DB, no Graph, no tenant resolution. This module is the
single place that enforces the bulk-remediation invariants:

  1. Only SAFE controls may ever be bulk-remediated.
  2. Execution is bound to an approved plan hash: a finding that was not part of
     the reviewed-and-approved plan can never be executed, and the approved set
     cannot be tampered with after approval without detection.

A "plan item" identifies exactly one finding to remediate in one tenant:
``{tenant_id, compliance_result_id, control_id}``.
"""

from __future__ import annotations

import hashlib
import json

from app.services.remediation.control_registry import CONTROL_REGISTRY

SAFE_REMEDIATION_LEVEL = "SAFE"


class UnsafeControlError(ValueError):
    """Raised when a non-SAFE control is included in a bulk campaign."""

    def __init__(self, control_id: str):
        super().__init__(f"Control {control_id!r} is not SAFE and cannot be bulk-remediated")
        self.control_id = control_id


class CampaignScopeError(ValueError):
    """Raised when execution would diverge from the approved plan.

    ``reason`` is one of:
      * "plan_tampered"    — the approved item set no longer matches the
        approved hash (integrity failure; fail closed).
      * "item_not_approved" — the item was not part of the approved plan.
    """

    def __init__(self, message: str, *, reason: str):
        super().__init__(message)
        self.reason = reason


def make_item(tenant_id: str, compliance_result_id: int, control_id: str) -> dict:
    return {
        "tenant_id": str(tenant_id),
        "compliance_result_id": int(compliance_result_id),
        "control_id": str(control_id),
    }


def _item_key(item: dict) -> tuple[str, int, str]:
    return (
        str(item["tenant_id"]),
        int(item["compliance_result_id"]),
        str(item["control_id"]),
    )


def canonical_plan(items: list[dict]) -> list[dict]:
    """Deterministic, de-duplicated, sorted list of plan items."""
    unique = {_item_key(item): item for item in items}
    return [make_item(*key) for key in sorted(unique.keys())]


def compute_plan_hash(items: list[dict]) -> str:
    canonical = canonical_plan(items)
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_safe_control(control_id: str) -> bool:
    control = CONTROL_REGISTRY.get(control_id)
    if not control:
        return False
    return control.get("auto_remediation_level") == SAFE_REMEDIATION_LEVEL and bool(control.get("is_executable"))


def assert_controls_safe(control_ids) -> None:
    for control_id in control_ids:
        if not is_safe_control(control_id):
            raise UnsafeControlError(control_id)


def assert_within_approved_plan(
    *,
    item: dict,
    approved_items: list[dict],
    approved_hash: str,
) -> None:
    """Fail closed unless ``item`` is part of the approved, untampered plan.

    Order of checks matters: the integrity (tamper) check runs first so a
    smuggled item added to ``approved_items`` cannot mask itself as approved.
    """
    if compute_plan_hash(approved_items) != approved_hash:
        raise CampaignScopeError(
            "Approved plan set does not match the approved hash — refusing to execute",
            reason="plan_tampered",
        )

    approved_keys = {_item_key(a) for a in approved_items}
    if _item_key(item) not in approved_keys:
        raise CampaignScopeError(
            "Item was not part of the approved plan — refusing to execute",
            reason="item_not_approved",
        )
