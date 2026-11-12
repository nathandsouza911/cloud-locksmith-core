"""Adapter registry — maps control_id to its VerificationAdapter.

Built at import time from CONTROL_REGISTRY. Every control with
verification_supported=True gets a LegacyFunctionAdapter wrapping its
registered verifier. New controls that implement VerificationAdapter
natively can be registered here directly.
"""

from __future__ import annotations

from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.remediation.verification.adapter import (
    LegacyFunctionAdapter,
    VerificationAdapter,
)


def _build_registry() -> dict[str, VerificationAdapter]:
    registry: dict[str, VerificationAdapter] = {}
    for control_id, entry in CONTROL_REGISTRY.items():
        if entry.get("verification_supported") and entry.get("verifier"):
            registry[control_id] = LegacyFunctionAdapter(
                entry["verifier"],
                control_id=control_id,
            )
    return registry


ADAPTER_REGISTRY: dict[str, VerificationAdapter] = _build_registry()


def get_adapter(control_id: str) -> VerificationAdapter | None:
    """Return the VerificationAdapter for ``control_id``, or None if not verifiable."""
    return ADAPTER_REGISTRY.get(control_id)
