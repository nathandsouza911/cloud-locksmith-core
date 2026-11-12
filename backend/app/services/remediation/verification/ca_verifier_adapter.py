"""Adapter bridging the raw Conditional Access verifiers to the generic
verification dispatch contract.

Raw CA verifiers in ``ca_policy_engine`` have the signature
``async (*, graph_client) -> bool``. The generic dispatcher
(``verify_execution`` / ``run_verification_job``) calls every registered verifier
as ``await verifier(db=, tenant=, compliance_result=)`` and expects a
``{"success": bool, "details": {...}}`` dict.

Without this adapter the CA controls were registered with
``verification_supported: True`` but could never actually be dispatched — the
mismatched signature raised ``TypeError`` (swallowed by the background job,
surfaced as a 500 on the API), so CA controls silently never verified.

Fail-closed: provider read errors propagate; they are never reported as a
successful verification.
"""

from __future__ import annotations

from typing import Awaitable, Callable


def _default_client_factory(*, db, tenant):
    # Imported lazily to avoid an import-time cycle with the executor module.
    from app.services.remediation_executor import RemediationGraphClient

    return RemediationGraphClient(db=db, tenant=tenant)


def make_ca_verifier_adapter(
    verify_fn: Callable[..., Awaitable[bool]],
    *,
    control_id: str,
    client_factory: Callable[..., object] = _default_client_factory,
):
    """Wrap a ``(*, graph_client) -> bool`` CA verifier as a generic
    ``(*, db, tenant, compliance_result) -> dict`` verifier."""

    async def _adapter(*, db, tenant, compliance_result) -> dict:
        graph_client = client_factory(db=db, tenant=tenant)
        passed = await verify_fn(graph_client=graph_client)
        success = bool(passed)
        return {
            "success": success,
            "details": {
                "reason": None if success else "CA_POLICY_NOT_ENFORCED",
                "evidence": {"control_id": control_id},
            },
        }

    _adapter.__name__ = f"verify_{control_id.lower()}_adapter"
    return _adapter
