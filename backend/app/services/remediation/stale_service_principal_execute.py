"""Executor for IDENTITY_STALE_SERVICE_PRINCIPAL.

Disables a stale service principal by patching accountEnabled=false.
The pre-execution accountEnabled value is captured in build_snapshot() for
rollback. If the SP is already disabled when execute() runs, the executor
is a no-op (already remediated); it still returns SUCCESS so the pipeline
records the execution.

Security: sp_id is sourced from the ComplianceResult evidence, not from
caller-supplied input. Tenant isolation is enforced by the caller (remediation
executor validates ComplianceResult.tenant_id before dispatching).
"""

from __future__ import annotations


class StaleSPExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        """Fetch the current SP state before disabling it."""
        sp_id = evidence.get("sp_id") or evidence.get("resource_id")
        if not sp_id:
            return {}
        sp = await graph_client.get(f"/servicePrincipals/{sp_id}?$select=id,displayName,accountEnabled")
        return {
            "sp_id": sp_id,
            "accountEnabled": sp.get("accountEnabled", True),
            "displayName": sp.get("displayName"),
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        """Disable the stale service principal."""
        sp_id = evidence.get("sp_id") or evidence.get("resource_id")
        if not sp_id:
            return {"status": "failed", "reason": "missing_sp_id"}
        await graph_client.patch(
            f"/servicePrincipals/{sp_id}",
            {"accountEnabled": False},
        )
        return {
            "status": "SUCCESS",
            "sp_id": sp_id,
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        """Re-enable the service principal from pre-execution snapshot."""
        sp_id = (snapshot or {}).get("sp_id")
        prior_enabled = (snapshot or {}).get("accountEnabled", True)
        if not sp_id:
            return
        await graph_client.patch(
            f"/servicePrincipals/{sp_id}",
            {"accountEnabled": prior_enabled},
        )
