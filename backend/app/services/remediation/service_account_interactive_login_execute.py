"""Executor for IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN.

Disables the service account by setting accountEnabled=False. This is the only
Microsoft Graph API path that approximates "disable interactive sign-in" for a
user object — Graph does not expose a per-login-type disable for user accounts.
The pre-execution accountEnabled value is captured in build_snapshot() so rollback
can restore the prior state exactly.

Security: user_id is sourced from ComplianceResult evidence, not caller input.
Tenant isolation is enforced by the remediation executor before dispatch.

Classification rationale: GUARDED (not SAFE) because name-based heuristic detection
can produce false positives (a real user named 'svc-admin' would be incorrectly
identified). Human approval is required before each execution. evaluate_safe_eligibility()
returns SAFE_NOW (score 13/15) but the registry keeps this GUARDED until detection
moves to explicit service-account type markers (managedIdentity, servicePrincipal) in
Entra ID rather than naming heuristics.
"""

from __future__ import annotations


class ServiceAccountExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        """Capture the current account state before disabling."""
        user_id = evidence.get("user_id")
        if not user_id:
            return {}
        state = await graph_client.get_user_account_state(user_id)
        return {
            "user_id": user_id,
            "accountEnabled": bool(state.get("accountEnabled", True)),
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        """Disable the service account (accountEnabled=False)."""
        user_id = evidence.get("user_id")
        if not user_id:
            return {"status": "failed", "reason": "missing_user_id"}
        await graph_client.set_user_account_enabled(user_id, False)
        return {
            "status": "SUCCESS",
            "user_id": user_id,
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        """Restore the account's prior accountEnabled state."""
        user_id = (snapshot or {}).get("user_id")
        if not user_id:
            return
        prior_enabled = (snapshot or {}).get("accountEnabled", True)
        await graph_client.set_user_account_enabled(user_id, prior_enabled)
