"""Executor for IDENTITY_PASSWORD_NEVER_EXPIRES.

Removes the DisablePasswordExpiration flag from a user's passwordPolicies via
Microsoft Graph PATCH /users/{id}. Other flags (e.g. DisableStrongPassword)
are preserved in the snapshot and restored on rollback.

This control is SAFE: the change is per-user, deterministic, fully reversible
from snapshot, and has no lockout risk. Rollback restores the exact original
passwordPolicies string.
"""

from __future__ import annotations

from app.services.detection.password_never_expires_detector import remove_never_expires_flag


class PasswordNeverExpiresExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        if not user_id:
            raise ValueError("user_id is required for password-never-expires remediation")
        user_data = await graph_client.get(f"/users/{user_id}?$select=id,passwordPolicies")
        return {
            "user_id": user_id,
            "password_policies": user_data.get("passwordPolicies") or "",
        }

    async def preview(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        current_policies = evidence.get("password_policies") or evidence.get("passwordPolicies") or ""
        target_policies = remove_never_expires_flag(current_policies)
        return {
            "changes": [
                {
                    "action": "PATCH_USER_PASSWORD_POLICIES",
                    "user_id": user_id,
                    "current_passwordPolicies": current_policies,
                    "target_passwordPolicies": target_policies,
                }
            ]
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        if not user_id:
            raise ValueError("user_id is required")

        snapshot = evidence.get("snapshot") or await self.build_snapshot(graph_client, evidence)
        current_policies = snapshot.get("password_policies") or ""
        target_policies = remove_never_expires_flag(current_policies)

        await graph_client.patch(f"/users/{user_id}", {"passwordPolicies": target_policies})

        return {
            "status": "SUCCESS",
            "snapshot": snapshot,
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        user_id = snapshot.get("user_id")
        if not user_id:
            raise ValueError("snapshot missing user_id")
        original_policies = snapshot.get("password_policies") or "None"
        await graph_client.patch(f"/users/{user_id}", {"passwordPolicies": original_policies})
