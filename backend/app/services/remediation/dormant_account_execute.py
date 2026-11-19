def account_enabled(state: dict | None) -> bool | None:
    """Enabled state from an adapter's account state: Microsoft returns
    ``accountEnabled``, Google ``is_active``. None when neither is present."""
    state = state or {}
    if "accountEnabled" in state:
        return bool(state["accountEnabled"])
    if "is_active" in state:
        return bool(state["is_active"])
    return None


class DormantAccountExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        if not user_id:
            raise ValueError("user_id is required for dormant account remediation")

        enabled = account_enabled(await graph_client.get_user_account_state(user_id))
        if enabled is None:
            # Rollback restores this value: never guess it.
            raise ValueError("account state could not be read for the pre-change snapshot")
        return {"user_id": user_id, "accountEnabled": enabled}

    async def preview(self, graph_client, evidence: dict) -> dict:
        return {
            "changes": [
                {
                    "action": "PATCH_USER",
                    "user_id": evidence.get("user_id"),
                    "payload": {"accountEnabled": False},
                }
            ]
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        if not user_id:
            raise ValueError("user_id is required for dormant account remediation")

        snapshot = evidence.get("snapshot") or {"user_id": user_id, "accountEnabled": True}

        await graph_client.set_user_account_enabled(user_id, False)

        return {
            "status": "SUCCESS",
            "snapshot": snapshot,
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        await graph_client.set_user_account_enabled(
            snapshot["user_id"],
            snapshot.get("accountEnabled", True),
        )
