from app.services.graph_client import GraphAPIError


GRANT_BODY_FIELDS = (
    "clientId",
    "resourceId",
    "principalId",
    "consentType",
    "scope",
    "startTime",
    "expiryTime",
)


def _serialize_grant(live: dict) -> dict:
    return {
        "id": live.get("id"),
        **{field: live.get(field) for field in GRANT_BODY_FIELDS},
    }


class IllicitConsentGrantsExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        grants: list[dict] = []
        for entry in evidence.get("illicit_grants", []) or []:
            grant_id = entry.get("id")
            if not grant_id:
                continue
            try:
                live = await graph_client.get_oauth2_permission_grant(grant_id)
            except GraphAPIError as exc:
                if exc.status_code == 404:
                    continue
                raise
            grants.append(_serialize_grant(live))
        return {"grants": grants}

    async def preview(self, graph_client, evidence: dict) -> dict:
        grants = evidence.get("illicit_grants", []) or []
        return {
            "changes": [
                {
                    "action": "DELETE_OAUTH2_PERMISSION_GRANT",
                    "grant_id": grant.get("id"),
                    "clientId": grant.get("clientId"),
                    "scope": grant.get("scope"),
                }
                for grant in grants
            ]
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        snapshot = evidence.get("snapshot")
        if not isinstance(snapshot, dict) or "grants" not in snapshot:
            snapshot = await self.build_snapshot(graph_client, evidence)

        target_grants = snapshot.get("grants", []) or []
        deleted: list[str] = []
        failed: list[dict] = []

        for grant in target_grants:
            grant_id = grant.get("id")
            if not grant_id:
                failed.append({"id": None, "reason": "MISSING_ID"})
                continue
            try:
                await graph_client.delete_oauth2_permission_grant(grant_id)
            except GraphAPIError as exc:
                if exc.status_code == 404:
                    deleted.append(grant_id)
                    continue
                failed.append({"id": grant_id, "reason": f"DELETE_ERROR_{exc.status_code}"})
                continue

            try:
                await graph_client.get_oauth2_permission_grant(grant_id)
            except GraphAPIError as exc:
                if exc.status_code == 404:
                    deleted.append(grant_id)
                else:
                    failed.append({"id": grant_id, "reason": f"VERIFY_ERROR_{exc.status_code}"})
                continue

            failed.append({"id": grant_id, "reason": "STILL_PRESENT_AFTER_DELETE"})

        if not failed:
            status = "SUCCESS"
        elif deleted:
            status = "PARTIAL"
        else:
            status = "FAILED"

        return {
            "status": status,
            "snapshot": snapshot,
            "result": {
                "deleted": deleted,
                "failed": failed,
                "total": len(target_grants),
            },
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        grants = (snapshot or {}).get("grants", []) or []

        unique: dict[tuple, dict] = {}
        for grant in grants:
            client_id = grant.get("clientId")
            resource_id = grant.get("resourceId")
            if not client_id or not resource_id:
                continue
            key = (
                client_id,
                resource_id,
                grant.get("principalId"),
                grant.get("consentType"),
                grant.get("scope"),
            )
            unique[key] = grant
        deduped_grants = list(unique.values())

        def _is_equivalent(existing_grant: dict, snapshot_grant: dict) -> bool:
            return (
                existing_grant.get("clientId") == snapshot_grant.get("clientId")
                and existing_grant.get("resourceId") == snapshot_grant.get("resourceId")
                and existing_grant.get("principalId") == snapshot_grant.get("principalId")
                and existing_grant.get("consentType") == snapshot_grant.get("consentType")
                and existing_grant.get("scope") == snapshot_grant.get("scope")
            )

        for grant in deduped_grants:
            # Fetch inside the loop so each create sees the current state,
            # avoiding a race where a concurrent grant creation causes a duplicate.
            existing_grants = await graph_client.list_oauth2_permission_grants()
            if any(_is_equivalent(existing, grant) for existing in existing_grants):
                continue
            payload = {field: grant.get(field) for field in GRANT_BODY_FIELDS if grant.get(field) is not None}
            await graph_client.create_oauth2_permission_grant(payload)
