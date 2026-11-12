import logging

from app.services.graph_client import GraphAPIError

logger = logging.getLogger(__name__)


class AdminRoleExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        if not user_id:
            raise ValueError("user_id is required")

        roles = [
            {
                "role_id": role.get("id"),
                "role_name": role.get("displayName"),
            }
            for role in await graph_client.fetch_user_memberof_directory_roles(user_id)
        ]
        return {
            "user_id": user_id,
            "roles": sorted(
                [
                    {
                        "role_id": role["role_id"],
                        "role_name": role["role_name"],
                    }
                    for role in roles
                    if role.get("role_id")
                ],
                key=lambda item: item["role_id"],
            ),
        }

    async def preview(self, graph_client, evidence: dict) -> dict:
        selected_roles = (
            evidence.get("selected_roles") or evidence.get("available_roles") or evidence.get("current_roles") or []
        )
        return {
            "changes": [
                {
                    "action": "REMOVE_DIRECTORY_ROLE_MEMBERSHIP",
                    "user_id": evidence.get("user_id"),
                    "selected_roles": selected_roles,
                }
            ]
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        user_id = evidence.get("user_id")
        selected_roles = evidence.get("selected_roles") or []

        if not user_id:
            raise ValueError("user_id is required")
        if not selected_roles:
            raise ValueError("selected_roles must be provided")

        # 1. Fetch current roles
        roles = [
            {
                "role_id": role.get("id"),
                "role_name": role.get("displayName"),
            }
            for role in await graph_client.fetch_user_memberof_directory_roles(user_id)
        ]

        # 2. Build lookup maps
        role_id_map = {r["role_id"]: r["role_id"] for r in roles if r.get("role_id")}
        role_name_map = {r["role_name"]: r["role_id"] for r in roles if r.get("role_name") and r.get("role_id")}

        # 3. Resolve selected roles → role_ids
        resolved_role_ids = []
        for r in selected_roles:
            # Case 1: already role_id
            if r in role_id_map:
                resolved_role_ids.append(r)
                continue

            # Case 2: displayName → role_id
            if r in role_name_map:
                resolved_role_ids.append(role_name_map[r])
                continue

            # Unknown role → skip safely
            logger.warning("Unknown role passed to executor: %s", r)

        failed_roles = []

        # 4. Execute removals
        for role_id in resolved_role_ids:
            try:
                await graph_client.remove_directory_role_member(role_id, user_id)
            except GraphAPIError as exc:
                if exc.status_code == 404:
                    failed_roles.append(role_id)
                    continue
                raise

        return {
            "status": "PARTIAL_SUCCESS" if failed_roles else "SUCCESS",
            "skipped_roles": failed_roles,
            "snapshot": evidence.get("snapshot")
            or {
                "user_id": user_id,
                "roles": sorted(
                    [
                        {
                            "role_id": r["role_id"],
                            "role_name": r["role_name"],
                        }
                        for r in roles
                        if r.get("role_id")
                    ],
                    key=lambda x: x["role_id"],
                ),
            },
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        user_id = snapshot.get("user_id")

        for role in snapshot.get("roles", []):
            role_id = role.get("role_id")
            if not role_id:
                continue

            await graph_client.add_directory_role_member(role_id, user_id)
