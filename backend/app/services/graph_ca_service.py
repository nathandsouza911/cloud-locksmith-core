import logging

from app.services.graph_client import graph_get, graph_get_all

logger = logging.getLogger(__name__)


async def fetch_conditional_access_policies(db, tenant) -> list[dict]:
    response = await graph_get(
        db,
        tenant,
        "/identity/conditionalAccess/policies",
    )
    return response.get("value", [])


async def build_ca_group_member_map(
    db,
    tenant,
    policies: list[dict],
) -> dict[str, set[str]]:
    """
    Collects every group ID referenced in ``includeGroups`` across all CA
    policies, fetches their members from Graph, and returns a mapping of
    ``{group_id: {user_id, ...}}``.

    Key design decisions
    ──────────────────────
    - Groups are de-duplicated before fetching so each group is queried once,
      regardless of how many policies reference it.
    - Full pagination is handled by ``graph_get_all``.
    - Non-user members (service principals, nested groups) are filtered out.
    - A per-group fetch failure logs and returns an empty set for that group so
      a single inaccessible group never aborts the entire scan.
    """
    group_ids: set[str] = set()
    for policy in policies:
        for gid in (policy.get("conditions") or {}).get("users", {}).get("includeGroups") or []:
            if gid:
                group_ids.add(gid)

    if not group_ids:
        return {}

    logger.info(
        "ca_group_member_map_start tenant_id=%s groups=%s",
        getattr(tenant, "id", None),
        len(group_ids),
    )

    member_map: dict[str, set[str]] = {}
    for gid in group_ids:
        try:
            members = await graph_get_all(
                db,
                tenant,
                f"/groups/{gid}/members?$select=id",
            )
            member_map[gid] = {
                m["id"]
                for m in members
                if m.get("id")
                # Keep only user objects; skip nested groups and service principals.
                and m.get("@odata.type") in (None, "#microsoft.graph.user")
            }
            logger.debug(
                "ca_group_members_fetched group_id=%s members=%s",
                gid,
                len(member_map[gid]),
            )
        except Exception:
            logger.exception(
                "ca_group_member_fetch_failed group_id=%s tenant_id=%s — treating as empty",
                gid,
                getattr(tenant, "id", None),
            )
            member_map[gid] = set()

    logger.info(
        "ca_group_member_map_done tenant_id=%s groups_resolved=%s",
        getattr(tenant, "id", None),
        len(member_map),
    )
    return member_map
