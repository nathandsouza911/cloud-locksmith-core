def users_covered_by_policy(
    policy: dict,
    all_user_ids: set[str],
    group_member_map: dict[str, set[str]] | None = None,
) -> set[str]:
    """
    Returns the set of user IDs that are covered by this CA policy's user
    conditions, after applying exclusions.

    ``group_member_map`` should be the result of
    ``graph_ca_service.build_ca_group_member_map`` — a pre-fetched mapping of
    ``{group_id: {user_id, ...}}``.  When supplied, ``includeGroups`` entries
    are expanded into individual user IDs before the coverage check.  Without
    it only ``includeUsers`` (direct IDs and "All") is evaluated.

    Note: ``includeRoles`` is not yet expanded (MVP scope).
    """
    users = policy.get("conditions", {}).get("users", {})
    include = set(users.get("includeUsers", []))
    exclude = set(users.get("excludeUsers", []))

    # Expand group membership into the include set.
    if group_member_map:
        for gid in users.get("includeGroups") or []:
            include |= group_member_map.get(gid, set())

    if "All" in include:
        return all_user_ids - exclude

    return include - exclude
