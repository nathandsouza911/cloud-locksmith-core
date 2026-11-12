import inspect
import logging

from app.services.graph_client import (
    GraphAPIError,
    graph_get_all,
    is_non_premium_signin_activity_error,
)
from app.services.identity_dedup import dedupe_directory_users

logger = logging.getLogger(__name__)

USERS_SELECT_WITH_SIGNIN = (
    "/users?$select=id,displayName,mail,userPrincipalName,accountEnabled," "createdDateTime,signInActivity"
)
USERS_SELECT_FALLBACK = "/users?$select=id,displayName,mail,userPrincipalName,accountEnabled," "createdDateTime"


async def _maybe_commit(db) -> None:
    commit = getattr(db, "commit", None)
    if commit is None:
        return
    result = commit()
    if inspect.isawaitable(result):
        await result


async def _set_signin_activity_capability(db, tenant, available: bool) -> None:
    asset_flags = dict(getattr(tenant, "asset_flags", None) or {})
    asset_flags["has_signin_activity"] = available
    tenant.asset_flags = asset_flags
    await _maybe_commit(db)


async def fetch_users(db, tenant):
    try:
        response = await graph_get_all(db, tenant, USERS_SELECT_WITH_SIGNIN)
        await _set_signin_activity_capability(db, tenant, True)
        return dedupe_directory_users(response, include_disabled=True)
    except GraphAPIError as exc:
        if is_non_premium_signin_activity_error(exc):
            logger.warning(
                "signInActivity not available for tenant %s",
                getattr(tenant, "id", None),
            )
            await _set_signin_activity_capability(db, tenant, False)
            try:
                response = await graph_get_all(db, tenant, USERS_SELECT_FALLBACK)
                return dedupe_directory_users(response, include_disabled=True)
            except GraphAPIError:
                logger.exception(
                    "Graph fallback user fetch failed for tenant %s",
                    getattr(tenant, "id", None),
                )
                return []

        logger.exception(
            "Graph user fetch failed for tenant %s",
            getattr(tenant, "id", None),
        )
        return []
