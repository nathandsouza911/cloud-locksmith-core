import logging

from app.services.graph_client import get_tenant_graph_token_claims, graph_get

logger = logging.getLogger(__name__)


def _structured_warning(*, user_id: str, tenant_id: str, error_code: str):
    logger.warning(
        "%s",
        {
            "event": "auth_methods_fetch_failed",
            "user_id": user_id,
            "tenant_id": tenant_id,
            "reason": error_code,
        },
    )


async def fetch_authentication_methods(db, tenant, user_id: str) -> dict:
    response = await graph_get(
        db,
        tenant,
        f"/users/{user_id}/authentication/methods",
    )

    if isinstance(response, dict) and response.get("status") == "error":
        _structured_warning(
            user_id=user_id,
            tenant_id=str(getattr(tenant, "id", "")),
            error_code=f"{response.get('code')}_{response.get('reason')}",
        )
        claims = await get_tenant_graph_token_claims(db=db, tenant=tenant)
        current_authenticated_user = claims.get("oid") or claims.get("sub")

        if current_authenticated_user == user_id:
            me_response = await graph_get(db, tenant, "/me/authentication/methods")
            if not (isinstance(me_response, dict) and me_response.get("status") == "error"):
                return {
                    "auth_methods_status": "OK",
                    "mfa_status": "KNOWN",
                    "methods": me_response.get("value", []),
                    "fallback_used": True,
                }

        return {
            "auth_methods_status": "ACCESS_DENIED",
            "mfa_status": "UNKNOWN",
            "methods": [],
            "error_code": response.get("code"),
        }

    return {
        "auth_methods_status": "OK",
        "mfa_status": "KNOWN",
        "methods": response.get("value", []),
        "fallback_used": False,
    }
