import logging
import uuid
from datetime import timedelta
from app.utils.datetime import utc_now

import jwt

from app.config import settings

logger = logging.getLogger(__name__)
APP_TOKEN_SOURCE = "cloud_locksmith_app"


def create_access_token(*, user_id, organization_id, email, role, tenant_ids=None):
    payload = {
        "sub": str(user_id),
        "user_id": str(user_id),
        "organization_id": str(organization_id),
        "email": email,
        "role": role,
        "tenant_ids": tenant_ids or [],
        "token_source": APP_TOKEN_SOURCE,
        "jti": str(uuid.uuid4()),
        "exp": utc_now() + timedelta(hours=settings.APP_JWT_TTL_HOURS),
    }
    return jwt.encode(
        payload,
        settings.APP_JWT_SECRET,
        algorithm=settings.APP_JWT_ALGORITHM,
    )


def create_token(user_id, tenant_ids=None):
    return create_access_token(
        user_id=user_id,
        organization_id="",
        email="",
        role="ADMIN",
        tenant_ids=tenant_ids,
    )


def decode_access_token(token):
    from app.services.auth.token_denylist import is_revoked

    try:
        unverified_payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=[settings.APP_JWT_ALGORITHM],
        )
        issuer = str(unverified_payload.get("iss") or "")
        looks_like_app_token = unverified_payload.get("token_source") == APP_TOKEN_SOURCE or (
            {"sub", "user_id", "organization_id", "email", "role"}.issubset(unverified_payload.keys())
            and "login.microsoftonline.com" not in issuer
        )
        if not looks_like_app_token:
            raise ValueError("Token is not an app-issued JWT")

        payload = jwt.decode(
            token,
            settings.APP_JWT_SECRET,
            algorithms=[settings.APP_JWT_ALGORITHM],
        )

        jti = payload.get("jti")
        if jti and is_revoked(jti):
            raise ValueError("Token has been revoked")

        return payload
    except Exception as exc:
        logger.debug("jwt_decode_error error=%s", type(exc).__name__)
        raise


def decode_token(token):
    return decode_access_token(token)
