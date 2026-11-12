import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
import base64
import json
import logging

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.services.crypto import decrypt_str, encrypt_str

logger = logging.getLogger(__name__)
_REFRESH_BUFFER_SECONDS = 60
_REFRESH_RETRY_COUNT = 2
_tenant_refresh_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

# Ephemeral per-task Graph token for read-only flows (preview, cost-checker).
# Stores (tenant_id, access_token). The tenant_id is validated on every read to
# prevent cross-tenant token leakage. Never written to DB. Scoped to the current
# asyncio Task — concurrent requests for different tenants cannot interfere.
_SCAN_EPHEMERAL_TOKEN: ContextVar[tuple[str, str] | None] = ContextVar("_scan_ephemeral_token", default=None)


@asynccontextmanager
async def scan_ephemeral_token(tenant_id: str, access_token: str):
    """
    Inject a short-lived Graph token for preview / cost-checker scan runs.

    The token is never persisted. It is active only for the duration of this
    context and only for the exact tenant_id supplied.  Any call to
    ``get_valid_access_token`` or ``has_delegated_oauth_token`` for this tenant
    within the same asyncio Task will use the injected token instead of hitting
    TenantOAuth in the DB.
    """
    reset = _SCAN_EPHEMERAL_TOKEN.set((tenant_id, access_token))
    try:
        yield
    finally:
        _SCAN_EPHEMERAL_TOKEN.reset(reset)


def _normalized_scopes(token: dict) -> list[str]:
    if token.get("scopes"):
        return list(token["scopes"])

    scope_string = token.get("scope") or ""
    if scope_string:
        return scope_string.split()

    raise HTTPException(
        status_code=401,
        detail={
            "code": "TENANT_REAUTH_REQUIRED",
            "message": "Tenant token is missing delegated scope metadata",
        },
    )


def _decode_access_token_claims(access_token: str) -> dict:
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _access_token_tid(access_token: str) -> str:
    return str(_decode_access_token_claims(access_token).get("tid") or "").strip()


def _tenant_token_url(tenant_id: str) -> str:
    resolved_tenant = (tenant_id or "").strip()
    if not resolved_tenant:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "TENANT_REAUTH_REQUIRED",
                "message": "Tenant context missing for delegated token refresh",
            },
        )
    return f"https://login.microsoftonline.com/{resolved_tenant}/oauth2/v2.0/token"


async def _get_tenant_record(tenant_or_id, db):
    if isinstance(tenant_or_id, Tenant):
        return tenant_or_id
    if db is None:
        raise ValueError("db is required when resolving a tenant by ID")
    if isinstance(db, AsyncSession):
        return await db.get(Tenant, tenant_or_id)
    return db.get(Tenant, tenant_or_id)


async def _get_tenant_oauth_record(db, tenant_id: str):
    if db is None:
        return None
    if isinstance(db, AsyncSession):
        result = await db.execute(
            select(TenantOAuth).where(
                TenantOAuth.tenant_id == tenant_id,
                TenantOAuth.provider == "microsoft",
            )
        )
        return result.scalar_one_or_none()
    return (
        db.query(TenantOAuth)
        .filter_by(
            tenant_id=tenant_id,
            provider="microsoft",
        )
        .one_or_none()
    )


async def has_delegated_oauth_token(tenant_or_id, db=None) -> bool:
    tenant = await _get_tenant_record(tenant_or_id, db)
    if tenant is None:
        return False
    ephemeral = _SCAN_EPHEMERAL_TOKEN.get()
    if ephemeral is not None and ephemeral[0] == tenant.id:
        return True
    tenant_oauth = await _get_tenant_oauth_record(db, tenant.id)
    return tenant_oauth is not None


def has_delegated_oauth_token_sync(tenant_or_id, db=None) -> bool:
    if isinstance(tenant_or_id, Tenant):
        tenant = tenant_or_id
    else:
        if db is None:
            raise ValueError("db is required when resolving a tenant by ID")
        tenant = db.get(Tenant, tenant_or_id)
    if tenant is None:
        return False
    tenant_oauth = (
        db.query(TenantOAuth)
        .filter_by(
            tenant_id=tenant.id,
            provider="microsoft",
        )
        .one_or_none()
    )
    return tenant_oauth is not None


async def _commit_if_present(db, tenant: Tenant) -> None:
    if db is None:
        return
    db.add(tenant)
    if isinstance(db, AsyncSession):
        await db.commit()
    else:
        db.commit()


def _token_dict_from_oauth_record(tenant_id: str, tenant_oauth: TenantOAuth) -> dict:
    """Build a plaintext token dict from a TenantOAuth record for use within token_manager."""
    access_token = decrypt_str(tenant_oauth.access_token)
    refresh_token = decrypt_str(tenant_oauth.refresh_token) if tenant_oauth.refresh_token else None
    expires_at = tenant_oauth.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "scopes": tenant_oauth.scopes or [],
        "scope": " ".join(tenant_oauth.scopes or []),
        "token_type": "Bearer",
        "tenant_id": tenant_id,
    }


async def _clear_stored_token(db, tenant: Tenant) -> None:
    tenant.last_delegated_auth_at = None
    tenant_oauth = await _get_tenant_oauth_record(db, tenant.id)
    if tenant_oauth is not None and db is not None:
        awaitable_delete = db.delete(tenant_oauth)
        if awaitable_delete is not None and hasattr(awaitable_delete, "__await__"):
            await awaitable_delete
    await _commit_if_present(db, tenant)


def _auth_error(message: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={
            "code": "TENANT_REAUTH_REQUIRED",
            "message": message,
        },
    )


async def _store_tenant_token(*, db, tenant: Tenant, token_payload: dict) -> None:
    tenant_oauth = await _get_tenant_oauth_record(db, tenant.id)
    if tenant_oauth is None:
        raise _auth_error("TenantOAuth record missing — re-authentication required")
    tenant_oauth.access_token = encrypt_str(token_payload["access_token"])
    refresh = token_payload.get("refresh_token")
    tenant_oauth.refresh_token = encrypt_str(refresh) if refresh else None
    expires_at = datetime.fromisoformat(token_payload["expires_at"])
    if expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    tenant_oauth.expires_at = expires_at
    tenant_oauth.scopes = token_payload.get("scopes", [])
    await _commit_if_present(db, tenant)


async def _validate_existing_token_binding(*, db, tenant: Tenant, token: dict) -> None:
    stored_tenant_id = str(token.get("tenant_id") or tenant.id)
    if stored_tenant_id != tenant.id:
        logger.warning(
            "tenant_oauth_tenant_mismatch stored_tenant_id=%s tenant_id=%s",
            stored_tenant_id,
            tenant.id,
        )
        await _clear_stored_token(db, tenant)
        raise _auth_error("Stored delegated token does not belong to this tenant")

    claims_tid = str((token.get("claims") or {}).get("tid") or "").strip()
    if claims_tid and claims_tid != tenant.id:
        logger.warning(
            "tenant_oauth_claim_tenant_mismatch token_tid=%s tenant_id=%s",
            claims_tid,
            tenant.id,
        )
        await _clear_stored_token(db, tenant)
        raise _auth_error("Stored delegated token no longer matches this tenant")

    access_token = token.get("access_token")
    if isinstance(access_token, str) and access_token.strip():
        token_tid = _access_token_tid(access_token)
        if token_tid and token_tid != tenant.id:
            logger.warning(
                "tenant_oauth_access_token_tenant_mismatch token_tid=%s tenant_id=%s",
                token_tid,
                tenant.id,
            )
            await _clear_stored_token(db, tenant)
            raise _auth_error("Stored delegated access token belongs to a different tenant")


async def refresh_tenant_oauth_token(*, tenant_id: str, db, current_token: dict) -> dict:
    delegated_scopes = _normalized_scopes(current_token)
    refresh_token = current_token.get("refresh_token")
    if not refresh_token:
        raise _auth_error("Access token expired and no refresh token is available")

    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": " ".join(delegated_scopes),
    }

    token_url = _tenant_token_url(tenant_id)
    last_body = None
    logger.info("tenant_oauth_refresh_start tenant_id=%s", tenant_id)
    for attempt in range(1, _REFRESH_RETRY_COUNT + 1):
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(token_url, data=data)
        last_body = resp.text[:500]
        if resp.status_code == 200:
            new_token = resp.json()
            break
        logger.warning(
            "tenant_oauth_refresh_failure tenant_id=%s attempt=%s status_code=%s response=%s",
            tenant_id,
            attempt,
            resp.status_code,
            last_body,
        )
    else:
        raise _auth_error("Microsoft delegated token refresh failed")

    access_token = new_token["access_token"]
    claims = _decode_access_token_claims(access_token)
    refreshed_tid = str(claims.get("tid") or "").strip()
    if refreshed_tid != tenant_id:
        logger.warning(
            "tenant_oauth_refresh_tenant_mismatch tenant_id=%s refreshed_tid=%s",
            tenant_id,
            refreshed_tid,
        )
        raise _auth_error("Refreshed delegated token belongs to a different tenant")

    refreshed_scope_string = new_token.get("scope") or " ".join(delegated_scopes)
    refreshed_payload = {
        "access_token": access_token,
        "refresh_token": new_token.get("refresh_token", refresh_token),
        "expires_in": new_token["expires_in"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=new_token["expires_in"])).isoformat(),
        "scope": refreshed_scope_string,
        "scopes": refreshed_scope_string.split(),
        "token_type": new_token.get("token_type", "Bearer"),
        "tenant_id": tenant_id,
        "claims": {
            "scp": claims.get("scp"),
            "roles": claims.get("roles"),
            "wids": claims.get("wids"),
            "tid": refreshed_tid,
        },
    }
    logger.info(
        "tenant_oauth_refresh_success tenant_id=%s expires_in=%s refresh_token_rotated=%s",
        tenant_id,
        new_token["expires_in"],
        bool(new_token.get("refresh_token")),
    )
    return refreshed_payload


def _expires_soon(token: dict, *, now: datetime) -> bool:
    expires_at = datetime.fromisoformat(token["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= now + timedelta(seconds=_REFRESH_BUFFER_SECONDS)


async def get_valid_access_token(tenant_or_id, db=None, force_refresh: bool = False):
    tenant = await _get_tenant_record(tenant_or_id, db)
    if tenant is None:
        raise _auth_error("Tenant not found for delegated token lookup")

    ephemeral = _SCAN_EPHEMERAL_TOKEN.get()
    if ephemeral is not None and ephemeral[0] == tenant.id:
        return ephemeral[1]

    tenant_oauth = await _get_tenant_oauth_record(db, tenant.id)
    if tenant_oauth is None:
        raise _auth_error("Tenant has no delegated OAuth token")
    token = _token_dict_from_oauth_record(tenant.id, tenant_oauth)

    await _validate_existing_token_binding(db=db, tenant=tenant, token=token)

    now = datetime.now(timezone.utc)
    if not force_refresh and not _expires_soon(token, now=now):
        return token["access_token"]

    async with _tenant_refresh_locks[tenant.id]:
        tenant = await _get_tenant_record(tenant.id, db)
        if tenant is None:
            raise _auth_error("Tenant not found for delegated token lookup")

        tenant_oauth = await _get_tenant_oauth_record(db, tenant.id)
        if tenant_oauth is None:
            raise _auth_error("Tenant has no delegated OAuth token")
        token = _token_dict_from_oauth_record(tenant.id, tenant_oauth)

        await _validate_existing_token_binding(db=db, tenant=tenant, token=token)

        now = datetime.now(timezone.utc)
        if not force_refresh and not _expires_soon(token, now=now):
            return token["access_token"]

        try:
            refreshed_token = await refresh_tenant_oauth_token(
                tenant_id=tenant.id,
                db=db,
                current_token=token,
            )
        except HTTPException:
            await _clear_stored_token(db, tenant)
            raise

        await _store_tenant_token(db=db, tenant=tenant, token_payload=refreshed_token)
        return refreshed_token["access_token"]
