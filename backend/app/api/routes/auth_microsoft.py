from datetime import datetime, timedelta, timezone
from app.utils.datetime import to_naive_utc, utc_now
import uuid
import logging
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models.pending_oauth_session import PendingOAuthSession
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.oauth_state_nonce import OAuthStateNonce
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from app.db.session import get_sync_db
from app.services.audit.audit_logger import log_audit_event
from app.services.auth.jwt_service import create_access_token, decode_access_token
from app.services.auth.oauth_identity_service import upsert_oauth_platform_user
from app.services.auth.tenant_admin_verification import (
    oauth_user_holds_tenant_admin_role,
)
from app.services.graph_client import (
    GraphBlockedError,
    decode_access_token_claims,
    graph_get_with_token,
)
from app.services.identity_scan_service import run_scan
from app.services.oidc_verifier import verify_microsoft_id_token
from app.services.crypto import decrypt_token_dict, encrypt_str, encrypt_token_dict
from app.services.microsoft_oauth_scopes import (
    DELEGATED_SCOPE_STRING,
    PREVIEW_SCOPE_STRING,
    REQUIRED_AUTHORIZATION_POLICY_SCOPE,
    WRITE_SCOPES,
)
from app.services.tenant_service import get_or_create_tenant
from app.services.token_manager import scan_ephemeral_token
from app.services.user_tenant_access_service import get_or_create_user_tenant_access

router = APIRouter(prefix="/microsoft", tags=["Auth"])
logger = logging.getLogger(__name__)
MICROSOFT_OAUTH_STATE_SALT = "microsoft-oauth-state"
# 30 minutes: real headroom above the 10-minute onboarding target this
# window is measured against. It previously equalled that target exactly,
# so a user who paused to read Microsoft's consent screen (or the
# confirm-tenant screen) could hit "session expired" right at the finish
# line, indistinguishable from genuinely running out of time.
MICROSOFT_OAUTH_STATE_MAX_AGE_SECONDS = 1800

_COST_CHECKER_SCOPES = [
    "User.Read.All",
    "Directory.Read.All",
    "Reports.Read.All",
]
_COST_CHECKER_SCOPE_STRING = " ".join(_COST_CHECKER_SCOPES)


class MspConnectConfirmRequest(BaseModel):
    session_id: str


class MspConnectPendingResponse(BaseModel):
    session_id: str
    tenant_id: str
    tenant_name: str | None
    domain: str | None
    existing_organization_id: str | None
    msp_organization_id: str | None


def _normalize_tenant_hint(tenant_id: str | None) -> str | None:
    if tenant_id is None:
        return None
    normalized = tenant_id.strip()
    return normalized or None


def _build_microsoft_authorize_url(tenant_id: str | None) -> str:
    resolved_tenant = _normalize_tenant_hint(tenant_id) or "organizations"
    return f"https://login.microsoftonline.com/{resolved_tenant}/oauth2/v2.0/authorize"


def _build_microsoft_token_url(tenant_id: str | None) -> str:
    resolved_tenant = _normalize_tenant_hint(tenant_id)
    if resolved_tenant is None:
        resolved_tenant = "organizations"
    return f"https://login.microsoftonline.com/{resolved_tenant}/oauth2/v2.0/token"


def _tenant_matches_request(
    requested_tenant_id: str | None,
    returned_tenant_id: str,
    domains: list[dict],
) -> bool:
    requested = _normalize_tenant_hint(requested_tenant_id)
    if requested is None:
        return True
    if requested.lower() == returned_tenant_id.lower():
        return True

    requested_lower = requested.lower()
    verified_domains = {str(domain.get("name", "")).strip().lower() for domain in domains if domain.get("name")}
    return requested_lower in verified_domains


def _store_token_metadata(token_data: dict) -> dict:
    access_token = token_data["access_token"]
    claims = decode_access_token_claims(access_token)
    # Never fall back to DELEGATED_SCOPE_STRING — an absent scope field must not be
    # interpreted as "all admin scopes were granted".
    scope_string = token_data.get("scope") or ""
    if not scope_string:
        logger.warning(
            "oauth_token_missing_scope_field: 'scope' absent from token response; scopes derived only from JWT scp claim"
        )
    token_scopes = scope_string.split()

    logger.info(
        "oauth_token_claims %s",
        {
            "scp": claims.get("scp"),
            "roles": claims.get("roles"),
            "wids": claims.get("wids"),
            "scopes": claims.get("scp"),
            "has_policy_readwrite_authorization": (REQUIRED_AUTHORIZATION_POLICY_SCOPE in token_scopes),
            "has_user_auth_method_scope": ("UserAuthenticationMethod.Read.All" in token_scopes),
            "has_directory_read_all": ("Directory.Read.All" in token_scopes),
        },
    )

    return {
        "access_token": access_token,
        "refresh_token": token_data.get("refresh_token"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])).isoformat(),
        "expires_in": token_data["expires_in"],
        "scope": scope_string,
        "scopes": token_scopes,
        "token_type": token_data.get("token_type", "Bearer"),
        "tenant_id": claims.get("tid"),
        "claims": {
            "scp": claims.get("scp"),
            "roles": claims.get("roles"),
            "wids": claims.get("wids"),
            "tid": claims.get("tid"),
        },
    }


async def _oauth_user_can_claim_msp_tenant(
    *,
    access_token: str,
    oauth_user_oid: str,
) -> bool:
    # Delegates to the shared verifier so MSP connect and SMB onboarding
    # enforce identical tenant-admin role requirements.
    return await oauth_user_holds_tenant_admin_role(
        access_token=access_token,
        oauth_user_oid=oauth_user_oid,
    )


def _oauth_state_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.SESSION_SECRET, salt=MICROSOFT_OAUTH_STATE_SALT)


def _platform_user_lookup_id(user_id: str | uuid.UUID) -> uuid.UUID:
    try:
        return uuid.UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401,
            detail="User must be logged in before starting OAuth",
        ) from exc


def _get_platform_session_from_cookie(request: Request, db: Session) -> tuple[PlatformUser, dict]:
    token = request.cookies.get(settings.APP_AUTH_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=401,
            detail="User must be logged in before starting OAuth",
        )

    try:
        payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail="User must be logged in before starting OAuth",
        ) from exc

    user_id = payload.get("sub") or payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="User must be logged in before starting OAuth",
        )

    current_user = db.get(PlatformUser, _platform_user_lookup_id(user_id))
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail="User must be logged in before starting OAuth",
        )

    return current_user, payload


def get_current_user_from_cookie(request: Request, db: Session) -> PlatformUser:
    current_user, _payload = _get_platform_session_from_cookie(request, db)
    return current_user


def _encode_oauth_state(
    db: Session,
    intent: str,
    user_id: str | None = None,
    initiating_session_identifier: str | None = None,
    tenant_id: str | None = None,
    frontend_path: str | None = None,
) -> str:
    if intent not in {"smb_onboarding", "msp_connect", "preview", "cost_checker"}:
        raise HTTPException(status_code=400, detail="Invalid OAuth intent")

    nonce = uuid.uuid4().hex
    payload = {
        "csrf": secrets.token_urlsafe(32),
        "provider": "microsoft",
        "nonce": nonce,
        "intent": intent,
    }
    if intent == "msp_connect":
        if user_id is None:
            raise HTTPException(status_code=400, detail="msp_connect requires authenticated user")
        payload["user_id"] = str(user_id)

    normalized_tenant_id = _normalize_tenant_hint(tenant_id)
    if normalized_tenant_id is not None:
        payload["tenant_id"] = normalized_tenant_id
    if frontend_path:
        payload["frontend_path"] = frontend_path

    logger.debug("oauth_state_created intent=%s", intent)
    db.add(OAuthStateNonce(nonce=nonce, flow=intent))
    state = _oauth_state_serializer().dumps(payload)
    now = utc_now()
    db.add(
        PendingOAuthSession(
            state=state,
            initiating_user_id=uuid.UUID(str(user_id)) if user_id else None,
            initiating_session_identifier=initiating_session_identifier,
            intent=intent,
            expected_tenant_id=normalized_tenant_id,
            frontend_path=frontend_path,
            expires_at=now + timedelta(seconds=MICROSOFT_OAUTH_STATE_MAX_AGE_SECONDS),
        )
    )
    db.flush()

    return state


def _decode_oauth_state(db: Session, state: str) -> dict:
    try:
        payload = _oauth_state_serializer().loads(
            state,
            max_age=MICROSOFT_OAUTH_STATE_MAX_AGE_SECONDS,
        )
    except SignatureExpired as exc:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid") from exc
    except BadSignature as exc:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid") from exc

    csrf = payload.get("csrf")
    user_id = payload.get("user_id")
    provider = payload.get("provider")

    # Accept both the new "msp_connect" intent and the legacy "connect_tenant" label
    # so that in-flight states from old code aren't rejected.
    raw_intent = payload.get("intent") or payload.get("flow") or payload.get("action")
    if raw_intent == "connect_tenant":
        raw_intent = "msp_connect"

    if not isinstance(csrf, str) or len(csrf) < 20:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if provider != "microsoft":
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if raw_intent not in {"smb_onboarding", "msp_connect", "preview", "cost_checker"}:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if raw_intent == "msp_connect" and (user_id is None or not isinstance(user_id, str) or not user_id.strip()):
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")

    payload["intent"] = raw_intent  # normalise so the callback can read a single field

    # Single-use enforcement: claim the nonce atomically
    nonce = payload.get("nonce")
    logger.debug("oauth_state_validating intent=%s", payload.get("intent"))
    nonce_record = (
        db.query(OAuthStateNonce)
        .filter(
            OAuthStateNonce.nonce == nonce,
            OAuthStateNonce.used_at.is_(None),
        )
        .with_for_update()
        .one_or_none()
    )
    if nonce_record is None:
        logger.warning(
            "oauth_nonce_missing payload=%s",
            {
                "nonce": nonce,
                "provider": payload.get("provider"),
                "flow": payload.get("flow"),
                "action": payload.get("action"),
                "intent": payload.get("intent"),
                "user_id": payload.get("user_id"),
                "tenant_id": payload.get("tenant_id"),
            },
        )
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    nonce_record.used_at = utc_now()
    db.flush()

    return payload


# _decode_id_token_claims removed — use verify_microsoft_id_token() instead.
# That function fetches the tenant JWKS and verifies signature, aud, iss, and exp.


def _utc_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _claim_pending_oauth_session(
    *,
    db: Session,
    state: str,
    request: Request,
    state_payload: dict,
) -> PendingOAuthSession:
    pending = db.query(PendingOAuthSession).filter(PendingOAuthSession.state == state).with_for_update().one_or_none()
    if pending is None:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if pending.consumed_at is not None:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if _utc_aware(pending.expires_at) <= utc_now():
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if pending.intent != state_payload.get("intent"):
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")

    if pending.intent == "msp_connect":
        current_user, auth_payload = _get_platform_session_from_cookie(request, db)
        session_identifier = str(auth_payload.get("jti") or "").strip()
        if not session_identifier:
            raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
        if str(current_user.id) != str(pending.initiating_user_id):
            raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
        if session_identifier != pending.initiating_session_identifier:
            raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
        if str(state_payload.get("user_id") or "") != str(current_user.id):
            raise HTTPException(status_code=401, detail="OAuth session expired or invalid")

    pending.consumed_at = utc_now()
    db.flush()
    return pending


def _resolve_primary_domain(domains: list[dict]) -> str | None:
    for domain in domains:
        if domain.get("isDefault"):
            return domain.get("name")
    if domains:
        return domains[0].get("name")
    return None


def _issue_app_auth_response(
    *,
    user: PlatformUser,
    tenant: Tenant,
    tenant_ids: list[str],
    frontend_path: str = "/auth/callback",
) -> RedirectResponse:
    app_token = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        role=user.role,
        tenant_ids=tenant_ids,
    )
    response = RedirectResponse(
        url=f"{settings.FRONTEND_URL}{frontend_path}",
        status_code=302,
    )
    logger.info(
        "issuing_app_auth_cookie user_id=%s cookie=%s secure=%s samesite=%s frontend_path=%s",
        user.id,
        settings.APP_AUTH_COOKIE_NAME,
        True,
        "none",
        frontend_path,
    )
    response.set_cookie(
        key=settings.APP_AUTH_COOKIE_NAME,
        value=app_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=settings.APP_JWT_TTL_HOURS * 3600,
    )
    # Non-secret tenant hint for the frontend landing page (UUID only, 60s TTL)
    response.set_cookie(
        key="cl_post_oauth_tenant",
        value=str(tenant.id),
        httponly=False,
        secure=True,
        samesite="none",
        path="/",
        max_age=60,
    )
    return response


def _upsert_tenant_oauth_record(
    *,
    db: Session,
    tenant_id: str,
    stored_token: dict,
):
    expires_at = datetime.fromisoformat(stored_token["expires_at"])
    if expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    tenant_oauth = (
        db.query(TenantOAuth)
        .filter_by(
            tenant_id=tenant_id,
            provider="microsoft",
        )
        .one_or_none()
    )

    if tenant_oauth is None:
        tenant_oauth = TenantOAuth(
            tenant_id=tenant_id,
            provider="microsoft",
            access_token=encrypt_str(stored_token["access_token"]),
            refresh_token=(encrypt_str(stored_token["refresh_token"]) if stored_token.get("refresh_token") else None),
            expires_at=expires_at,
            scopes=stored_token.get("scopes", []),
        )
        db.add(tenant_oauth)
        return

    tenant_oauth.access_token = encrypt_str(stored_token["access_token"])
    tenant_oauth.refresh_token = (
        encrypt_str(stored_token["refresh_token"]) if stored_token.get("refresh_token") else None
    )
    tenant_oauth.expires_at = expires_at
    tenant_oauth.scopes = stored_token.get("scopes", [])


def _invalidate_existing_delegated_tokens(*, db: Session, tenant_id: str, tenant) -> None:
    tenant.last_delegated_auth_at = None
    tenant_oauth = (
        db.query(TenantOAuth)
        .filter_by(
            tenant_id=tenant_id,
            provider="microsoft",
        )
        .one_or_none()
    )
    if tenant_oauth is not None:
        db.delete(tenant_oauth)


def _stage_tenant_token(
    *,
    db: Session,
    tenant: Tenant,
    stored_token: dict,
    intent: str | None = None,
) -> None:
    # Preview and cost-checker flows must NEVER overwrite the tenant's
    # delegated OAuth token. These intents are read-only and frequently use
    # narrower scopes than the tenant's primary token; persisting them would
    # degrade subsequent admin operations for the legitimate OWNER. They may
    # also be initiated by users who are not the tenant owner.
    if intent in {"preview", "cost_checker"}:
        logger.info(
            "tenant_token_persist_skipped intent=%s tenant_id=%s",
            intent,
            tenant.id,
        )
        return

    token_tid = str(decode_access_token_claims(stored_token["access_token"]).get("tid") or "").strip()
    if not token_tid or token_tid != tenant.id:
        raise HTTPException(
            status_code=400,
            detail=(
                "Delegated access token tenant mismatch: " f"token.tid={token_tid or '<missing>'} tenant.id={tenant.id}"
            ),
        )

    tenant.last_delegated_auth_at = to_naive_utc(utc_now())
    _upsert_tenant_oauth_record(
        db=db,
        tenant_id=tenant.id,
        stored_token=stored_token,
    )
    db.add(tenant)


def _persist_tenant_token(
    *,
    db: Session,
    tenant: Tenant,
    stored_token: dict,
    intent: str | None = None,
) -> None:
    _stage_tenant_token(
        db=db,
        tenant=tenant,
        stored_token=stored_token,
        intent=intent,
    )
    db.commit()


def _load_pending_msp_session(
    *,
    db: Session,
    request: Request,
    session_id: str,
    require_unconfirmed: bool,
) -> tuple[PendingOAuthSession, PlatformUser]:
    try:
        pending_id = uuid.UUID(str(session_id))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Pending MSP connection not found") from exc

    pending = db.query(PendingOAuthSession).filter(PendingOAuthSession.id == pending_id).with_for_update().one_or_none()
    if pending is None or pending.intent != "msp_connect":
        raise HTTPException(status_code=404, detail="Pending MSP connection not found")
    if pending.consumed_at is None:
        raise HTTPException(status_code=409, detail="OAuth callback has not completed")
    if require_unconfirmed and pending.confirmed_at is not None:
        raise HTTPException(status_code=409, detail="Pending MSP connection already confirmed")
    if _utc_aware(pending.expires_at) <= utc_now():
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")

    current_user, auth_payload = _get_platform_session_from_cookie(request, db)
    session_identifier = str(auth_payload.get("jti") or "").strip()
    if not session_identifier:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if str(current_user.id) != str(pending.initiating_user_id):
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if session_identifier != pending.initiating_session_identifier:
        raise HTTPException(status_code=401, detail="OAuth session expired or invalid")
    if not isinstance(pending.callback_payload, dict):
        raise HTTPException(status_code=409, detail="MSP connection is incomplete")

    return pending, current_user


def _pending_msp_tenant_payload(pending: PendingOAuthSession) -> dict:
    payload = pending.callback_payload if isinstance(pending.callback_payload, dict) else {}
    tenant_payload = payload.get("tenant")
    if not isinstance(tenant_payload, dict):
        raise HTTPException(status_code=409, detail="MSP connection is incomplete")
    tenant_id = str(tenant_payload.get("tenant_id") or "").strip()
    if not tenant_id or tenant_id != pending.resolved_tenant_id:
        raise HTTPException(status_code=409, detail="MSP connection tenant mismatch")
    return tenant_payload


def _pending_msp_stored_token(pending: PendingOAuthSession) -> dict:
    payload = pending.callback_payload if isinstance(pending.callback_payload, dict) else {}
    staged_token = payload.get("stored_token")
    if not isinstance(staged_token, dict):
        raise HTTPException(status_code=409, detail="MSP connection is incomplete")
    # NOTE: no Policy.ReadWrite.Authorization gate here — see the callback's
    # equivalent note and docs/oauth-policy-authorization-scope-audit.md.
    return decrypt_token_dict(staged_token)


@router.get("/start")
def start_microsoft_oauth(
    request: Request,
    intent: str = Query(default="smb_onboarding"),
    force_consent: bool = Query(default=True),
    tenant_id: str | None = Query(default=None),
    frontend_path: str | None = Query(default=None),
    db: Session = Depends(get_sync_db),
):
    if intent not in {"smb_onboarding", "msp_connect", "preview", "cost_checker"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid intent. Must be 'smb_onboarding', 'msp_connect', 'preview', or 'cost_checker'",
        )

    current_user: PlatformUser | None = None
    initiating_session_identifier: str | None = None
    if intent == "msp_connect":
        # MSP connect always requires an authenticated session.
        current_user, auth_payload = _get_platform_session_from_cookie(request, db)
        initiating_session_identifier = str(auth_payload.get("jti") or "").strip() or None

    normalized_tenant_id = _normalize_tenant_hint(tenant_id)

    state = _encode_oauth_state(
        db,
        intent=intent,
        user_id=str(current_user.id) if current_user is not None else None,
        initiating_session_identifier=initiating_session_identifier,
        tenant_id=normalized_tenant_id,
        frontend_path=frontend_path,
    )

    db.commit()

    if intent == "preview":
        scope_string = PREVIEW_SCOPE_STRING
    elif intent == "cost_checker":
        scope_string = _COST_CHECKER_SCOPE_STRING
    else:
        scope_string = DELEGATED_SCOPE_STRING
    # Preview and cost-checker always force a fresh consent screen so Microsoft
    # re-evaluates the narrower read-only scope set. For full onboarding and MSP
    # connect, honor force_consent instead of always falling back to account-picker
    # behavior, otherwise the permissions page can be skipped entirely on tenants
    # where a prior grant already exists.
    prompt_value = "consent" if force_consent or intent in {"preview", "cost_checker"} else "select_account"
    params = {
        "client_id": str(settings.MICROSOFT_CLIENT_ID),
        "response_type": "code",
        "redirect_uri": str(settings.MICROSOFT_REDIRECT_URI),
        "response_mode": "query",
        "scope": scope_string,
        "prompt": prompt_value,
        "state": state,
    }

    authorize_url = _build_microsoft_authorize_url(normalized_tenant_id)
    return RedirectResponse(f"{authorize_url}?{urlencode(params)}")


@router.get("/adminconsent")
def start_microsoft_admin_consent(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["microsoft_admin_consent_state"] = state
    params = {
        "client_id": str(settings.MICROSOFT_CLIENT_ID),
        "redirect_uri": settings.microsoft_admin_consent_redirect_uri,
        "state": state,
    }
    return RedirectResponse(f"{settings.microsoft_admin_consent_url}?{urlencode(params)}")


@router.get("/adminconsent/callback")
def microsoft_admin_consent_callback(
    request: Request,
    tenant: str | None = Query(default=None),
    state: str | None = Query(default=None),
    admin_consent: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
):
    expected_state = request.session.pop("microsoft_admin_consent_state", None)
    if not expected_state or state != expected_state:
        raise HTTPException(status_code=400, detail="Invalid admin consent state")

    if error:
        raise HTTPException(
            status_code=400,
            detail={"error": error, "error_description": error_description},
        )

    return RedirectResponse(
        url=(
            f"{settings.FRONTEND_URL}/settings?"
            f"admin_consent={'granted' if admin_consent else 'missing'}&tenant={tenant or ''}"
        ),
        status_code=302,
    )


def _connect_error_redirect(code: str, message: str | None = None) -> RedirectResponse:
    """A friendly landing spot for any onboarding failure, instead of a raw
    backend JSON error. `/tenants` is where "Add Tenant" already lives, so
    it's the natural place for a user to land and try again.
    """
    params = {"connect_error": code}
    if message:
        params["connect_error_message"] = message
    return RedirectResponse(
        url=f"{settings.FRONTEND_URL}/tenants?{urlencode(params)}",
        status_code=302,
    )


async def _microsoft_oauth_callback_impl(
    request: Request,
    code: str,
    state: str,
    db: Session,
):
    state_payload = _decode_oauth_state(db, state)
    pending_session = _claim_pending_oauth_session(
        db=db,
        state=state,
        request=request,
        state_payload=state_payload,
    )
    # intent is normalised by _decode_oauth_state.
    intent = state_payload["intent"]
    requested_tenant_id = _normalize_tenant_hint(state_payload.get("tenant_id"))
    frontend_path = state_payload.get("frontend_path")

    token_url = _build_microsoft_token_url(requested_tenant_id)
    if intent == "preview":
        exchange_scope = PREVIEW_SCOPE_STRING
    elif intent == "cost_checker":
        exchange_scope = _COST_CHECKER_SCOPE_STRING
    else:
        exchange_scope = DELEGATED_SCOPE_STRING

    async with httpx.AsyncClient(timeout=10) as client:
        token_resp = await client.post(
            token_url,
            data={
                "client_id": str(settings.MICROSOFT_CLIENT_ID),
                "client_secret": str(settings.MICROSOFT_CLIENT_SECRET),
                "grant_type": "authorization_code",
                "code": str(code),
                "redirect_uri": str(settings.MICROSOFT_REDIRECT_URI),
                "scope": exchange_scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if token_resp.status_code != 200:
        logger.warning(
            "microsoft_token_exchange_failed status=%s",
            token_resp.status_code,
        )
        raise HTTPException(
            status_code=400,
            detail="Microsoft token exchange failed",
        )

    token_data = token_resp.json()
    stored_token = _store_token_metadata(token_data)
    if intent == "cost_checker":
        returned_scopes = {str(scope).strip() for scope in stored_token.get("scopes", []) if str(scope).strip()}
        expected_scopes = set(_COST_CHECKER_SCOPES)
        if returned_scopes and returned_scopes != expected_scopes:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Cost-checker requires exact read-only scopes: "
                    f"{sorted(expected_scopes)}; received {sorted(returned_scopes)}"
                ),
            )
        stored_token["scope"] = _COST_CHECKER_SCOPE_STRING
        stored_token["scopes"] = list(_COST_CHECKER_SCOPES)
    # Extract tid from the access token first; use it to fetch the correct JWKS
    # and to cross-verify the id_token belongs to the same tenant.
    azure_tenant_id = stored_token.get("claims", {}).get("tid")
    if not azure_tenant_id:
        raise HTTPException(status_code=400, detail="Unable to determine tenant ID from access token")
    # The demo tenant ID is reserved: a real sign-in must never create or attach it.
    from app.demo import DEMO_TENANT_ID

    if azure_tenant_id == DEMO_TENANT_ID:
        raise HTTPException(status_code=403, detail="reserved_demo_tenant")
    id_token_claims = {}
    if token_data.get("id_token"):
        id_token_claims = await verify_microsoft_id_token(
            token_data.get("id_token"),
            expected_tid=azure_tenant_id,
        )

    try:
        org_payload = await graph_get_with_token(
            stored_token["access_token"],
            "/organization",
            expected_tenant_id=azure_tenant_id,
        )
    except GraphBlockedError as exc:
        target_url = f"{settings.FRONTEND_URL}/settings?" + urlencode(
            {"status": exc.status, "reason": exc.reason, "message": exc.message}
        )
        return RedirectResponse(url=target_url, status_code=302)

    tenant_data = org_payload["value"][0]
    tenant_identifier = azure_tenant_id or tenant_data["id"]
    if tenant_identifier != azure_tenant_id:
        raise HTTPException(status_code=400, detail="Tenant mismatch during OAuth")
    domains = tenant_data.get("verifiedDomains", [])

    if not _tenant_matches_request(requested_tenant_id, tenant_identifier, domains):
        logger.warning(
            "Token tenant mismatch: expected %s, got %s",
            requested_tenant_id,
            tenant_identifier,
        )
        raise HTTPException(status_code=400, detail="Tenant mismatch during OAuth")

    primary_domain = _resolve_primary_domain(domains)
    me_claims = {}
    if intent == "cost_checker":
        me_claims = await graph_get_with_token(
            stored_token["access_token"],
            "/me?$select=id,displayName,userPrincipalName,mail",
            expected_tenant_id=azure_tenant_id,
        )
    oauth_user_oid = str(
        id_token_claims.get("oid")
        or me_claims.get("id")
        or decode_access_token_claims(stored_token["access_token"]).get("oid")
        or ""
    ).strip()

    # ------------------------------------------------------------------ #
    #  PREVIEW — read-only login; user gets READ_ONLY tenant access       #
    # ------------------------------------------------------------------ #
    if intent in {"preview", "cost_checker"}:
        # Scope-based rejection is not viable: when an app has tenant-wide admin consent,
        # Microsoft encodes all consented scopes into the JWT scp claim regardless of
        # what the current request asked for. Write-access restriction is enforced at the
        # application layer via UserTenantAccess.role = READ_ONLY on every write endpoint.
        jwt_claims = decode_access_token_claims(stored_token["access_token"])
        jwt_scopes = set((jwt_claims.get("scp") or "").split())
        logger.debug(
            "preview_scope_audit %s",
            {
                "raw_scp": jwt_claims.get("scp"),
                "jwt_scopes": sorted(jwt_scopes),
                "write_scopes_present": sorted(jwt_scopes & WRITE_SCOPES),
            },
        )

        preview_tenant_id = str(id_token_claims.get("tid") or tenant_identifier or "").strip()
        preview_user_oid = str(id_token_claims.get("oid") or me_claims.get("id") or "").strip()
        preview_email = (
            str(
                id_token_claims.get("email")
                or id_token_claims.get("preferred_username")
                or id_token_claims.get("upn")
                or me_claims.get("mail")
                or me_claims.get("userPrincipalName")
                or ""
            )
            .strip()
            .lower()
        )
        preview_name = str(
            id_token_claims.get("name") or me_claims.get("displayName") or tenant_data.get("displayName") or ""
        ).strip()

        if not preview_tenant_id:
            raise HTTPException(status_code=400, detail="Unable to determine tenant ID")
        if not preview_user_oid:
            raise HTTPException(status_code=400, detail="Unable to determine Microsoft user ID")
        if not preview_email:
            raise HTTPException(status_code=400, detail="Unable to determine Microsoft user email")

        tenant = get_or_create_tenant(
            db=db,
            tenant_id=preview_tenant_id,
            name=tenant_data.get("displayName") or preview_name or "Microsoft Tenant",
            domain=primary_domain,
            provider="microsoft",
            organization_id=None,
        )
        stored_token["tenant_id"] = tenant.id
        _persist_tenant_token(
            db=db,
            tenant=tenant,
            stored_token=stored_token,
            intent=intent,
        )

        platform_user = upsert_oauth_platform_user(
            db=db,
            tenant=tenant,
            email=preview_email,
            oid=preview_user_oid,
        )

        # Gate: only allow access if the user is already authorized or is the tenant OWNER.
        # Never elevate an existing OWNER/ADMIN to READ_ONLY.
        existing_access = (
            db.query(UserTenantAccess)
            .filter(
                UserTenantAccess.user_id == platform_user.id,
                UserTenantAccess.tenant_id == tenant.id,
            )
            .one_or_none()
        )
        if existing_access is None:
            owner_access = (
                db.query(UserTenantAccess)
                .filter(
                    UserTenantAccess.tenant_id == tenant.id,
                    UserTenantAccess.role == UserTenantRole.OWNER,
                )
                .first()
            )
            if owner_access is not None:
                owner_user = db.get(PlatformUser, owner_access.user_id)
                # Identity check uses oid (immutable Entra object ID) rather
                # than email. Email is mutable in Microsoft Entra and would
                # allow an attacker who re-assigns the owner's UPN/email on
                # a tenant they control to impersonate the owner.
                if (
                    owner_user is None
                    or not owner_user.oid
                    or not preview_user_oid
                    or owner_user.oid != preview_user_oid
                ):
                    raise HTTPException(
                        status_code=403,
                        detail="Access denied. Contact your administrator to be granted access.",
                    )
            get_or_create_user_tenant_access(
                db=db,
                user_id=platform_user.id,
                tenant_id=tenant.id,
                role=UserTenantRole.READ_ONLY,
            )

        if tenant.organization_id is None and platform_user.organization_id is not None:
            tenant.organization_id = platform_user.organization_id

        db.commit()
        db.refresh(platform_user)

        tenant_ids = [
            str(row[0])
            for row in db.query(UserTenantAccess.tenant_id).filter(UserTenantAccess.user_id == platform_user.id).all()
        ]

        if intent == "preview":
            async with scan_ephemeral_token(str(tenant.id), stored_token["access_token"]):
                await run_scan(str(tenant.id))
        return _issue_app_auth_response(
            user=platform_user,
            tenant=tenant,
            tenant_ids=tenant_ids,
            frontend_path=frontend_path or ("/cost-checker/callback" if intent == "cost_checker" else "/auth/callback"),
        )

    # ------------------------------------------------------------------ #
    #  SMB ONBOARDING — create or log in user, issue fresh session        #
    # ------------------------------------------------------------------ #
    if intent == "smb_onboarding":
        smb_tenant_id = str(id_token_claims.get("tid") or tenant_identifier or "").strip()
        smb_user_oid = str(id_token_claims.get("oid") or "").strip()
        smb_email = (
            str(
                id_token_claims.get("email")
                or id_token_claims.get("preferred_username")
                or id_token_claims.get("upn")
                or ""
            )
            .strip()
            .lower()
        )
        smb_name = str(id_token_claims.get("name") or tenant_data.get("displayName") or "").strip()

        if not smb_tenant_id:
            raise HTTPException(status_code=400, detail="Unable to determine tenant ID")
        if not smb_user_oid:
            raise HTTPException(status_code=400, detail="Unable to determine Microsoft user ID")
        if not smb_email:
            raise HTTPException(status_code=400, detail="Unable to determine Microsoft user email")

        tenant = db.get(Tenant, smb_tenant_id)
        owner_user = None
        if tenant is not None:
            # Only block if there is already an SMB_OWNER — MSP-only associations do not block SMB onboarding.
            smb_owner_access = (
                db.query(UserTenantAccess)
                .filter(
                    UserTenantAccess.tenant_id == tenant.id,
                    UserTenantAccess.access_type == TenantAccessType.SMB_OWNER,
                )
                .order_by(UserTenantAccess.created_at.asc())
                .first()
            )
            if smb_owner_access is not None:
                owner_user = db.get(PlatformUser, smb_owner_access.user_id)
            # Identity check uses oid (immutable Entra object ID). Email is
            # mutable in Entra and MUST NOT be used for identity comparison —
            # comparing by email would let an attacker whose Microsoft account
            # carries the same email claim silently inherit an existing owner.
            if owner_user is not None:
                if not owner_user.oid:
                    # Legacy owner row with no oid captured. Identity cannot be
                    # verified safely via email — require manual migration by
                    # support. Silent email-based identity merges are disallowed.
                    logger.warning(
                        "smb_onboarding_legacy_owner_no_oid tenant_id=%s owner_user_id=%s",
                        smb_tenant_id,
                        owner_user.id,
                    )
                    raise HTTPException(
                        status_code=409,
                        detail=("Tenant owner requires identity migration. " "Contact support."),
                    )
                if not smb_user_oid or owner_user.oid != smb_user_oid:
                    raise HTTPException(
                        status_code=403,
                        detail="This tenant is already owned. Contact your administrator.",
                    )

        # First-owner claim must be a tenant admin (parity with MSP connect).
        # A returning owner (owner_user matched by oid above) is not re-checked.
        # Verify BEFORE persisting any delegated token or granting OWNER so a
        # non-admin leaves no trace and is denied — fail closed.
        if owner_user is None:
            if not await oauth_user_holds_tenant_admin_role(
                access_token=stored_token["access_token"],
                oauth_user_oid=smb_user_oid,
            ):
                logger.warning(
                    "smb_onboarding_denied_not_admin tenant_id=%s",
                    smb_tenant_id,
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Tenant onboarding requires a Global Administrator or "
                        "Privileged Role Administrator on this Microsoft tenant."
                    ),
                )

        tenant = get_or_create_tenant(
            db=db,
            tenant_id=smb_tenant_id,
            name=tenant_data.get("displayName") or smb_name or "Microsoft Tenant",
            domain=primary_domain,
            provider="microsoft",
            organization_id=(owner_user.organization_id if owner_user is not None else None),
        )
        stored_token["tenant_id"] = tenant.id
        _persist_tenant_token(
            db=db,
            tenant=tenant,
            stored_token=stored_token,
            intent=intent,
        )

        platform_user = owner_user or upsert_oauth_platform_user(
            db=db,
            tenant=tenant,
            email=smb_email,
            oid=smb_user_oid,
        )
        # Never mutate oid on an existing PlatformUser row — identity is
        # bound to the oid captured at account creation. Legacy rows without
        # oid are rejected above and must be migrated out-of-band.
        get_or_create_user_tenant_access(
            db=db,
            user_id=platform_user.id,
            tenant_id=tenant.id,
            role=UserTenantRole.OWNER,
            organization_id=platform_user.organization_id,
            access_type=TenantAccessType.SMB_OWNER,
        )
        if tenant.organization_id is None and platform_user.organization_id is not None:
            tenant.organization_id = platform_user.organization_id
        db.commit()
        db.refresh(platform_user)

        tenant_ids = [
            str(row[0])
            for row in db.query(UserTenantAccess.tenant_id).filter(UserTenantAccess.user_id == platform_user.id).all()
        ]

        await run_scan(str(tenant.id))
        return _issue_app_auth_response(
            user=platform_user,
            tenant=tenant,
            tenant_ids=tenant_ids,
        )

    # ------------------------------------------------------------------ #
    #  MSP CONNECT — attach tenant to existing MSP org, keep session      #
    # ------------------------------------------------------------------ #
    platform_user = db.get(PlatformUser, pending_session.initiating_user_id)
    if platform_user is None:
        raise HTTPException(status_code=401, detail="OAuth initiator user not found")

    # MSP_CONNECT hijack prevention: the OAuth-completing user MUST be a
    # Global Admin or Privileged Role Administrator on the tenant being
    # attached. Without this check, any logged-in MSP user could attach a
    # tenant they do not control (brand-new tenants or tenants inside their
    # own org). Verify unconditionally against the tenant resolved from the
    # delegated access token.
    can_connect = await _oauth_user_can_claim_msp_tenant(
        access_token=stored_token["access_token"],
        oauth_user_oid=oauth_user_oid,
    )
    if not can_connect:
        logger.warning(
            "msp_connect_denied_not_admin tenant_id=%s user_id=%s user_org=%s",
            tenant_identifier,
            platform_user.id,
            platform_user.organization_id,
        )
        return RedirectResponse(
            url=(f"{settings.FRONTEND_URL}/tenants?" + urlencode({"error": "tenant_admin_required"})),
            status_code=302,
        )

    existing_tenant = db.get(Tenant, tenant_identifier)
    if existing_tenant is not None:
        tenant_org_id = existing_tenant.organization_id
        if tenant_org_id is not None and tenant_org_id != platform_user.organization_id:
            # Tenant already belongs to a different organisation. Even with
            # admin rights on the tenant, we do NOT overwrite
            # tenant.organization_id — ownership is stable — we only grant
            # MSP_MANAGER access to the attaching user below.
            logger.info(
                "msp_connect_cross_org tenant_id=%s tenant_org=%s msp_org=%s",
                tenant_identifier,
                tenant_org_id,
                platform_user.organization_id,
            )
        # Same org (or no org yet) — idempotent; fall through to upsert below.

    # NOTE: connecting a tenant no longer requires Policy.ReadWrite.Authorization
    # as a blanket gate. That permission backs one specific control
    # (IDENTITY_USER_CONSENT_POLICY), whose own execution-time permission check
    # (remediation_execution_service.py) already protects it independently.
    # See docs/oauth-policy-authorization-scope-audit.md.

    tenant_org_id = existing_tenant.organization_id if existing_tenant is not None else None
    pending_session.resolved_tenant_id = tenant_identifier
    pending_session.callback_payload = {
        "tenant": {
            "tenant_id": tenant_identifier,
            "tenant_name": tenant_data.get("displayName"),
            "domain": primary_domain,
            "provider": "microsoft",
            "existing_organization_id": str(tenant_org_id) if tenant_org_id is not None else None,
            "msp_organization_id": str(platform_user.organization_id),
        },
        "stored_token": encrypt_token_dict({**stored_token, "tenant_id": tenant_identifier}),
        "oauth_user_oid": oauth_user_oid,
        "frontend_path": frontend_path,
    }
    db.add(pending_session)
    db.commit()

    logger.info(
        "msp_connect_confirmation_staged user_id=%s tenant_id=%s org_id=%s pending_session_id=%s",
        platform_user.id,
        tenant_identifier,
        platform_user.organization_id,
        pending_session.id,
    )
    return RedirectResponse(
        url=(f"{settings.FRONTEND_URL}/msp/confirm-tenant?" + urlencode({"session_id": str(pending_session.id)})),
        status_code=302,
    )


@router.get("/callback")
async def microsoft_oauth_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
    db: Session = Depends(get_sync_db),
):
    # Microsoft omits `code` entirely and sends `error` instead whenever the
    # user cancels consent, an org policy blocks the app, or any other
    # Microsoft-side failure occurs before a code could be issued. This must
    # be checked before anything requires `code`/`state`, or FastAPI's own
    # request validation rejects the request with a bare 422 before this
    # function body ever runs.
    if error:
        return _connect_error_redirect(
            code="cancelled" if error == "access_denied" else "microsoft_error",
            message=error_description,
        )
    if not code or not state:
        return _connect_error_redirect(code="missing_parameters")

    try:
        return await _microsoft_oauth_callback_impl(
            request=request,
            code=code,
            state=state,
            db=db,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else "Connection failed. Please try again."
        logger.warning("microsoft_oauth_callback_failed status=%s detail=%s", exc.status_code, detail)
        return _connect_error_redirect(code="connection_failed", message=detail)


@router.get("/msp-connect/pending/{session_id}", response_model=MspConnectPendingResponse)
def get_pending_msp_connect(
    session_id: str,
    request: Request,
    db: Session = Depends(get_sync_db),
):
    pending, _platform_user = _load_pending_msp_session(
        db=db,
        request=request,
        session_id=session_id,
        require_unconfirmed=False,
    )
    tenant_payload = _pending_msp_tenant_payload(pending)
    return MspConnectPendingResponse(
        session_id=str(pending.id),
        tenant_id=str(tenant_payload["tenant_id"]),
        tenant_name=tenant_payload.get("tenant_name"),
        domain=tenant_payload.get("domain"),
        existing_organization_id=tenant_payload.get("existing_organization_id"),
        msp_organization_id=tenant_payload.get("msp_organization_id"),
    )


@router.post("/msp-connect/confirm")
async def confirm_msp_connect(
    payload: MspConnectConfirmRequest,
    request: Request,
    db: Session = Depends(get_sync_db),
):
    pending, platform_user = _load_pending_msp_session(
        db=db,
        request=request,
        session_id=payload.session_id,
        require_unconfirmed=True,
    )
    tenant_payload = _pending_msp_tenant_payload(pending)
    stored_token = _pending_msp_stored_token(pending)

    tenant_id = str(tenant_payload["tenant_id"])
    tenant = get_or_create_tenant(
        db=db,
        tenant_id=tenant_id,
        name=tenant_payload.get("tenant_name") or "Microsoft Tenant",
        domain=tenant_payload.get("domain"),
        provider=tenant_payload.get("provider") or "microsoft",
        organization_id=platform_user.organization_id,
    )
    if tenant.organization_id is None and platform_user.organization_id is not None:
        tenant.organization_id = platform_user.organization_id

    stored_token["tenant_id"] = tenant.id
    _stage_tenant_token(
        db=db,
        tenant=tenant,
        stored_token=stored_token,
        intent="msp_connect",
    )
    get_or_create_user_tenant_access(
        db=db,
        user_id=platform_user.id,
        tenant_id=tenant.id,
        role=UserTenantRole.OWNER,
        organization_id=platform_user.organization_id,
        access_type=TenantAccessType.MSP_MANAGER,
    )
    pending.confirmed_at = utc_now()
    db.add(pending)
    db.commit()

    existing_org_id = tenant_payload.get("existing_organization_id")
    if existing_org_id and existing_org_id != str(platform_user.organization_id):
        log_audit_event(
            db=db,
            tenant_id=tenant.id,
            action="msp_tenant_connected",
            actor=platform_user.email,
            target=tenant.id,
            status="SUCCESS",
            reason=None,
            details={
                "msp_org_id": str(platform_user.organization_id),
                "tenant_id": str(tenant.id),
                "pending_session_id": str(pending.id),
            },
        )

    logger.info(
        "msp_connect tenant confirmed user_id=%s tenant_id=%s org_id=%s pending_session_id=%s",
        platform_user.id,
        tenant.id,
        platform_user.organization_id,
        pending.id,
    )

    await run_scan(str(tenant.id))
    return {"status": "tenant_attached", "tenant_id": tenant.id}
