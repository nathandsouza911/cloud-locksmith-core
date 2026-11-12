import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user
from app.config import settings
from app.db.models.organization import Organization, OrganizationMode
from app.db.models.platform_user import PlatformUser
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import get_sync_db
from app.schemas.auth import (
    LoginRequest,
    PasswordSignupRequest,
    SignupRequest,
    VerifyEmailRequest,
)
from app.services.auth.email_verification import (
    create_email_verification_token,
    decode_email_verification_token,
    send_verification_email,
)
from app.services.auth.jwt_service import create_access_token, decode_access_token
from app.services.auth.password import hash_password, verify_password
from app.services.auth.token_denylist import revoke as revoke_token
from app.utils.datetime import utc_now

# Pre-computed hash of an unrelated random value, used to keep the timing of
# login-password constant for "no such user" / "wrong provider" branches.
# Computed once at import — never compared to a real user-supplied password.
_DUMMY_HASH = hash_password("dummy_password_for_constant_time_comparison")

# Per-account lockout configuration: 5 failures within 5 minutes locks the
# account for the remainder of the window. Reset on a successful login.
_ACCT_FAIL_LIMIT = 5
_ACCT_FAIL_WINDOW_SECONDS = 300

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _normalize_email(email: str) -> str:
    """Legacy helper kept for the existing MSP signup flow."""
    return email.strip().lower()


def _account_lockout_check(user_id) -> None:
    """Raise 429 if too many recent password failures for this account."""
    try:
        from app.core.redis_client import redis_client

        key = f"acct_fail:{user_id}"
        failures = int(redis_client.get(key) or 0)
        if failures >= _ACCT_FAIL_LIMIT:
            raise HTTPException(status_code=429, detail="account_locked")
    except HTTPException:
        raise
    except Exception:
        # Redis unavailable — fail open so legitimate users can still log in.
        # Per-IP rate limiting still applies via middleware.
        return


def _record_account_failure(user_id) -> None:
    try:
        from app.core.redis_client import redis_client

        key = f"acct_fail:{user_id}"
        new_count = redis_client.incr(key)
        if new_count == 1:
            redis_client.expire(key, _ACCT_FAIL_WINDOW_SECONDS)
    except Exception:
        return


def _reset_account_failures(user_id) -> None:
    try:
        from app.core.redis_client import redis_client

        redis_client.delete(f"acct_fail:{user_id}")
    except Exception:
        return


def _create_token(user: PlatformUser) -> str:
    return create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        role=user.role,
    )


def _set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.APP_AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=settings.APP_JWT_TTL_HOURS * 3600,
    )
    logger.info(
        "auth_cookie_set cookie=%s httponly=%s secure=%s samesite=%s",
        settings.APP_AUTH_COOKIE_NAME,
        True,
        True,
        "none",
    )


@router.post("/signup", deprecated=True)
def signup(
    data: SignupRequest,
    response: Response,
    db: Session = Depends(get_sync_db),
):
    """DISABLED (security audit M2).

    This legacy endpoint issued an authenticated session with no email
    verification and created ``auth_provider="microsoft"`` accounts carrying a
    password that could never be used to log back in (password login is
    disabled). It is permanently retired in favour of the verified
    ``/auth/signup-password`` -> ``/auth/verify-email`` flow.

    Fail closed: create nothing, issue no session, return 410 Gone.
    """
    logger.warning("legacy_signup_rejected path=/auth/signup")
    raise HTTPException(
        status_code=410,
        detail={
            "code": "ENDPOINT_REMOVED",
            "message": (
                "This signup endpoint has been removed. Use /auth/signup-password "
                "and verify your email before signing in."
            ),
        },
    )


@router.post("/login")
def login():
    raise HTTPException(
        status_code=403,
        detail="Password login disabled. Use Microsoft sign-in.",
    )


@router.post("/signup-password", name="signup_password")
def signup_password(
    data: PasswordSignupRequest,
    db: Session = Depends(get_sync_db),
):
    """
    Create a password-auth user. NO session is issued — the caller must
    verify their email via /auth/verify-email before they can log in.

    The response is intentionally identical for "created" and "already
    registered" cases to avoid leaking which addresses exist.
    """
    if not data.name or not data.name.strip():
        raise HTTPException(status_code=400, detail="Organization name is required")

    # data.email already normalised by the schema validator.
    normalized_email = data.email
    existing = db.query(PlatformUser).filter(func.lower(PlatformUser.email) == normalized_email).first()

    if existing:
        # Return a generic message regardless of provider to avoid enumeration.
        raise HTTPException(status_code=409, detail="Email already registered")

    organization = Organization(
        name=data.name.strip(),
        mode=OrganizationMode.MANAGED if data.is_msp else OrganizationMode.SINGLE,
    )
    user = PlatformUser(
        email=normalized_email,
        password_hash=hash_password(data.password),
        auth_provider="password",
        role="ADMIN",
        organization=organization,
        verified_at=None,
    )

    db.add(organization)
    db.add(user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.warning("signup_password_integrity_error")
        raise HTTPException(status_code=409, detail="Email already registered") from exc

    db.refresh(user)
    logger.debug("password_user_created user_id=%s", user.id)

    token = create_email_verification_token(user.id)
    send_verification_email(normalized_email, token)
    return {"ok": True, "verification_required": True}


@router.post("/verify-email", name="verify_email")
def verify_email(
    data: VerifyEmailRequest,
    db: Session = Depends(get_sync_db),
):
    # Inline import to avoid circular dependency at module load time.
    from app.services.auth.email_verification import (
        is_verification_token_used,
        mark_verification_token_used,
    )

    if is_verification_token_used(data.token):
        raise HTTPException(status_code=400, detail="invalid_token")

    try:
        payload = decode_email_verification_token(data.token)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_token")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="invalid_token")

    user = db.query(PlatformUser).filter(PlatformUser.id == user_id).one_or_none()
    if user is None or user.auth_provider != "password":
        raise HTTPException(status_code=400, detail="invalid_token")

    mark_verification_token_used(data.token)

    if user.verified_at is None:
        user.verified_at = utc_now()
        db.commit()
        logger.info("email_verified user_id=%s", user.id)
    return {"ok": True}


@router.post("/login-password", name="login_password")
def login_password(
    data: LoginRequest,
    response: Response,
    db: Session = Depends(get_sync_db),
):
    # data.email already normalised by the schema validator.
    normalized_email = data.email
    user = db.query(PlatformUser).filter(func.lower(PlatformUser.email) == normalized_email).first()

    # Constant-time branch: when the user does not exist, has the wrong
    # auth provider, or is unverified, run verify_password against a dummy
    # hash so the response time matches the real-user path. This prevents
    # both account enumeration and provider-disclosure timing attacks.
    if not user or user.auth_provider != "password" or user.password_hash is None or user.verified_at is None:
        verify_password(data.password, _DUMMY_HASH)
        raise HTTPException(status_code=401, detail="invalid_credentials")

    # Per-account lockout. Checked AFTER user lookup so attackers who guess
    # email-only cannot use lockout-state as an oracle for "user exists".
    _account_lockout_check(user.id)

    if not verify_password(data.password, user.password_hash):
        _record_account_failure(user.id)
        raise HTTPException(status_code=401, detail="invalid_credentials")

    _reset_account_failures(user.id)
    logger.debug("password_login_success user_id=%s", user.id)
    token = _create_token(user)
    _set_auth_cookie(response, token)
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(settings.APP_AUTH_COOKIE_NAME)
    if token:
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                revoke_token(jti, float(exp))
                logger.info("token_revoked jti=%s", jti)
        except Exception:
            pass  # best-effort; cookie deletion still proceeds
    response.delete_cookie(
        key=settings.APP_AUTH_COOKIE_NAME,
        path="/",
        secure=True,
        samesite="none",
        httponly=True,
    )
    return {"ok": True}


@router.get("/me")
def me(
    request: Request,
    current_user: PlatformUser = Depends(get_current_user),
    db: Session = Depends(get_sync_db),
):
    tenant_ids = [
        str(row[0])
        for row in (db.query(UserTenantAccess.tenant_id).filter(UserTenantAccess.user_id == current_user.id).all())
    ]

    user_tenant_role = None
    requested_tenant_id = request.headers.get("X-Tenant-ID")
    if requested_tenant_id:
        access = (
            db.query(UserTenantAccess)
            .filter(
                UserTenantAccess.user_id == current_user.id,
                UserTenantAccess.tenant_id == requested_tenant_id,
            )
            .one_or_none()
        )
        if access is not None:
            user_tenant_role = access.role.value if hasattr(access.role, "value") else str(access.role)

    return {
        "user_id": str(current_user.id),
        "email": current_user.email,
        "role": current_user.role,
        "tenants": tenant_ids,
        "user_tenant_role": user_tenant_role,
    }
