"""
Email verification tokens for password-signup flow (SMB/MSP signup).

Tokens are short-lived JWTs scoped to a single purpose ("email_verify").
They cannot be confused with session tokens because the decoder enforces
the purpose claim.

Sending goes through Resend — the same provider and pattern used everywhere
else in this codebase (see notification_dispatcher.py, support_notification_service.py).
"""

import hashlib as _hashlib
import logging
import uuid
from datetime import timedelta

import httpx
import jwt

from app.config import settings
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)

EMAIL_VERIFY_PURPOSE = "email_verify"
EMAIL_VERIFY_TTL_HOURS = 24


def create_email_verification_token(user_id) -> str:
    payload = {
        "sub": str(user_id),
        "user_id": str(user_id),
        "purpose": EMAIL_VERIFY_PURPOSE,
        "jti": str(uuid.uuid4()),
        "exp": utc_now() + timedelta(hours=EMAIL_VERIFY_TTL_HOURS),
    }
    return jwt.encode(
        payload,
        settings.APP_JWT_SECRET,
        algorithm=settings.APP_JWT_ALGORITHM,
    )


def decode_email_verification_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        settings.APP_JWT_SECRET,
        algorithms=[settings.APP_JWT_ALGORITHM],
    )
    if payload.get("purpose") != EMAIL_VERIFY_PURPOSE:
        raise ValueError("Token is not an email verification token")
    return payload


def send_verification_email(email: str, token: str) -> None:
    """
    Send the account-verification email via Resend.

    Sync (not async) — the signup route (signup_password) is a sync FastAPI
    endpoint using the sync DB session, so this keeps the same calling
    convention rather than forcing the whole route to become async.

    Never raises: signup has already succeeded and committed by the time this
    is called. A Resend outage should not turn a successful signup into a
    500 the user can't recover from — it's logged instead, same failure mode
    as every other best-effort delivery path in this codebase.
    """
    base = str(getattr(settings, "FRONTEND_URL", "") or "").rstrip("/") or "http://localhost:3000"
    url = f"{base}/verify-email?token={token}"

    if not settings.RESEND_API_KEY:
        logger.info("verification_email_resend_not_configured email_recipient_set=%s", bool(email))
        print(f"[DEV] Verification URL for {email}: {url}", flush=True)
        return

    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": f"Cloud Locksmith <noreply@{settings.EMAIL_FROM_DOMAIN}>",
                "to": [email],
                "subject": "Verify your Cloud Locksmith account",
                "text": (
                    f"Welcome to Cloud Locksmith.\n\n"
                    f"Verify your email to activate your account:\n{url}\n\n"
                    f"This link expires in {EMAIL_VERIFY_TTL_HOURS} hours.\n\n"
                    f"If you didn't request this, you can ignore this email."
                ),
            },
            timeout=10,
        )
        response.raise_for_status()
        logger.info("verification_email_dispatched email_recipient_set=%s", bool(email))
    except Exception:
        logger.exception("verification_email_send_failed email_recipient_set=%s", bool(email))


def _token_used_key(token: str) -> str:
    """Hash the token so we never store the raw credential in Redis."""
    digest = _hashlib.sha256(token.encode()).hexdigest()
    return f"email_verify_used:{digest}"


def is_verification_token_used(token: str) -> bool:
    """Return True if this token has already been consumed."""
    try:
        from app.core.redis_client import redis_client

        return redis_client.exists(_token_used_key(token)) == 1
    except Exception:
        # Redis unavailable — fail open: better to allow re-verification
        # than to permanently lock a user out.
        return False


_EMAIL_VERIFY_TTL_SECONDS = EMAIL_VERIFY_TTL_HOURS * 3600  # 86400


def mark_verification_token_used(token: str) -> None:
    """Mark a verification token as consumed; TTL matches the JWT lifetime."""
    try:
        from app.core.redis_client import redis_client

        key = _token_used_key(token)
        redis_client.set(key, "1", ex=_EMAIL_VERIFY_TTL_SECONDS)  # 24 h, matches email verification token TTL
    except Exception:
        pass
