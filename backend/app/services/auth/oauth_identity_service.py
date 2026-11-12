import hashlib
import logging
import secrets

from fastapi import HTTPException

from app.db.models.organization import Organization, OrganizationMode
from app.db.models.platform_user import PlatformUser
from app.services.auth.password import hash_password
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)


def _hash_email_for_log(email: str) -> str:
    """Stable, non-reversible identifier for email-collision telemetry."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]


def upsert_oauth_platform_user(
    *,
    db,
    tenant,
    email: str,
    oid: str | None = None,
    role: str = "ADMIN",
):
    """
    Resolve an OAuth-authenticated identity to a PlatformUser.

    Identity is based solely on the immutable Microsoft Entra object ID (oid).
    Email is NEVER used to match an existing user — email is mutable in Entra
    and non-unique across tenants, so an email-based silent merge would enable
    account takeover of password-signup users whose email happens to match an
    attacker-controlled Microsoft identity.

    - If a PlatformUser with the given oid exists, return it.
    - If the email is already held by an UNVERIFIED password-signup row, that
      row is treated as squatting (anyone could have created it without
      proving control of the email) — it is deleted and OAuth proceeds.
    - If the email is already held by a verified password user OR a different
      OAuth identity, reject with HTTP 409 — silent merges are not permitted.
    - Otherwise, create a fresh PlatformUser bound to the provided oid.
    """
    normalized_email = email.strip().lower()
    normalized_oid = (oid or "").strip() or None

    if not normalized_oid:
        raise HTTPException(
            status_code=400,
            detail="Microsoft identity (oid) is required for OAuth sign-in",
        )

    user = db.query(PlatformUser).filter(PlatformUser.oid == normalized_oid).one_or_none()

    if user is not None:
        # Existing oid match — do not mutate identity-bearing fields.
        # If they were marked unverified for any reason, OAuth proves
        # control of the email so we can mark them verified.
        if user.verified_at is None:
            user.verified_at = utc_now()
            db.flush()
        return user

    # No oid match: handle the email-collision case.
    existing_email = db.query(PlatformUser).filter(PlatformUser.email == normalized_email).one_or_none()
    if existing_email is not None:
        is_squatted_password_row = (
            existing_email.auth_provider == "password"
            and existing_email.verified_at is None
            and existing_email.oid is None
        )
        if is_squatted_password_row:
            # The row was created via /auth/signup-password but the email
            # was never verified — anyone could have submitted that form.
            # Microsoft now proves control of the same address, so the
            # password row is fraudulent. Drop it and let OAuth proceed.
            logger.warning(
                "oauth_squatting_row_evicted email_hash=%s squatted_user_id=%s",
                _hash_email_for_log(normalized_email),
                existing_email.id,
            )
            db.delete(existing_email)
            db.flush()
        else:
            logger.warning(
                "oauth_identity_email_collision email_hash=%s incoming_oid_set=%s "
                "existing_user_id=%s existing_provider=%s existing_oid_set=%s "
                "existing_verified=%s",
                _hash_email_for_log(normalized_email),
                bool(normalized_oid),
                existing_email.id,
                existing_email.auth_provider,
                bool(existing_email.oid),
                existing_email.verified_at is not None,
            )
            raise HTTPException(
                status_code=409,
                detail=("Email is already registered. Please sign in using the " "original login method."),
            )

    organization = Organization(
        name=f"{normalized_email.split('@', 1)[0] or 'Cloud Locksmith'} Organization",
        mode=OrganizationMode.SINGLE,
    )
    db.add(organization)
    db.flush()
    user = PlatformUser(
        email=normalized_email,
        oid=normalized_oid,
        # OAuth users have no usable password. We still write a random
        # high-entropy hash so the row passes the password_required_check
        # constraint on environments where it was applied to all rows.
        password_hash=hash_password(secrets.token_urlsafe(32)),
        auth_provider="microsoft",
        verified_at=utc_now(),
        role=role,
        organization_id=organization.id,
    )
    db.add(user)
    db.flush()
    return user
