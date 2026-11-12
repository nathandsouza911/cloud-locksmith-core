# app/schemas/auth.py

import unicodedata

from pydantic import BaseModel, EmailStr, field_validator

from app.services.auth.password import BCRYPT_MAX_BYTES


def normalize_email(raw: str) -> str:
    """
    Canonicalise an email address so that visually-equivalent forms collide
    in the unique index:
      - NFKC unicode normalisation (folds compatibility characters)
      - IDNA-encode the domain (rejects deceptive Unicode lookalikes)
      - lowercase the whole address
    Raises ValueError on malformed input.
    """
    if raw is None:
        raise ValueError("Invalid email address")
    value = unicodedata.normalize("NFKC", raw).strip()
    if "@" not in value:
        raise ValueError("Invalid email address")
    local, _, domain = value.rpartition("@")
    if not local or not domain:
        raise ValueError("Invalid email address")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid email domain") from exc
    return f"{local}@{domain}".lower()


def _validate_password(value: str) -> str:
    if value is None or len(value) < 8:
        raise ValueError("Password must be at least 8 characters")
    # Reject up-front rather than relying on bcrypt's silent truncation.
    if len(value.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError("password_too_long")
    return value


class AuthRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(AuthRequest):
    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return normalize_email(v)


class SignupRequest(BaseModel):
    # NOTE: legacy MSP-onboarding signup uses plain str + manual handling.
    # Left untouched to avoid changing that flow's behaviour.
    email: str
    password: str
    name: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        return _validate_password(value)


class PasswordSignupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    is_msp: bool = False

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return normalize_email(v)

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        return _validate_password(value)


class VerifyEmailRequest(BaseModel):
    token: str
