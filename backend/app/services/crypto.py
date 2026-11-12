"""
Application-layer encryption for sensitive credential fields.

Usage:
    from app.services.crypto import encrypt_str, decrypt_str, encrypt_token_dict, decrypt_token_dict

The ENCRYPTION_KEY env var must be a 32-byte Fernet key produced by:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Encrypted values are stored as opaque strings; decryption is only performed
inside this module, never exposed in logs or API responses.
"""

import functools
import logging

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

from app.config import settings

logger = logging.getLogger(__name__)

# Fields within a token dict that must be encrypted at rest.
_ENCRYPTED_TOKEN_FIELDS = frozenset({"access_token", "refresh_token"})


@functools.lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    key: str = settings.ENCRYPTION_KEY
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY environment variable is not set. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        raise RuntimeError(
            "ENCRYPTION_KEY is not a valid Fernet key. " "It must be a URL-safe base64-encoded 32-byte value."
        ) from exc


def encrypt_str(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns an opaque ciphertext string."""
    if not isinstance(plaintext, str):
        raise TypeError("encrypt_str requires a str argument")
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_str(ciphertext: str) -> str:
    """Decrypt a ciphertext string produced by encrypt_str."""
    if not isinstance(ciphertext, str):
        raise TypeError("decrypt_str requires a str argument")
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        logger.error("token_decryption_failed: ciphertext is invalid or key mismatch")
        raise HTTPException(
            status_code=500,
            detail="Token decryption failed — re-authentication required",
        ) from exc


def encrypt_token_dict(token_dict: dict) -> dict:
    """
    Return a copy of `token_dict` with sensitive fields encrypted.
    Only fields in _ENCRYPTED_TOKEN_FIELDS are touched; all others are copied as-is.
    """
    result = dict(token_dict)
    for field in _ENCRYPTED_TOKEN_FIELDS:
        value = result.get(field)
        if isinstance(value, str) and value:
            result[field] = encrypt_str(value)
    return result


def decrypt_token_dict(token_dict: dict) -> dict:
    """
    Return a copy of `token_dict` with sensitive fields decrypted.
    Safe to call on a dict that may already be plaintext (idempotent on non-Fernet strings
    is NOT guaranteed — only call on data written by encrypt_token_dict).
    """
    result = dict(token_dict)
    for field in _ENCRYPTED_TOKEN_FIELDS:
        value = result.get(field)
        if isinstance(value, str) and value:
            result[field] = decrypt_str(value)
    return result
