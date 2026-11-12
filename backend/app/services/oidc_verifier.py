"""
OIDC id_token verification using Microsoft's JWKS endpoint.

Every call fetches the tenant-specific JWKS and verifies:
  - RSA signature (RS256)
  - aud  == MICROSOFT_CLIENT_ID
  - iss  == https://login.microsoftonline.com/{tid}/v2.0
  - exp  (PyJWT enforces this automatically)
  - tid  matches the expected tenant from the access token

Never call jwt.decode() with verify_signature=False in production.
"""

import json
import logging

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import HTTPException

from app.config import settings

logger = logging.getLogger(__name__)

_JWKS_TIMEOUT_SECONDS = 10


async def verify_microsoft_id_token(
    id_token: str | None,
    *,
    expected_tid: str,
) -> dict:
    """
    Fetch Microsoft JWKS for `expected_tid`, verify `id_token` signature,
    audience, issuer, and expiry.  Raise HTTP 400/401/502 on any failure.

    Args:
        id_token:     The raw id_token string from the OAuth token response.
        expected_tid: The tenant ID extracted from the *access* token (already
                      validated by Microsoft's token endpoint).  Used to build
                      the correct JWKS URI and to cross-check the id_token tid.

    Returns:
        Verified id_token claims dict.
    """
    if not isinstance(id_token, str) or not id_token.strip():
        raise HTTPException(
            status_code=400,
            detail="Microsoft id_token missing from OAuth callback",
        )

    # ── 1. Decode header only (no verification) to get the key ID ────────────
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed Microsoft id_token header")

    kid = header.get("kid")
    alg = header.get("alg", "")
    if alg.upper() not in {"RS256"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported id_token algorithm: {alg}",
        )

    # ── 2. Fetch JWKS for the specific tenant ────────────────────────────────
    jwks_uri = f"https://login.microsoftonline.com/{expected_tid}/discovery/v2.0/keys"
    try:
        async with httpx.AsyncClient(timeout=_JWKS_TIMEOUT_SECONDS) as http:
            resp = await http.get(jwks_uri)
            resp.raise_for_status()
            jwks_data = resp.json()
    except httpx.HTTPStatusError:
        logger.error("oidc_jwks_fetch_http_error")
        raise HTTPException(
            status_code=502,
            detail="Unable to fetch Microsoft signing keys (HTTP error)",
        )
    except Exception:
        logger.error("oidc_jwks_fetch_failed")
        raise HTTPException(
            status_code=502,
            detail="Unable to fetch Microsoft signing keys",
        )

    # ── 3. Locate the matching key by kid ─────────────────────────────────────
    keys = jwks_data.get("keys", [])
    if not keys:
        raise HTTPException(status_code=502, detail="Microsoft JWKS returned no keys")

    # Require an exact kid match. Falling back to keys[0] masked key-rotation
    # issues and removed a useful defense-in-depth; an id_token whose kid is
    # not present in the tenant JWKS is rejected outright.
    if not kid:
        logger.warning("oidc_id_token_missing_kid")
        raise HTTPException(
            status_code=401,
            detail="Microsoft id_token is missing kid header",
        )
    matching_key_data = next(
        (k for k in keys if k.get("kid") == kid),
        None,
    )
    if matching_key_data is None:
        logger.warning("oidc_kid_not_in_jwks kid=%s", kid)
        raise HTTPException(
            status_code=401,
            detail="Microsoft id_token kid not found in tenant JWKS",
        )

    try:
        public_key = RSAAlgorithm.from_jwk(json.dumps(matching_key_data))
    except Exception:
        logger.error("oidc_jwks_key_construct_failed")
        raise HTTPException(
            status_code=502,
            detail="Unable to construct RSA public key from JWKS",
        )

    # ── 4. Full verification: signature + aud + iss + exp ─────────────────────
    expected_issuer = f"https://login.microsoftonline.com/{expected_tid}/v2.0"
    client_id = str(settings.MICROSOFT_CLIENT_ID)

    try:
        claims: dict = jwt.decode(
            id_token,
            public_key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=expected_issuer,
            options={"require": ["exp", "aud", "iss", "sub", "oid"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Microsoft id_token has expired")
    except jwt.InvalidAudienceError:
        logger.warning("oidc_audience_mismatch")
        raise HTTPException(status_code=401, detail="Microsoft id_token audience mismatch")
    except jwt.InvalidIssuerError:
        logger.warning("oidc_issuer_mismatch")
        raise HTTPException(status_code=401, detail="Microsoft id_token issuer mismatch")
    except jwt.MissingRequiredClaimError as exc:
        logger.warning("oidc_missing_claim claim=%s", exc.claim)
        raise HTTPException(status_code=401, detail="Microsoft id_token is missing required claims")
    except Exception:
        logger.warning("oidc_token_validation_failed")
        raise HTTPException(status_code=401, detail="Microsoft id_token validation failed")

    if not isinstance(claims, dict):
        raise HTTPException(status_code=400, detail="Invalid Microsoft id_token payload")

    # ── 5. Cross-check tid matches the access token's tenant ──────────────────
    id_token_tid = str(claims.get("tid") or "").strip()
    if id_token_tid and id_token_tid != expected_tid:
        logger.warning("oidc_tid_mismatch")
        raise HTTPException(
            status_code=401,
            detail="Microsoft id_token tenant does not match the access token tenant",
        )

    return claims
