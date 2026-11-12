"""Evidence fingerprinting — what makes a finding "the same thing".

A review decision ("I looked at this OAuth grant and it's fine") stays valid
only while the underlying evidence is unchanged. ``resource_id`` alone is not
enough: the same service principal can have its scopes escalated, its consent
widened from one user to the whole tenant, or its publisher change — all while
keeping the same id.

**Failure asymmetry drives every decision in this module.**

  * Over-sensitive (fingerprint changes when nothing material did) — decisions
    expire needlessly. The technician re-reviews something they already
    approved. Annoying, visible, self-correcting.
  * Under-sensitive (fingerprint stays the same when something material
    changed) — a materially different grant hides behind an old approval and is
    never surfaced again. Silent, invisible, and a genuine security hole.

So: **unknown evidence is treated as material.** A control with no declared
allowlist falls back to hashing its entire evidence payload. That is
deliberately over-sensitive. Narrowing it for a specific control is a conscious
act — add an allowlist entry and a test.

Extensibility: add an entry to ``MATERIAL_EVIDENCE_KEYS`` for a control whose
evidence shape is known. Different workflows legitimately need different
notions of sameness; this is the seam for that.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Keys that change on every scan without any material change to the finding.
# Excluded from every fingerprint, allowlisted control or not — otherwise the
# fallback path would invalidate every decision on every scan and the memory
# layer would be useless.
VOLATILE_EVIDENCE_KEYS: frozenset[str] = frozenset(
    {
        "evaluated_at",
        "last_seen_at",
        "first_seen_at",
        "detected_at",
        "scanned_at",
        "checked_at",
        "timestamp",
        "scan_id",
        "drift_count",
        "remediation_count_7d",
        "execution_attempts",
        "age_days",
        "days_since_last_signin",
        "days_inactive",
    }
)

# Sentinel distinguishing "key absent" from "key present with value None".
# A material field disappearing IS a material change.
_ABSENT = "\x00__absent__"


# ── Material key allowlists ─────────────────────────────────────────────────
#
# Only for controls whose evidence shape we have actually reviewed. Everything
# else falls back to the whole payload. Keys listed here that a detector does
# not emit are harmless (they hash as _ABSENT consistently).

MATERIAL_EVIDENCE_KEYS: dict[str, tuple[str, ...]] = {
    # An OAuth grant is "the same" only if the app, who granted it, how widely,
    # and what it can reach are all unchanged.
    # NOTE: Microsoft Graph returns camelCase and the detector passes it
    # through unchanged, so the camelCase spellings are the ones that actually
    # appear in evidence. The snake_case spellings are kept for the normalised
    # projection the OAuth review builds. Declaring both is deliberate — a key
    # that never appears simply hashes as absent, consistently.
    "IDENTITY_ILLICIT_CONSENT_GRANTS": (
        # As emitted by illicit_consent_grants_detector (Graph shape)
        "clientId",
        "resourceId",
        "principalId",
        "consentType",
        "scope",
        "matched_scopes",
        # Normalised / enriched projection
        "client_id",
        "app_id",
        "service_principal_id",
        "app_display_name",
        "publisher",
        "publisher_domain",
        "verified_publisher",
        "consent_type",
        "principal_id",
        "scopes",
        "resource_id",
        "permissions",
    ),
    # date/date_source deliberately excluded: they describe our confidence in
    # explaining *when* a grant happened, not what was granted. Today they are
    # always None/"unknown"; if future audit-log enrichment starts populating
    # them, that arrival should not by itself invalidate every existing
    # review decision.
    "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY": (
        "grant_id",
        "client_id",
        "service_principal_id",
        "resource_id",
        "application_name",
        "consent_type",
        "principal_id",
        "consented_by",
        "scope",
        "scopes",
    ),
    "IDENTITY_USER_CONSENT_POLICY": (
        "consent_policy",
        "allow_user_consent",
        "permission_grant_policies",
    ),
    "IDENTITY_GUEST_INVITES_OPEN": (
        "guest_invite_setting",
        "allow_invites_from",
    ),
    "IDENTITY_UNUSED_ACCOUNT": (
        "user_id",
        "user_principal_name",
        "accountEnabled",
        "account_enabled",
        "last_sign_in",
        "assigned_roles",
    ),
    "IDENTITY_OVERPRIVILEGED_USER": (
        "user_id",
        "user_principal_name",
        "current_roles",
        "roles",
    ),
    "IDENTITY_ADMIN_NO_MFA": (
        "user_id",
        "user_principal_name",
        "current_roles",
        "roles",
        "mfa_registered",
        "mfa_methods",
    ),
    "IDENTITY_USER_NO_MFA": (
        "user_id",
        "user_principal_name",
        "mfa_registered",
        "mfa_methods",
    ),
    "IDENTITY_STALE_SERVICE_PRINCIPAL": (
        "service_principal_id",
        "app_id",
        "display_name",
        "accountEnabled",
        "account_enabled",
    ),
    "IDENTITY_PERMANENT_ROLE_ASSIGNMENT": (
        "user_id",
        "user_principal_name",
        "role_id",
        "role_name",
        "assignment_type",
    ),
    "IDENTITY_MAIL_FORWARDING_RULE": (
        "user_id",
        "user_principal_name",
        "forwarding_address",
        "forwarding_smtp_address",
        "rule_id",
        "rule_name",
    ),
    "IDENTITY_APP_SECRET_EXPIRING_SOON": (
        "app_id",
        "application_id",
        "display_name",
        "key_id",
        "secret_id",
        "expires_at",
    ),
}


def material_keys_for(control_id: str | None) -> tuple[str, ...] | None:
    """Declared material keys for a control, or None if it has no allowlist."""
    if not control_id:
        return None
    return MATERIAL_EVIDENCE_KEYS.get(control_id)


def _normalize(value: Any) -> Any:
    """Canonicalise a value so equivalent evidence hashes identically.

    Lists of scalars are sorted: Microsoft Graph does not guarantee ordering
    for collections such as ``scopes``, so ordering is not a material change.
    Duplicates are collapsed for the same reason. Lists containing structures
    keep their order — position may be meaningful there, and guessing wrong
    would be the permissive kind of mistake.
    """
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        if all(isinstance(item, (str, int, float, bool, type(None))) for item in items):
            return sorted({str(item) for item in items})
        return [_normalize(item) for item in items]
    return value


def _strip_volatile(evidence: dict) -> dict:
    return {key: value for key, value in evidence.items() if key not in VOLATILE_EVIDENCE_KEYS}


def compute_evidence_fingerprint(
    *,
    control_id: str | None,
    resource_type: str | None,
    resource_id: str | None,
    evidence: dict | None,
) -> str:
    """SHA-256 over the material identity + material evidence of a finding.

    Identity (control, resource type, resource id) is always part of the hash,
    so identical evidence attached to a different resource never collides with
    an existing decision.
    """
    payload = evidence if isinstance(evidence, dict) else {}

    allowlist = material_keys_for(control_id)

    # An allowlist that matches NOTHING in the evidence is a mis-declaration:
    # every declared key would hash as absent, the material part would be
    # constant, and a materially changed resource would keep its stale review
    # decision. That is the dangerous direction, so treat it as no allowlist and
    # fall back to full-payload hashing (safe over-sensitivity).
    #
    # Empty evidence is not a mis-declaration — there is simply nothing to
    # match — so it keeps using the allowlist and hashes to a stable "absent"
    # form.
    if allowlist is not None and payload and not (set(allowlist) & set(payload)):
        logger.warning(
            "evidence_fingerprint_allowlist_unmatched control_id=%s "
            "declared=%s present=%s — falling back to full-payload hashing",
            control_id,
            sorted(allowlist),
            sorted(payload),
        )
        allowlist = None

    if allowlist is not None:
        material: dict[str, Any] = {
            key: _normalize(payload.get(key, _ABSENT)) for key in allowlist if key not in VOLATILE_EVIDENCE_KEYS
        }
    else:
        # Fail safe: no allowlist means everything (minus known scan noise) is
        # treated as material.
        material = _normalize(_strip_volatile(payload))

    canonical = json.dumps(
        {
            "control_id": control_id or "",
            "resource_type": resource_type or "",
            "resource_id": resource_id or "",
            "material": material,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fingerprint_finding(finding) -> str:
    """Convenience wrapper for a ComplianceResult-shaped object."""
    return compute_evidence_fingerprint(
        control_id=getattr(finding, "control_id", None),
        resource_type=getattr(finding, "resource_type", None),
        resource_id=getattr(finding, "resource_id", None),
        evidence=getattr(finding, "evidence", None),
    )
