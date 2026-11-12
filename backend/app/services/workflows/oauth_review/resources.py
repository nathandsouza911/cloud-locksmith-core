"""OAuth review resources — one application per review item.

The detector emits a single tenant-level finding whose evidence carries a list
of grants. A technician reviews one *application* at a time, so this module
projects that finding into per-grant review resources.

**Projection only.** The finding is never split, re-detected or mutated:
``test_building_resources_does_not_mutate_the_evidence`` enforces that. Review
decisions are keyed on the grant id, which Review Memory already supports —
it keys on ``(tenant, workflow, control, resource_id)`` and does not care that
several resource ids share one finding.

This module is workflow-specific by design. It consumes the platform (evidence
fingerprinting, the registry) and extends none of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.work.evidence_fingerprint import compute_evidence_fingerprint
from app.services.workflows._shared.resource_key import ResourceKey
from app.services.workflows._shared.resources import ResourceFact, ReviewResource

# Re-exported so existing imports of RiskLevel/RiskAssessment from this module
# keep working. Both are generic and now live in the shared package.
from app.services.workflows._shared.risk import (  # noqa: F401
    RiskAssessment,
    RiskLevel,
)

CONTROL_ID = "IDENTITY_ILLICIT_CONSENT_GRANTS"
WORKFLOW_ID = "OAUTH_REVIEW"


# Scopes that let an application act, exfiltrate at scale, or persist.
_CRITICAL_SCOPES = {
    "Mail.ReadWrite",
    "Mail.ReadWrite.All",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "MailboxSettings.ReadWrite",
}

# Broad read access — mass data exposure without the ability to act.
_HIGH_SCOPES = {
    "Mail.Read",
    "Mail.Read.All",
    "Files.Read.All",
    "Sites.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "Contacts.Read",
    "Calendars.Read",
    "Notes.Read.All",
    # Refresh tokens outlive the session that granted them.
    "offline_access",
}

# Narrow, self-scoped, low consequence.
_LOW_SCOPES = {
    "User.Read",
    "profile",
    "openid",
    "email",
    "User.ReadBasic.All",
}


def scope_risk(scope: str | None) -> str:
    """Risk contributed by a single permission scope.

    Unrecognised scopes are treated as MEDIUM, not LOW: a permission we have not
    classified is not evidence that it is safe.
    """
    if not scope:
        return RiskLevel.LOW
    name = scope.strip()
    if name in _CRITICAL_SCOPES:
        return RiskLevel.CRITICAL
    if name in _HIGH_SCOPES:
        return RiskLevel.HIGH
    if name in _LOW_SCOPES:
        return RiskLevel.LOW
    return RiskLevel.MEDIUM


def classify_grant_risk(grant: dict) -> RiskAssessment:
    """Assess one normalised grant and explain the assessment in plain English.

    The explanation is written for the technician who has to justify the
    decision to a client, not for a log line.
    """
    scopes = grant.get("scopes") or []
    per_scope = {scope: scope_risk(scope) for scope in scopes}
    level = RiskLevel.worst(per_scope.values()) if per_scope else RiskLevel.LOW

    drivers: list[str] = []
    sentences: list[str] = []

    worst_scopes = sorted(s for s, r in per_scope.items() if r == level)
    app = grant.get("application_name") or grant.get("client_id") or "This application"

    if worst_scopes and level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        verb = "can modify or send data" if level == RiskLevel.CRITICAL else "can read broadly"
        sentences.append(f"{app} {verb} using {', '.join(worst_scopes)}.")
        drivers.append(f"scopes:{','.join(worst_scopes)}")
    elif worst_scopes:
        sentences.append(f"{app} holds {', '.join(worst_scopes)}, which is limited in scope.")
    else:
        sentences.append(f"{app} holds no permissions that could be classified.")

    if grant.get("consent_type") == "AllPrincipals":
        level = RiskLevel.escalate(level)
        drivers.append("consent:tenant_wide")
        sentences.append(
            "Consent was granted on behalf of every user in the tenant, "
            "so the permission applies organisation-wide rather than to one person."
        )
    else:
        who = grant.get("principal_id")
        sentences.append(f"Consent was granted by a single user{f' ({who})' if who else ''}.")

    verified = grant.get("verified_publisher")
    if verified is False:
        drivers.append("publisher:unverified")
        sentences.append(
            "The publisher is not verified by Microsoft, so the application's " "origin cannot be confirmed."
        )
    elif verified is None:
        drivers.append("publisher:unknown")
        sentences.append("No publisher verification information is available.")

    if grant.get("last_used") is None:
        sentences.append("There is no recorded sign-in activity for this grant.")

    recommended = (
        "REVOKE"
        if level in (RiskLevel.CRITICAL, RiskLevel.HIGH) and drivers
        else "KEEP"
        if level == RiskLevel.LOW
        else "REVIEW"
    )

    explanation = " ".join(sentences)
    # The first word is often an application id, which may be lowercase. This
    # is prose a technician pastes into a client report, so it starts as a
    # sentence.
    explanation = explanation[:1].upper() + explanation[1:]

    return RiskAssessment(
        level=level,
        explanation=explanation,
        recommended_action=recommended,
        drivers=drivers,
    )


def normalize_grant(grant: dict) -> dict:
    """Graph's camelCase into stable snake_case, with scopes parsed.

    Both spellings are declared in the evidence-fingerprint allowlist, so a
    normalised grant and a raw one hash over the same material fields.
    """
    raw_scope = grant.get("scope")
    scopes = sorted({s for s in (raw_scope or "").split() if s})

    return {
        "grant_id": grant.get("id"),
        "client_id": grant.get("clientId") or grant.get("client_id"),
        "resource_id": grant.get("resourceId") or grant.get("resource_id"),
        "principal_id": grant.get("principalId") or grant.get("principal_id"),
        "consent_type": grant.get("consentType") or grant.get("consent_type"),
        "scope": raw_scope,
        "scopes": scopes,
        "matched_scopes": sorted(grant.get("matched_scopes") or []),
        # Enrichment — present when discovery could resolve it, else None.
        "application_name": (
            grant.get("app_display_name")
            or grant.get("application_name")
            or grant.get("clientId")
            or grant.get("client_id")
        ),
        "app_id": grant.get("app_id"),
        "publisher": grant.get("publisher"),
        "publisher_domain": grant.get("publisher_domain"),
        "verified_publisher": grant.get("verified_publisher"),
        "last_used": grant.get("last_used"),
        "owners": list(grant.get("owners") or []) or None,
        "first_seen": grant.get("first_seen"),
        "grant_history": grant.get("grant_history"),
    }


@dataclass(frozen=True)
class OAuthReviewResource(ReviewResource):
    """One application awaiting a decision.

    A ``ReviewResource`` with the OAuth fields the dedicated screen reads. It
    subclasses rather than wraps so ``dataclasses.replace`` (used by
    ``with_delta``) returns an OAuth resource, letting the generic review session
    decorate it without knowing what OAuth is.

    Every field added here has a default because the base class has defaulted
    fields — required fields cannot follow optional ones in a dataclass.
    """

    grant_id: str = ""
    application_name: str = ""
    client_id: str | None = None
    publisher: str | None = None
    verified_publisher: bool | None = None
    consent_type: str | None = None
    principal_id: str | None = None
    scopes: list[str] = field(default_factory=list)
    scope_risks: dict[str, str] = field(default_factory=dict)
    last_used: str | None = None
    owners: list[str] | None = None


def build_oauth_resource(grant: dict, finding=None) -> OAuthReviewResource:
    """Project one normalised grant into a review resource.

    Split out from ``build_review_resources`` so the projector and the legacy
    entry point share one construction path.
    """
    normalized = normalize_grant(grant)
    grant_id = normalized["grant_id"]
    assessment = classify_grant_risk(normalized)
    scopes = normalized["scopes"]

    return OAuthReviewResource(
        key=ResourceKey(CONTROL_ID, grant_id),
        resource_type="SERVICE_PRINCIPAL",
        title=normalized["application_name"] or grant_id,
        subtitle=normalized["publisher"],
        risk_level=assessment.level,
        risk_explanation=assessment.explanation,
        recommended_action=assessment.recommended_action,
        risk_drivers=list(assessment.drivers),
        facts=[
            ResourceFact("Publisher", normalized["publisher"]),
            ResourceFact("Verified publisher", normalized["verified_publisher"]),
            ResourceFact("Consent type", normalized["consent_type"]),
            ResourceFact("Last used", normalized["last_used"]),
        ],
        # Per-scope risk is carried in the evidence so the generic screen's
        # detail hatch can render the scope table without an OAuth-shaped API.
        # A *copy* — `normalized` itself must stay untouched because it is what
        # the fingerprint below is computed from, and changing that would make
        # every existing decision look stale.
        evidence=dict(normalized, scope_risks={s: scope_risk(s) for s in scopes}),
        # Per-resource fingerprint via the platform function, unchanged — the
        # grant id is the resource identity.
        evidence_hash=compute_evidence_fingerprint(
            control_id=CONTROL_ID,
            resource_type="SERVICE_PRINCIPAL",
            resource_id=grant_id,
            evidence=normalized,
        ),
        compliance_result_id=getattr(finding, "id", None),
        grant_id=grant_id,
        application_name=normalized["application_name"] or grant_id,
        client_id=normalized["client_id"],
        publisher=normalized["publisher"],
        verified_publisher=normalized["verified_publisher"],
        consent_type=normalized["consent_type"],
        principal_id=normalized["principal_id"],
        scopes=scopes,
        scope_risks={scope: scope_risk(scope) for scope in scopes},
        last_used=normalized["last_used"],
        owners=normalized["owners"],
    )


def build_review_resources(evidence: dict | None) -> list[OAuthReviewResource]:
    """Project a finding's evidence into per-application review resources.

    Ordered riskiest-first, then by grant id so the order is stable between
    refreshes — a review that reshuffles itself is unusable.
    """
    if not isinstance(evidence, dict):
        return []

    resources = [
        build_oauth_resource(raw)
        for raw in (evidence.get("illicit_grants") or [])
        if isinstance(raw, dict) and raw.get("id")
    ]
    resources.sort(key=lambda r: (RiskLevel.rank(r.risk_level), r.grant_id))
    return resources
