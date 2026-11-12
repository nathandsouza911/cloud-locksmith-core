"""Resource projection for IDENTITY_OAUTH_APP_CONSENT_DISCOVERY.

The Gate 2 validation slice: one delegated OAuth consent grant per review
resource, matching the fan-out convention already established by this
workflow's illicit-consent-grants resources (resources.py) -- but this
module deliberately does NOT reuse that module's classify_grant_risk. This
is a read-only inventory, not a risk assessment: no scope-based severity
scoring, no "should this be revoked" verdict, nothing this validation slice
was told not to build.

ReviewResource (the platform's shared contract) structurally requires
risk_level/risk_explanation/recommended_action -- every workflow's UI and
sort order depends on them being present. DISCOVERY_RISK_LEVEL is a fixed,
neutral placeholder to satisfy that contract, not a computed assessment.
Sorting by it (see RiskLevel.rank) puts every discovery resource at the
same rank, so within this control resources sort by grant id only --
appropriate for a plain inventory, which has no "riskiest first" concept.
"""

from __future__ import annotations

from app.services.work.evidence_fingerprint import compute_evidence_fingerprint
from app.services.workflows._shared.resource_key import ResourceKey
from app.services.workflows._shared.resources import ResourceFact, ReviewResource

CONSENT_DISCOVERY_CONTROL_ID = "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"
WORKFLOW_ID = "OAUTH_REVIEW"

# Not a risk level. A fixed placeholder because ReviewResource requires one;
# see module docstring. Deliberately not a value from RiskLevel.ALL, so it
# cannot be mistaken for a real assessment and sorts last (RiskLevel.rank
# falls back to "unknown level" for anything not in RiskLevel.ALL).
DISCOVERY_RISK_LEVEL = "DISCOVERY"


def _permissions_display(scopes: list[str] | None) -> str:
    if not scopes:
        return "(none)"
    return ", ".join(scopes)


def _date_display(entry: dict) -> str:
    """Never fabricated. A real value is shown verbatim; otherwise 'Unknown'.

    docs/oauth-discovery-graph-data-model.md: Microsoft Graph provides no
    reliable consent timestamp for oauth2PermissionGrant. This function does
    not infer, estimate, or substitute one.
    """
    date = entry.get("date")
    return str(date) if date else "Unknown"


def build_consent_discovery_resource(entry: dict, finding=None) -> ReviewResource:
    """Project one normalised discovery entry into a review resource."""
    grant_id = entry.get("grant_id") or ""
    application_name = entry.get("application_name") or grant_id
    scopes = entry.get("scopes") or []
    consented_by = entry.get("consented_by") or "Unknown"
    date_display = _date_display(entry)

    return ReviewResource(
        key=ResourceKey(CONSENT_DISCOVERY_CONTROL_ID, grant_id),
        resource_type="SERVICE_PRINCIPAL",
        title=application_name,
        subtitle=entry.get("consent_type"),
        risk_level=DISCOVERY_RISK_LEVEL,
        risk_explanation=(
            "Discovered via the delegated OAuth consent inventory. " "No risk assessment has been performed."
        ),
        recommended_action="REVIEW",
        risk_drivers=[],
        facts=[
            ResourceFact("Application", application_name),
            ResourceFact("Consented by", consented_by),
            ResourceFact("Permissions", _permissions_display(scopes)),
            ResourceFact("Date", date_display),
        ],
        # Copied, not referenced -- the resource is immutable.
        evidence=dict(entry),
        evidence_hash=compute_evidence_fingerprint(
            control_id=CONSENT_DISCOVERY_CONTROL_ID,
            resource_type="SERVICE_PRINCIPAL",
            resource_id=grant_id,
            evidence=entry,
        ),
        compliance_result_id=getattr(finding, "id", None),
    )
