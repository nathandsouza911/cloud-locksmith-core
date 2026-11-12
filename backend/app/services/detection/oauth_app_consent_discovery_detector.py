"""OAuth app consent discovery — the read-only delegated consent inventory.

Gate 2's first validation slice: "show every application with a delegated
OAuth permission grant in this tenant." Deliberately distinct from
``illicit_consent_grants_detector``, which filters to a hardcoded high-risk
scope set and was never meant to be a full inventory — this control returns
every delegated grant, unfiltered, because the validation question ("do MSPs
value visibility into what's consented") can't be answered from a filtered
list.

Covers ``oauth2PermissionGrant`` only. Application permissions
(``appRoleAssignment``) are an explicit, documented scope decision to defer
until this simpler slice has real MSP feedback — see
docs/oauth-discovery-final-implementation-decision.md.

Date semantics (the one thing this module must never get wrong): Microsoft
Graph provides no reliable consent timestamp for ``oauth2PermissionGrant`` —
verified against Microsoft's own resource schema during the final
verification pass (docs/oauth-discovery-graph-data-model.md). Neither
``servicePrincipal`` nor ``oauth2PermissionGrant`` carries a creation
timestamp Graph will vouch for. This detector never infers one from scan
time, service principal metadata, or any other proxy — every entry's
``date`` is ``None`` with ``date_source: "unknown"`` unless a future pass
adds real audit-log enrichment (deferred, not built here).
"""

from __future__ import annotations

import logging

from app.services.graph_client import graph_get, graph_get_all

logger = logging.getLogger(__name__)

CONTROL_ID = "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"


async def _resolve_consented_by(db, tenant, *, consent_type: str | None, principal_id: str | None, cache: dict) -> str:
    """Never a raw GUID. Resolve to a name, a tenant-wide label, or 'Unknown'."""
    if consent_type == "AllPrincipals":
        return "Admin (tenant-wide)"
    if consent_type == "Principal" and principal_id:
        if principal_id in cache:
            return cache[principal_id]
        try:
            user = await graph_get(db, tenant, f"/users/{principal_id}?$select=displayName,userPrincipalName")
            name = (user or {}).get("displayName") or (user or {}).get("userPrincipalName")
        except Exception:
            logger.warning("oauth_consent_principal_resolution_failed principal_id=%s", principal_id)
            name = None
        resolved = name or "Unknown"
        cache[principal_id] = resolved
        return resolved
    return "Unknown"


async def detect_oauth_app_consent(*, db, tenant) -> dict:
    """One tenant-level finding carrying every delegated consent grant.

    Persistence shape mirrors ``illicit_consent_grants_detector``
    deliberately: one ComplianceResult per tenant, evidence carrying a list,
    fanned out into one independently-reviewable resource per grant at
    projection time (EvidenceFanOutProjector). Grant-level granularity, not
    application-level, because one application can carry several distinct
    grants (e.g. one AllPrincipals grant plus separate per-user grants) that
    warrant independent review decisions.
    """
    grants = await graph_get_all(db, tenant, "/oauth2PermissionGrants")

    service_principals = await graph_get_all(db, tenant, "/servicePrincipals")
    service_principals_by_id = {sp.get("id"): sp for sp in service_principals if sp.get("id")}

    principal_name_cache: dict[str, str] = {}

    discovered: list[dict] = []
    for grant in grants:
        grant_id = grant.get("id")
        if not grant_id:
            # No identity means it cannot be reviewed or revoked later.
            continue

        client_id = grant.get("clientId")
        service_principal = service_principals_by_id.get(client_id) or {}
        application_name = (
            service_principal.get("appDisplayName")
            or service_principal.get("displayName")
            or client_id
            or "Unknown application"
        )

        consent_type = grant.get("consentType")
        principal_id = grant.get("principalId")
        scope_value = grant.get("scope") or ""
        scopes = sorted({s for s in scope_value.split() if s})

        consented_by = await _resolve_consented_by(
            db,
            tenant,
            consent_type=consent_type,
            principal_id=principal_id,
            cache=principal_name_cache,
        )

        discovered.append(
            {
                "grant_id": grant_id,
                "client_id": client_id,
                "service_principal_id": client_id,
                "resource_id": grant.get("resourceId"),
                "application_name": application_name,
                "consent_type": consent_type,
                "principal_id": principal_id,
                "consented_by": consented_by,
                "scope": grant.get("scope"),
                "scopes": scopes,
                # Never fabricated — see module docstring.
                "date": None,
                "date_source": "unknown",
            }
        )

    return {
        "control_id": CONTROL_ID,
        "severity": "INFO",
        "passed": len(discovered) == 0,
        "evidence": {
            "oauth_app_consents": discovered,
            "total_grants_examined": len(grants),
        },
    }
