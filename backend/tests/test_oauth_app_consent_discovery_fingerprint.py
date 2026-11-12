"""Evidence fingerprint stability for IDENTITY_OAUTH_APP_CONSENT_DISCOVERY.

Same discipline as test_evidence_fingerprint_real_shapes.py: use the exact
shape the real detector emits, not an invented one, and require the
allowlist to declare at least one key the detector actually produces —
otherwise the material part of every hash is constant and review decisions
never expire when they should.
"""

from app.services.work.evidence_fingerprint import (
    MATERIAL_EVIDENCE_KEYS,
    compute_evidence_fingerprint,
)

# Exactly the shape oauth_app_consent_discovery_detector puts in evidence.
ENTRY = {
    "grant_id": "grant-1",
    "client_id": "app-1",
    "service_principal_id": "app-1",
    "resource_id": "resource-1",
    "application_name": "Contoso App",
    "consent_type": "Principal",
    "principal_id": "user-1",
    "consented_by": "Jane Doe",
    "scope": "User.Read Mail.Read",
    "scopes": ["Mail.Read", "User.Read"],
    "date": None,
    "date_source": "unknown",
}


def _fp(evidence, *, resource_id="grant-1"):
    return compute_evidence_fingerprint(
        control_id="IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        evidence=evidence,
    )


def test_allowlist_matches_the_real_detector_output():
    declared = set(MATERIAL_EVIDENCE_KEYS["IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"])
    assert declared & set(ENTRY)


def test_scope_change_changes_the_fingerprint():
    widened = {
        **ENTRY,
        "scope": "User.Read Mail.Read Mail.ReadWrite",
        "scopes": ["Mail.Read", "Mail.ReadWrite", "User.Read"],
    }
    assert _fp(ENTRY) != _fp(widened)


def test_consent_widened_to_tenant_changes_the_fingerprint():
    tenant_wide = {
        **ENTRY,
        "consent_type": "AllPrincipals",
        "principal_id": None,
        "consented_by": "Admin (tenant-wide)",
    }
    assert _fp(ENTRY) != _fp(tenant_wide)


def test_different_client_changes_the_fingerprint():
    assert _fp(ENTRY) != _fp({**ENTRY, "client_id": "app-999", "service_principal_id": "app-999"})


def test_scope_reordering_does_not_change_the_fingerprint():
    reordered = {**ENTRY, "scopes": ["User.Read", "Mail.Read"]}
    assert _fp(ENTRY) == _fp(reordered)


def test_date_being_unknown_is_not_treated_as_material():
    """The date is always None/unknown today. If enrichment adds a real date
    later, that arrival should not silently invalidate every prior decision
    on its own -- date/date_source describe our confidence, not what was
    granted.
    """
    with_a_date = {**ENTRY, "date": "2026-01-01T00:00:00Z", "date_source": "audit_log"}
    assert _fp(ENTRY) == _fp(with_a_date)
