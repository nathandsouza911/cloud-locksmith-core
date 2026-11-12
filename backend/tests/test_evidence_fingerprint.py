"""Sprint 2 — evidence fingerprinting.

The fingerprint decides whether a past review decision still applies. Getting
this wrong in the permissive direction is a security hole: a materially changed
OAuth grant would stay silently "already reviewed".

The asymmetry drives the design:
  * Too sensitive  → decisions expire needlessly. Annoying.
  * Too permissive → a changed grant hides behind an old approval. Dangerous.

So unknown evidence is treated as material by default.
"""

import pytest

from app.services.work.evidence_fingerprint import (
    VOLATILE_EVIDENCE_KEYS,
    compute_evidence_fingerprint,
    material_keys_for,
)


def fp(
    control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
    resource_id="grant-1",
    evidence=None,
    resource_type="SERVICE_PRINCIPAL",
):
    return compute_evidence_fingerprint(
        control_id=control_id,
        resource_type=resource_type,
        resource_id=resource_id,
        evidence=evidence if evidence is not None else {},
    )


OAUTH_EVIDENCE = {
    "client_id": "app-123",
    "app_display_name": "Zapier",
    "publisher": "Zapier Inc",
    "consent_type": "Principal",
    "scopes": ["Mail.Read", "Files.Read.All"],
    "principal_id": "user-9",
}


# ── Shape ───────────────────────────────────────────────────────────────────


def test_fingerprint_is_a_sha256_hex_digest():
    value = fp(evidence=OAUTH_EVIDENCE)
    assert len(value) == 64
    assert all(c in "0123456789abcdef" for c in value)


def test_fingerprint_is_deterministic():
    assert fp(evidence=OAUTH_EVIDENCE) == fp(evidence=dict(OAUTH_EVIDENCE))


def test_empty_evidence_does_not_crash():
    assert len(fp(evidence={})) == 64


def test_none_evidence_is_treated_as_empty():
    assert fp(evidence=None) == fp(evidence={})


# ── Identity is part of the fingerprint ─────────────────────────────────────


def test_same_evidence_on_a_different_resource_is_a_different_fingerprint():
    assert fp(resource_id="grant-1", evidence=OAUTH_EVIDENCE) != fp(resource_id="grant-2", evidence=OAUTH_EVIDENCE)


def test_same_evidence_under_a_different_control_is_a_different_fingerprint():
    assert fp(control_id="IDENTITY_ILLICIT_CONSENT_GRANTS", evidence=OAUTH_EVIDENCE) != fp(
        control_id="IDENTITY_USER_CONSENT_POLICY", evidence=OAUTH_EVIDENCE
    )


def test_same_evidence_under_a_different_resource_type_is_a_different_fingerprint():
    assert fp(resource_type="USER", evidence=OAUTH_EVIDENCE) != fp(
        resource_type="SERVICE_PRINCIPAL", evidence=OAUTH_EVIDENCE
    )


# ── Material changes invalidate (the security-critical cases) ───────────────


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("client_id", "app-999"),
        ("app_display_name", "Not Zapier"),
        ("publisher", "Someone Else"),
        ("consent_type", "AllPrincipals"),
        ("principal_id", "user-42"),
    ],
)
def test_changing_a_material_oauth_field_changes_the_fingerprint(field, new_value):
    changed = {**OAUTH_EVIDENCE, field: new_value}
    assert fp(evidence=OAUTH_EVIDENCE) != fp(evidence=changed)


def test_adding_a_scope_changes_the_fingerprint():
    escalated = {**OAUTH_EVIDENCE, "scopes": ["Mail.Read", "Files.Read.All", "Mail.ReadWrite"]}
    assert fp(evidence=OAUTH_EVIDENCE) != fp(evidence=escalated)


def test_removing_a_scope_changes_the_fingerprint():
    reduced = {**OAUTH_EVIDENCE, "scopes": ["Mail.Read"]}
    assert fp(evidence=OAUTH_EVIDENCE) != fp(evidence=reduced)


def test_consent_escalated_from_user_to_tenant_wide_changes_the_fingerprint():
    """The exact scenario a stale approval must never hide."""
    tenant_wide = {**OAUTH_EVIDENCE, "consent_type": "AllPrincipals", "principal_id": None}
    assert fp(evidence=OAUTH_EVIDENCE) != fp(evidence=tenant_wide)


# ── Non-material changes preserve the decision ──────────────────────────────


def test_reordering_scopes_does_not_change_the_fingerprint():
    """Graph does not guarantee ordering; reordering is not a material change."""
    reordered = {**OAUTH_EVIDENCE, "scopes": ["Files.Read.All", "Mail.Read"]}
    assert fp(evidence=OAUTH_EVIDENCE) == fp(evidence=reordered)


def test_duplicate_scopes_do_not_change_the_fingerprint():
    duplicated = {**OAUTH_EVIDENCE, "scopes": ["Mail.Read", "Files.Read.All", "Mail.Read"]}
    assert fp(evidence=OAUTH_EVIDENCE) == fp(evidence=duplicated)


@pytest.mark.parametrize("volatile_key", sorted(VOLATILE_EVIDENCE_KEYS))
def test_volatile_scan_metadata_does_not_change_the_fingerprint(volatile_key):
    noisy = {**OAUTH_EVIDENCE, volatile_key: "2026-08-03T10:00:00"}
    noisier = {**OAUTH_EVIDENCE, volatile_key: "2026-08-04T11:30:00"}
    assert fp(evidence=noisy) == fp(evidence=noisier)


def test_irrelevant_extra_field_on_a_known_control_does_not_change_the_fingerprint():
    """Known controls use an allowlist, so unrelated additions are ignored."""
    extra = {**OAUTH_EVIDENCE, "some_display_only_field": "whatever"}
    assert fp(evidence=OAUTH_EVIDENCE) == fp(evidence=extra)


# ── Unknown controls fail safe (over-sensitive, never permissive) ───────────


def test_unknown_control_treats_any_evidence_change_as_material():
    base = {"anything": "a", "nested": {"x": 1}}
    changed = {"anything": "b", "nested": {"x": 1}}
    assert fp(control_id="BRAND_NEW_CONTROL", evidence=base) != fp(control_id="BRAND_NEW_CONTROL", evidence=changed)


def test_unknown_control_treats_nested_changes_as_material():
    base = {"nested": {"x": 1}}
    changed = {"nested": {"x": 2}}
    assert fp(control_id="BRAND_NEW_CONTROL", evidence=base) != fp(control_id="BRAND_NEW_CONTROL", evidence=changed)


def test_unknown_control_still_ignores_volatile_scan_metadata():
    base = {"anything": "a"}
    noisy = {"anything": "a", "last_seen_at": "2026-08-03T10:00:00"}
    assert fp(control_id="BRAND_NEW_CONTROL", evidence=base) == fp(control_id="BRAND_NEW_CONTROL", evidence=noisy)


def test_unknown_control_has_no_material_key_allowlist():
    assert material_keys_for("BRAND_NEW_CONTROL") is None


# ── Extensibility ───────────────────────────────────────────────────────────


def test_known_controls_declare_their_material_keys():
    assert material_keys_for("IDENTITY_ILLICIT_CONSENT_GRANTS")


def test_a_control_with_declared_keys_ignores_undeclared_keys():
    keys = material_keys_for("IDENTITY_ILLICIT_CONSENT_GRANTS")
    assert keys is not None
    undeclared = {**OAUTH_EVIDENCE, "definitely_not_declared_xyz": "noise"}
    assert "definitely_not_declared_xyz" not in keys
    assert fp(evidence=OAUTH_EVIDENCE) == fp(evidence=undeclared)


def test_missing_material_key_is_distinguishable_from_a_null_value():
    """Absent and explicitly-null must not collide — a disappearing field is a
    material change."""
    without = {k: v for k, v in OAUTH_EVIDENCE.items() if k != "publisher"}
    with_null = {**OAUTH_EVIDENCE, "publisher": None}
    assert fp(evidence=without) != fp(evidence=with_null)
