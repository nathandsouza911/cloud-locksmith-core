"""Regression: fingerprints must be computed over REAL detector output.

Sprint 2 declared material-key allowlists using snake_case names, but several
detectors emit Microsoft Graph's camelCase. Where the two disagreed, every
declared key resolved to "absent", the material part of the hash was constant,
and a materially changed resource kept its stale review decision — the exact
security hole the fingerprint exists to prevent.

The Sprint 2 tests missed it because they used invented evidence shapes. These
tests use the shapes the detectors actually produce.

Two fixes are asserted here:
  1. The OAuth allowlist covers the keys the detector really emits.
  2. Generally: an allowlist that matches nothing in the evidence is treated as
     no allowlist at all, so a mis-declared control degrades to safe
     over-sensitivity instead of dangerous permissiveness.
"""

import pytest

from app.services.work.evidence_fingerprint import (
    MATERIAL_EVIDENCE_KEYS,
    compute_evidence_fingerprint,
)

# Exactly the shape illicit_consent_grants_detector puts in evidence.
GRANT = {
    "id": "grant-1",
    "clientId": "app-1",
    "resourceId": "resource-1",
    "principalId": "user-1",
    "consentType": "Principal",
    "scope": "Mail.Read Files.Read.All",
    "matched_scopes": ["Files.Read.All", "Mail.Read"],
}


def _fp(evidence, *, control_id="IDENTITY_ILLICIT_CONSENT_GRANTS", resource_id="grant-1"):
    return compute_evidence_fingerprint(
        control_id=control_id,
        resource_type="SERVICE_PRINCIPAL",
        resource_id=resource_id,
        evidence=evidence,
    )


# ── The security cases, against the real evidence shape ─────────────────────


def test_scope_escalation_on_a_real_grant_changes_the_fingerprint():
    escalated = {
        **GRANT,
        "scope": "Mail.Read Files.Read.All Mail.ReadWrite",
        "matched_scopes": ["Files.Read.All", "Mail.Read", "Mail.ReadWrite"],
    }
    assert _fp(GRANT) != _fp(escalated)


def test_consent_widening_on_a_real_grant_changes_the_fingerprint():
    """User-consent widened to the entire tenant must never stay 'reviewed'."""
    tenant_wide = {**GRANT, "consentType": "AllPrincipals", "principalId": None}
    assert _fp(GRANT) != _fp(tenant_wide)


def test_a_different_client_on_a_real_grant_changes_the_fingerprint():
    assert _fp(GRANT) != _fp({**GRANT, "clientId": "app-999"})


def test_a_different_principal_on_a_real_grant_changes_the_fingerprint():
    assert _fp(GRANT) != _fp({**GRANT, "principalId": "user-999"})


def test_reordering_matched_scopes_on_a_real_grant_does_not_change_it():
    reordered = {**GRANT, "matched_scopes": ["Mail.Read", "Files.Read.All"]}
    assert _fp(GRANT) == _fp(reordered)


def test_the_oauth_allowlist_actually_matches_the_detector_output():
    """At least one declared material key must be present in real evidence."""
    declared = set(MATERIAL_EVIDENCE_KEYS["IDENTITY_ILLICIT_CONSENT_GRANTS"])
    assert declared & set(GRANT), (
        "OAuth allowlist declares no key the detector emits — the material part " "of the hash would be constant"
    )


# ── The general safety net ──────────────────────────────────────────────────


def test_an_allowlist_that_matches_nothing_degrades_to_full_payload_hashing():
    """A mis-declared allowlist must fail safe (over-sensitive), never
    permissive.

    Simulates a control whose declared keys are all absent from the evidence:
    the fingerprint must still react to changes rather than being constant.
    """
    control = "IDENTITY_USER_CONSENT_POLICY"  # declares consent_policy, ...
    unrelated_a = {"totally": "different", "shape": 1}
    unrelated_b = {"totally": "different", "shape": 2}

    assert not set(MATERIAL_EVIDENCE_KEYS[control]) & set(unrelated_a)
    assert _fp(unrelated_a, control_id=control) != _fp(unrelated_b, control_id=control)


def test_the_safety_net_still_ignores_volatile_keys():
    control = "IDENTITY_USER_CONSENT_POLICY"
    base = {"unmatched": "x"}
    noisy = {"unmatched": "x", "last_seen_at": "2026-08-05T00:00:00"}

    assert _fp(base, control_id=control) == _fp(noisy, control_id=control)


def test_a_partially_matching_allowlist_still_uses_the_allowlist():
    """One matching key is enough — the allowlist is doing its job, and
    unrelated additions must stay non-material."""
    partial = {"clientId": "app-1"}
    with_noise = {"clientId": "app-1", "irrelevant_display_field": "noise"}

    assert _fp(partial) == _fp(with_noise)


@pytest.mark.parametrize("control_id", sorted(MATERIAL_EVIDENCE_KEYS))
def test_every_allowlist_is_non_empty(control_id):
    assert MATERIAL_EVIDENCE_KEYS[control_id], control_id
