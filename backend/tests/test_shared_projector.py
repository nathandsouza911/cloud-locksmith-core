"""Projectors — how findings become reviewable resources.

Two shapes cover every workflow in V1: one finding per resource (the default),
and one finding fanning out into many (OAuth's consent grants).
"""

import copy
from types import SimpleNamespace

from app.services.workflows._shared.projector import (
    EvidenceFanOutProjector,
    FindingProjector,
)
from app.services.workflows._shared.resource_key import ResourceKey
from app.services.workflows._shared.resources import ResourceFact, ReviewResource
from app.services.workflows._shared.risk import RiskAssessment, RiskLevel


def _finding(control_id="IDENTITY_USER_NO_MFA", resource_id="user-1", **kw):
    defaults = dict(
        id=1,
        tenant_id="t1",
        control_id=control_id,
        resource_type="USER",
        resource_id=resource_id,
        severity="HIGH",
        evidence={"user_principal_name": "alice@contoso.com"},
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


# ── FindingProjector ────────────────────────────────────────────────────────


def test_finding_projector_produces_one_resource_per_finding():
    projector = FindingProjector("IDENTITY_HYGIENE")
    resources = projector.project([_finding(resource_id="u1"), _finding(resource_id="u2")])
    assert sorted(r.resource_id for r in resources) == ["u1", "u2"]


def test_finding_projector_keys_on_control_and_resource():
    [resource] = FindingProjector("IDENTITY_HYGIENE").project([_finding()])
    assert resource.key == ResourceKey("IDENTITY_USER_NO_MFA", "user-1")


def test_finding_projector_fingerprints_using_the_platform_function():
    """The hash must match what fingerprint_finding produces, or a decision
    recorded by one path would look stale to the other."""
    from app.services.work.evidence_fingerprint import fingerprint_finding

    finding = _finding()
    [resource] = FindingProjector("IDENTITY_HYGIENE").project([finding])
    assert resource.evidence_hash == fingerprint_finding(finding)


def test_finding_projector_carries_the_finding_id_for_remediation():
    [resource] = FindingProjector("IDENTITY_HYGIENE").project([_finding(id=42)])
    assert resource.compliance_result_id == 42


def test_projecting_never_mutates_the_finding_or_its_evidence():
    finding = _finding()
    before = copy.deepcopy(finding.evidence)
    FindingProjector("IDENTITY_HYGIENE").project([finding])
    assert finding.evidence == before


def test_finding_projector_uses_the_supplied_risk_classifier():
    def classify(finding):
        return RiskAssessment(
            level=RiskLevel.CRITICAL,
            explanation="Because I said so.",
            recommended_action="REVOKE",
            drivers=["test:driver"],
        )

    [resource] = FindingProjector("IDENTITY_HYGIENE", classify=classify).project([_finding()])
    assert resource.risk_level == RiskLevel.CRITICAL
    assert resource.risk_explanation == "Because I said so."
    assert resource.risk_drivers == ["test:driver"]


def test_finding_projector_falls_back_to_severity_when_no_classifier_given():
    """Without a classifier the finding's own severity is the honest answer —
    inventing a level would be worse than reusing what detection said."""
    [resource] = FindingProjector("IDENTITY_HYGIENE").project([_finding(severity="CRITICAL")])
    assert resource.risk_level == RiskLevel.CRITICAL


def test_unknown_severity_becomes_medium_not_low():
    """An unclassified risk is not evidence that it is safe."""
    [resource] = FindingProjector("IDENTITY_HYGIENE").project([_finding(severity="BANANA")])
    assert resource.risk_level == RiskLevel.MEDIUM


def test_finding_projector_defaults_controls_to_the_registry():
    assert "IDENTITY_USER_NO_MFA" in FindingProjector("IDENTITY_HYGIENE").controls()


def test_finding_projector_orders_riskiest_first_then_stably_by_key():
    findings = [
        _finding(resource_id="b", severity="LOW"),
        _finding(resource_id="a", severity="CRITICAL"),
        _finding(resource_id="c", severity="CRITICAL"),
    ]
    resources = FindingProjector("IDENTITY_HYGIENE").project(findings)
    assert [r.resource_id for r in resources] == ["a", "c", "b"]


def test_finding_with_no_resource_id_still_projects_as_a_tenant_level_item():
    [resource] = FindingProjector("IDENTITY_HYGIENE").project([_finding(resource_id=None, resource_type="TENANT")])
    assert resource.resource_id == ""


# ── EvidenceFanOutProjector ─────────────────────────────────────────────────


def _fanout_projector():
    def build(entry, finding):
        return ReviewResource(
            key=ResourceKey("IDENTITY_ILLICIT_CONSENT_GRANTS", entry["id"]),
            resource_type="SERVICE_PRINCIPAL",
            title=entry.get("app_display_name") or entry["id"],
            subtitle=None,
            risk_level=RiskLevel.HIGH,
            risk_explanation="Broad read access.",
            recommended_action="REVIEW",
            facts=[ResourceFact("Scope", entry.get("scope"))],
            evidence=dict(entry),
            evidence_hash=f"hash-{entry['id']}",
            compliance_result_id=getattr(finding, "id", None),
        )

    return EvidenceFanOutProjector(
        "OAUTH_REVIEW",
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        evidence_path="illicit_grants",
        id_field="id",
        resource_type="SERVICE_PRINCIPAL",
        build=build,
    )


def test_fanout_projects_one_resource_per_evidence_entry():
    finding = _finding(
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_type="TENANT",
        resource_id="t1",
        evidence={"illicit_grants": [{"id": "g1"}, {"id": "g2"}]},
    )
    resources = _fanout_projector().project([finding])
    assert sorted(r.resource_id for r in resources) == ["g1", "g2"]


def test_fanout_skips_entries_with_no_id():
    """No identity means it cannot be reviewed or remediated safely."""
    finding = _finding(
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        evidence={"illicit_grants": [{"id": "g1"}, {"no_id": True}]},
    )
    assert len(_fanout_projector().project([finding])) == 1


def test_fanout_skips_non_dict_entries():
    finding = _finding(
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        evidence={"illicit_grants": [{"id": "g1"}, "not-a-dict", None]},
    )
    assert len(_fanout_projector().project([finding])) == 1


def test_fanout_on_missing_evidence_returns_nothing_rather_than_raising():
    finding = _finding(control_id="IDENTITY_ILLICIT_CONSENT_GRANTS", evidence=None)
    assert _fanout_projector().project([finding]) == []


def test_fanout_never_mutates_the_findings_evidence():
    evidence = {"illicit_grants": [{"id": "g1", "scope": "Mail.Read"}]}
    finding = _finding(control_id="IDENTITY_ILLICIT_CONSENT_GRANTS", evidence=evidence)
    before = copy.deepcopy(evidence)
    _fanout_projector().project([finding])
    assert evidence == before


def test_fanout_ignores_findings_for_other_controls():
    assert _fanout_projector().project([_finding(control_id="IDENTITY_USER_NO_MFA")]) == []
