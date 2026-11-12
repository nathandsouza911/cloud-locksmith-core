"""Projection — the one seam where workflow-specific discovery enters.

Everything downstream (delta, review memory, progress, remediation, reporting)
consumes ``ReviewResource`` and never looks at a finding again. That is what lets
a new workflow be added without touching the platform: it supplies a projector
and nothing else.

Two shapes cover V1:

  FindingProjector          one finding -> one resource. The default. A workflow
                            whose detectors already emit per-resource findings
                            writes no projection code at all.
  EvidenceFanOutProjector   one finding -> many resources, for detectors that
                            emit a single tenant-level finding carrying a list
                            (OAuth's consent grants).

**Projection is read-only.** It never splits, re-detects or mutates a finding —
``test_projecting_never_mutates_the_finding_or_its_evidence`` enforces that.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Protocol, runtime_checkable

from app.services.reports.control_presentation import enrich_control
from app.services.work.evidence_fingerprint import fingerprint_finding
from app.services.work.workflow_registry import controls_for
from app.services.workflows._shared.resource_key import ResourceKey
from app.services.workflows._shared.resources import ResourceFact, ReviewResource
from app.services.workflows._shared.risk import RiskAssessment, RiskLevel

logger = logging.getLogger(__name__)


@runtime_checkable
class ResourceProjector(Protocol):
    """What a workflow must supply to become reviewable."""

    workflow_id: str

    def controls(self) -> tuple[str, ...]:
        """Control ids whose findings this workflow reviews."""
        ...

    def project(self, findings: list) -> list[ReviewResource]:
        """Turn findings into reviewable resources. Must not mutate them."""
        ...


def _control_name(control_id: str) -> str:
    """Business-language control name, falling back to the id.

    ``enrich_control`` is shared with the work queue and must not be changed
    here, so an unknown control is handled on this side.
    """
    try:
        return enrich_control(control_id, include_cost_estimate=False)["name"]
    except Exception:  # pragma: no cover - defensive
        logger.debug("control_presentation_missing control_id=%s", control_id)
        return control_id


def _severity_as_risk(severity: Any) -> str:
    """A finding's own severity, used when a workflow supplies no classifier.

    Unknown severities become MEDIUM rather than LOW: a severity we cannot
    interpret is not evidence that the finding is safe.
    """
    value = str(severity or "").upper()
    return value if value in RiskLevel.ALL else RiskLevel.MEDIUM


def _finding_title(finding, evidence: dict, control_name: str) -> str:
    """The most human identity available for this resource."""
    for field_name in ("user_principal_name", "display_name", "app_display_name"):
        value = evidence.get(field_name)
        if value:
            return str(value)
    resource_id = getattr(finding, "resource_id", None)
    return str(resource_id) if resource_id else control_name


def _facts_from_evidence(evidence: dict) -> list[ResourceFact]:
    """Labelled rows for the detail panel, from whatever the detector emitted.

    Deliberately shallow: nested structures stay in ``evidence`` for the raw view
    rather than being flattened into misleading one-line facts.
    """
    return [
        ResourceFact(label=key.replace("_", " ").capitalize(), value=value)
        for key, value in sorted(evidence.items())
        if not isinstance(value, (dict, list))
    ]


class FindingProjector:
    """One finding, one resource. The default for well-shaped detectors."""

    def __init__(
        self,
        workflow_id: str,
        *,
        classify: Callable[[Any], RiskAssessment] | None = None,
        controls: tuple[str, ...] | None = None,
    ) -> None:
        self.workflow_id = workflow_id
        self._classify = classify
        self._controls = controls

    def controls(self) -> tuple[str, ...]:
        """Declared controls, defaulting to the registry's for this workflow."""
        if self._controls is not None:
            return self._controls
        return controls_for(self.workflow_id)

    def _assess(self, finding) -> RiskAssessment:
        if self._classify is not None:
            return self._classify(finding)
        return RiskAssessment(
            level=_severity_as_risk(getattr(finding, "severity", None)),
            explanation=_control_name(getattr(finding, "control_id", "")),
            recommended_action="REVIEW",
        )

    def project(self, findings: list) -> list[ReviewResource]:
        resources: list[ReviewResource] = []

        for finding in findings:
            key = ResourceKey.from_finding(finding)
            assessment = self._assess(finding)
            name = _control_name(key.control_id)
            evidence = getattr(finding, "evidence", None) or {}

            resources.append(
                ReviewResource(
                    key=key,
                    resource_type=getattr(finding, "resource_type", None) or "TENANT",
                    title=_finding_title(finding, evidence, name),
                    subtitle=name,
                    risk_level=assessment.level,
                    risk_explanation=assessment.explanation,
                    recommended_action=assessment.recommended_action,
                    risk_drivers=list(assessment.drivers),
                    facts=_facts_from_evidence(evidence),
                    # Copied, not referenced: the resource is immutable and must
                    # not become an alias onto the ORM object's dict.
                    evidence=dict(evidence),
                    evidence_hash=fingerprint_finding(finding),
                    compliance_result_id=getattr(finding, "id", None),
                )
            )

        # Riskiest first, then stably by key so a refresh never reshuffles.
        resources.sort(key=lambda r: (RiskLevel.rank(r.risk_level), r.key.as_tuple()))
        return resources


class EvidenceFanOutProjector:
    """One finding carrying a list, projected into one resource per entry.

    ``build`` is the workflow's own function: this class owns the traversal and
    the safety rules (skip entries without an id, never mutate evidence), the
    workflow owns what a resource looks like.
    """

    def __init__(
        self,
        workflow_id: str,
        *,
        control_id: str,
        evidence_path: str,
        id_field: str,
        resource_type: str,
        build: Callable[[dict, Any], ReviewResource],
    ) -> None:
        self.workflow_id = workflow_id
        self.control_id = control_id
        self.evidence_path = evidence_path
        self.id_field = id_field
        self.resource_type = resource_type
        self._build = build

    def controls(self) -> tuple[str, ...]:
        return (self.control_id,)

    def entries(self, evidence: dict | None) -> list[dict]:
        """The reviewable entries inside one finding's evidence.

        Public because remediation resolves caller-supplied ids against exactly
        this list — the two must never drift apart.
        """
        if not isinstance(evidence, dict):
            return []
        raw = evidence.get(self.evidence_path) or []
        return [entry for entry in raw if isinstance(entry, dict)]

    def project(self, findings: list) -> list[ReviewResource]:
        resources: list[ReviewResource] = []

        for finding in findings:
            if getattr(finding, "control_id", None) != self.control_id:
                continue
            for entry in self.entries(getattr(finding, "evidence", None)):
                if not entry.get(self.id_field):
                    # No identity means it cannot be reviewed or remediated.
                    logger.debug(
                        "fanout_entry_skipped workflow=%s reason=no_id",
                        self.workflow_id,
                    )
                    continue
                resources.append(self._build(entry, finding))

        resources.sort(key=lambda r: (RiskLevel.rank(r.risk_level), r.key.as_tuple()))
        return resources
