"""OAuth Review discovery — the only projection code this workflow needs.

The detectors each emit one tenant-level finding whose evidence carries a
list; a technician reviews one *application*/*grant* at a time. That is
exactly the fan-out shape, so each control gets its own
``EvidenceFanOutProjector``.

OAUTH_REVIEW now covers two independently-fanned-out controls
(``IDENTITY_ILLICIT_CONSENT_GRANTS`` and the Gate 2 validation slice
``IDENTITY_OAUTH_APP_CONSENT_DISCOVERY``). The platform's projector registry
allows exactly one projector per workflow_id (registering twice raises), so
``_CompositeProjector`` dispatches ``project()`` across both single-control
projectors and concatenates their resources. This does not touch
``EvidenceFanOutProjector`` or the illicit-consent-grants projector's own
tested behavior at all — it is a thin fan-out-of-fan-outs, not a new
architecture.
"""

from __future__ import annotations

from app.services.workflows._shared.projector import EvidenceFanOutProjector
from app.services.workflows._shared.resources import ReviewResource
from app.services.workflows._shared.risk import RiskLevel
from app.services.workflows.oauth_review.consent_discovery_resources import (
    CONSENT_DISCOVERY_CONTROL_ID,
    build_consent_discovery_resource,
)
from app.services.workflows.oauth_review.resources import (
    CONTROL_ID,
    WORKFLOW_ID,
    build_oauth_resource,
)


class _CompositeProjector:
    """Dispatches project() across several single-workflow projectors.

    Exists solely because the projector registry is one-projector-per-
    workflow. Each delegate projector already filters findings to its own
    control_id internally, so passing the full findings list to every
    delegate is safe — irrelevant findings are simply ignored.
    """

    def __init__(self, workflow_id: str, projectors: tuple) -> None:
        self.workflow_id = workflow_id
        self._projectors = projectors

    def controls(self) -> tuple[str, ...]:
        seen: list[str] = []
        for projector in self._projectors:
            for control_id in projector.controls():
                if control_id not in seen:
                    seen.append(control_id)
        return tuple(seen)

    def project(self, findings: list) -> list[ReviewResource]:
        resources: list[ReviewResource] = []
        for projector in self._projectors:
            resources.extend(projector.project(findings))
        resources.sort(key=lambda r: (RiskLevel.rank(r.risk_level), r.key.as_tuple()))
        return resources


def build_projector() -> _CompositeProjector:
    illicit_grants_projector = EvidenceFanOutProjector(
        WORKFLOW_ID,
        control_id=CONTROL_ID,
        evidence_path="illicit_grants",
        id_field="id",
        resource_type="SERVICE_PRINCIPAL",
        build=build_oauth_resource,
    )
    consent_discovery_projector = EvidenceFanOutProjector(
        WORKFLOW_ID,
        control_id=CONSENT_DISCOVERY_CONTROL_ID,
        evidence_path="oauth_app_consents",
        id_field="grant_id",
        resource_type="SERVICE_PRINCIPAL",
        build=build_consent_discovery_resource,
    )
    return _CompositeProjector(WORKFLOW_ID, (illicit_grants_projector, consent_discovery_projector))


OAUTH_REVIEW_PROJECTOR = build_projector()
