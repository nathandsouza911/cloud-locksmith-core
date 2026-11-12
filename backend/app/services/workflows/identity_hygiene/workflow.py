"""Identity Hygiene Review.

Note what is absent: no discovery code, no projection code, no delta handling,
no decision recording, no remediation path and no report envelope. All of that
is the platform's. This workflow supplies risk classification and one report
section, and that is the whole of it.

Remediation is simpler here than in OAuth Review: the default projector is 1:1,
so each review resource *is* a finding, and
``execute_approved_remediation(compliance_result_id=...)`` acts on it directly
through the existing executors. No selection payload is needed.
"""

from __future__ import annotations

from collections import Counter

from app.services.workflows._shared.projector import FindingProjector
from app.services.workflows.identity_hygiene.risk import classify_finding

WORKFLOW_ID = "IDENTITY_HYGIENE"


class IdentityHygieneProjector(FindingProjector):
    """The default 1:1 projector, plus this workflow's report section."""

    def __init__(self) -> None:
        super().__init__(WORKFLOW_ID, classify=classify_finding)

    def report_sections(self, review, decisions) -> dict:
        """Hygiene-specific reporting: what kind of cleanup this run represented.

        Built from the review and its decisions — never from a fresh query — so
        the section is consistent with the rest of the report.
        """
        by_control = Counter(entry.control_id for entry in decisions)
        outstanding_by_control = Counter(
            resource.control_id for resource in review.resources if resource.needs_attention
        )
        return {
            "decisions_by_control": dict(sorted(by_control.items())),
            "outstanding_by_control": dict(sorted(outstanding_by_control.items())),
            "risk_profile": dict(sorted(Counter(r.risk_level for r in review.resources).items())),
        }


IDENTITY_HYGIENE_PROJECTOR = IdentityHygieneProjector()
