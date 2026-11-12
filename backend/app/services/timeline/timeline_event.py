"""The normalised event a Client Timeline is made of.

Every source system has its own schema. This is the single shape they are all
projected into so the UI can render one chronological narrative.

Nothing here is persisted. The timeline **consumes** existing storage and never
duplicates it — a ``TimelineEvent`` is built on read and thrown away.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class SourceSystem:
    """Which existing subsystem an event was projected from."""

    REVIEW_DECISIONS = "REVIEW_DECISIONS"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    AUDIT_LOG = "AUDIT_LOG"
    REPORTS = "REPORTS"
    POSTURE_SNAPSHOT = "POSTURE_SNAPSHOT"
    # Reserved: the Workflow Engine will add WORKFLOW_RUN without any change to
    # the merge/pagination logic — it only has to emit TimelineEvents.
    WORKFLOW_RUN = "WORKFLOW_RUN"

    ALL = (
        REVIEW_DECISIONS,
        REMEDIATION,
        VERIFICATION,
        AUDIT_LOG,
        REPORTS,
        POSTURE_SNAPSHOT,
        WORKFLOW_RUN,
    )


class TimelineEventType:
    """What kind of thing happened, independent of which table it came from."""

    REVIEW_DECISION = "REVIEW_DECISION"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    AUDIT = "AUDIT"
    REPORT_GENERATED = "REPORT_GENERATED"
    POSTURE_SNAPSHOT = "POSTURE_SNAPSHOT"
    WORKFLOW_RUN = "WORKFLOW_RUN"

    ALL = (
        REVIEW_DECISION,
        REMEDIATION,
        VERIFICATION,
        AUDIT,
        REPORT_GENERATED,
        POSTURE_SNAPSHOT,
        WORKFLOW_RUN,
    )


@dataclass(frozen=True)
class TimelineEvent:
    # Globally unique across sources: "<source>:<native id>". Native ids are
    # only unique within their own table.
    id: str
    tenant_id: str
    timestamp: datetime
    source_system: str
    event_type: str

    # What happened, in the narrative sense.
    action: str
    title: str
    description: str | None = None

    # Who did it. None for system-generated events.
    actor: str | None = None

    # How it turned out — decision value, execution status, report type, score.
    outcome: str | None = None

    # Which workflow this belongs to, resolved through the registry where the
    # source carries a control_id. None for events with no workflow context.
    workflow_id: str | None = None
    workflow_name: str | None = None

    # Pointer into durable evidence: an audit chain hash, a report content hash,
    # an evidence fingerprint. Lets the UI offer "verify this".
    evidence_reference: str | None = None

    control_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None

    # Source-specific extras the UI may render but must not depend on.
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def sort_key(self) -> tuple:
        """Deterministic ordering key.

        Timestamp alone is not enough: several systems can write in the same
        second, and an unstable order would make cursor pagination skip or
        repeat rows. Source and id break the tie.
        """
        return (self.timestamp, self.source_system, self.id)
