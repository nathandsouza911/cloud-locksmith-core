"""Persistent review memory — the first workflow-domain model.

A ``WorkflowReviewDecision`` records that a human looked at one resource, in
one workflow, and decided something about it. It is what lets Cloud Locksmith
distinguish *"14 OAuth grants"* from *"10 you already approved and 4 that are
new"*.

Design notes for the future Workflow Engine
-------------------------------------------
This is deliberately **not** a temporary model. When ``workflow_runs`` lands it
consumes these rows directly:

  * A run's review step reads the active decisions for its
    ``(tenant, workflow_type)`` to compute its delta.
  * ``workflow_run_id`` is added later as an additive nullable column, so a
    decision can be attributed to the run that produced it. Rows written now
    simply have it NULL — they remain valid history.
  * Nothing here assumes a run exists, so ad-hoc review (today) and
    run-scoped review (later) write identical rows.

Supersession, not mutation
--------------------------
Decisions are append-only. Re-reviewing a resource writes a new row and points
the previous row's ``superseded_by`` at it. The active decision for a resource
is the one row with ``superseded_by IS NULL``, enforced by a partial unique
index. This keeps a full decision history for audit rather than overwriting it.

Expiry is computed, not stored
------------------------------
A decision whose ``evidence_hash`` no longer matches the current finding is
*stale*. Staleness is derived at read time by the delta engine — no background
job mutates rows, and the historical record stays truthful about what was
decided and when. Time-based expiry is intentionally not implemented yet.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class ReviewDecision:
    """Allowed decision values.

    Two of these suppress a finding from future "new work"; three keep it live.

      KEEP     — reviewed, accepted as-is. Suppresses.
      IGNORE   — reviewed, deliberately not acting. Suppresses.
      FIX      — reviewed, remediation intended *later*. Stays actionable.
      REVOKE   — reviewed, remediation requested *now*. Stays actionable.
      ESCALATE — reviewed, needs someone else. Stays actionable.

    On REVOKE (added Sprint 5). It is a platform-general value, not an OAuth
    one: any workflow with an executor needs to distinguish "someone will deal
    with this" from "act on it now". Conflating the two loses audit fidelity —
    a report cannot otherwise separate "remediations performed" from "items
    triaged for later".

    REVOKE stays ACTIONABLE deliberately. Requesting revocation is not a
    resolution: the grant is still present until the executor removes it and
    verification confirms it. Only then does the finding resolve.
    """

    KEEP = "KEEP"
    IGNORE = "IGNORE"
    FIX = "FIX"
    REVOKE = "REVOKE"
    ESCALATE = "ESCALATE"

    ALL = frozenset({KEEP, IGNORE, FIX, REVOKE, ESCALATE})

    # Decisions that mean "no further action needed on this item".
    SUPPRESSING = frozenset({KEEP, IGNORE})
    # Decisions that mean "triaged, but still open work".
    ACTIONABLE = frozenset({FIX, REVOKE, ESCALATE})


class WorkflowReviewDecision(Base):
    __tablename__ = "workflow_review_decisions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    tenant_id = Column(
        String,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Which recurring review this decision was made inside — e.g. OAUTH_REVIEW.
    # A resource can legitimately be reviewed by two different workflows with
    # different conclusions, so this is part of the identity of a decision.
    workflow_type = Column(String(64), nullable=False, index=True)

    control_id = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(32), nullable=False, default="TENANT")
    resource_id = Column(String(255), nullable=False, default="")

    decision = Column(String(16), nullable=False)
    reason = Column(Text, nullable=True)

    reviewed_by = Column(String(255), nullable=False)
    reviewed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Fingerprint of the evidence at the moment of review. The decision applies
    # only while the current finding still hashes to this value.
    evidence_hash = Column(String(64), nullable=False, index=True)

    # Sprint 4 — the run this decision was made inside.
    #
    # NULLABLE on purpose, and permanently so: rows written before the runtime
    # existed genuinely had no run. Backfilling them with synthetic runs would
    # fabricate execution history in a product whose value is a truthful audit
    # trail. NULL here means exactly "reviewed before runs existed".
    #
    # Review memory does not depend on this column — the delta engine keys on
    # (tenant, workflow, control, resource), so historical decisions keep
    # suppressing findings whether or not they belong to a run.
    workflow_run_id = Column(
        UUID(as_uuid=True),
        ForeignKey("workflow_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Activeness marker. Deliberately separate from ``superseded_by``:
    #
    # ``superseded_by`` is a self-FK, so it cannot be set until the replacement
    # row exists — but the replacement row cannot be inserted while the old row
    # still occupies the unique slot. Splitting the two lets the service retire
    # the old row (UPDATE, no FK dependency), insert the new one, then link
    # them. ``superseded_at`` answers "is this current?"; ``superseded_by``
    # answers "what replaced it?".
    superseded_at = Column(DateTime(timezone=True), nullable=True)

    superseded_by = Column(
        UUID(as_uuid=True),
        ForeignKey("workflow_review_decisions.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        # One active decision per resource per workflow. Partial index, so
        # retired history rows are unconstrained.
        Index(
            "uq_active_review_decision",
            "tenant_id",
            "workflow_type",
            "control_id",
            "resource_id",
            unique=True,
            postgresql_where=Column("superseded_at").is_(None),
            sqlite_where=Column("superseded_at").is_(None),
        ),
        Index(
            "ix_review_decisions_tenant_workflow_active",
            "tenant_id",
            "workflow_type",
            "superseded_at",
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<WorkflowReviewDecision {self.workflow_type}/{self.control_id}" f"/{self.resource_id} {self.decision}>"
