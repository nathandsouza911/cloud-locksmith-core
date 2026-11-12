from datetime import datetime
from sqlalchemy import JSON, Column, Integer, ForeignKey, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db.base import Base


class RemediationSnapshot(Base):
    __tablename__ = "remediation_snapshots"

    id = Column(Integer, primary_key=True, index=True)

    compliance_result_id = Column(
        Integer,
        ForeignKey("compliance_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    state = Column(JSONB, nullable=False)

    # Post-execution state captured atomically with execution success.
    # Immutable after being set once (NULL -> value); required for rollback fidelity.
    state_after = Column(JSONB, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    policy_snapshot = Column(JSON, nullable=True)
    policy_version = Column(Integer, nullable=True)
    policy_hash = Column(String(64), nullable=True, index=True)

    compliance_result = relationship(
        "ComplianceResult",
        backref="snapshots",
    )

    # --------------------------------
    # Enforce Immutability After Insert
    # --------------------------------


from sqlalchemy import event
from sqlalchemy import inspect as sa_inspect


@event.listens_for(RemediationSnapshot, "before_update", propagate=True)
def prevent_snapshot_update(mapper, connection, target):
    # Snapshots are immutable — with ONE narrow exception: the post-execution
    # state_after column may be written exactly once, transitioning from NULL
    # to a concrete value. This is required so rollback can see what the
    # executor actually achieved.
    insp = sa_inspect(target)
    changed_attrs = {key for key, attr in insp.attrs.items() if attr.history.has_changes()}
    if changed_attrs == {"state_after"}:
        history = insp.attrs.state_after.history
        # history.deleted holds the prior DB value for a field with active_history.
        # For JSONB without active_history, it may be empty; treat that as "was NULL".
        previous = history.deleted[0] if history.deleted else None
        if previous is None:
            return
    raise ValueError("RemediationSnapshot rows are immutable and cannot be updated.")
