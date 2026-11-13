"""Row lock on a finding that never waits.

The remediation endpoints are async but use a synchronous SQLAlchemy session. A
blocking ``SELECT ... FOR UPDATE`` that has to wait for another request's lock
blocks the whole event loop, so the request holding the lock can never finish:
in the 2026-11-13 live run two concurrent executes of one finding froze the API.
NOWAIT makes the second request fail at once instead.
"""

from __future__ import annotations

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult

_LOCK_NOT_AVAILABLE = "55P03"


class FindingBusyError(Exception):
    """Another request holds this finding (execute or rollback in progress)."""


def lock_finding_nowait(db: Session, *, compliance_result_id: int, tenant_id: str) -> ComplianceResult | None:
    try:
        return (
            db.query(ComplianceResult)
            .filter(
                ComplianceResult.id == compliance_result_id,
                ComplianceResult.tenant_id == tenant_id,
            )
            .with_for_update(nowait=True)
            .one_or_none()
        )
    except OperationalError as exc:
        if getattr(getattr(exc, "orig", None), "pgcode", None) == _LOCK_NOT_AVAILABLE:
            db.rollback()
            raise FindingBusyError("Another remediation for this finding is in progress") from exc
        raise
