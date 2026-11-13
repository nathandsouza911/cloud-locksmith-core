"""A second execute or rollback of the same finding is refused at once (live run L20).

2026-11-13: two concurrent executes of one finding froze the whole API for 20 minutes.
The first request locked the finding row (SELECT ... FOR UPDATE) and then awaited a
network call; the second request's lock wait is a synchronous database call inside an
async endpoint, so it blocked the event loop and the first request could never finish.

The finding lock is now taken with NOWAIT: if another request holds it, the call
returns immediately ("already executing" / 409) instead of waiting.
"""

import asyncio
import threading

from fastapi import HTTPException
from sqlalchemy import text

from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.db.session import SyncSessionLocal, sync_engine

WAIT_LIMIT_SECONDS = 5


def _seed(db, status: str):
    tenant = Tenant(id="tenant-nowait", tenant_name="nowait")
    db.add(tenant)
    db.commit()
    finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status=status,
        decision_status=status,
    )
    db.add(finding)
    db.commit()
    return tenant.id, finding.id


def _run_while_row_is_locked(finding_id: int, call):
    """Hold the finding's row lock on another connection and run ``call`` in a thread."""
    outcome: dict = {}
    holder = sync_engine.connect()
    holder.begin()
    holder.execute(text("SELECT id FROM compliance_results WHERE id = :id FOR UPDATE"), {"id": finding_id})

    def worker():
        session = SyncSessionLocal()
        try:
            outcome["value"] = call(session)
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            session.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=WAIT_LIMIT_SECONDS)
    finished = not thread.is_alive()
    holder.rollback()
    holder.close()
    thread.join(timeout=10)
    return finished, outcome


def test_execute_returns_at_once_when_the_finding_is_locked(db_session):
    from app.services.remediation_execution_service import execute_approved_remediation

    tenant_id, finding_id = _seed(db_session, "APPROVED")

    def call(session):
        tenant = session.get(Tenant, tenant_id)
        return asyncio.run(
            execute_approved_remediation(
                db=session, compliance_result_id=finding_id, tenant=tenant, tenant_id=tenant_id
            )
        )

    finished, outcome = _run_while_row_is_locked(finding_id, call)
    assert finished, "execute waited on the row lock (this blocks the event loop in the API)"
    assert outcome.get("value") == {"status": "already_executing"}


def test_rollback_returns_409_at_once_when_the_finding_is_locked(db_session):
    from app.api.v1 import remediation_rollback as rollback_api

    tenant_id, finding_id = _seed(db_session, "SUCCESS")

    def call(session):
        tenant = session.get(Tenant, tenant_id)
        return asyncio.run(
            rollback_api.rollback_remediation(
                compliance_result_id=finding_id, payload=None, db=session, current_tenant=tenant
            )
        )

    finished, outcome = _run_while_row_is_locked(finding_id, call)
    assert finished, "rollback waited on the row lock (this blocks the event loop in the API)"
    error = outcome.get("error")
    assert isinstance(error, HTTPException) and error.status_code == 409
