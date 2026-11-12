"""M3 — audit logging fails closed for security-critical events.

State-changing security actions (offboarding, remediation execution, rollback,
break-glass creation) must NOT be reported as successful if their immutable
audit record cannot be persisted. Informational events (previews, etc.) keep
the prior fail-open behaviour so a transient audit hiccup never blocks a
read-only / no-op event.
"""

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.services import remediation_audit_service
from app.services.audit import audit_logger
from app.services.audit.critical_events import (
    AUDIT_CRITICAL_EVENTS,
    AuditPersistenceError,
)
from app.services.offboarding import offboarding_execute


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class _FailingSession:
    """Stands in for a DB whose write fails at commit time."""

    def add(self, *a, **k):
        pass

    def flush(self, *a, **k):
        pass

    def refresh(self, *a, **k):
        pass

    def commit(self):
        raise RuntimeError("database unavailable")

    def rollback(self):
        pass


# --------------------------------------------------------------------------- #
# Hash-chain audit logger (offboarding uses this).                            #
# On SQLite the pg advisory-lock SQL is unavailable, so the chain write always #
# takes the failure path — a faithful stand-in for a persistence failure.     #
# --------------------------------------------------------------------------- #


def test_hash_chain_audit_fails_closed_for_critical_action():
    session = _make_session()
    with pytest.raises(AuditPersistenceError):
        audit_logger.log_audit_event(
            db=session,
            tenant_id="t1",
            action="OFFBOARDING",
            actor="admin@example.com",
            target="user-1",
            status="SUCCESS",
            reason=None,
            details={"executed_actions": ["disable_account"]},
        )
    session.close()


def test_hash_chain_audit_fails_open_for_informational_action():
    session = _make_session()
    result = audit_logger.log_audit_event(
        db=session,
        tenant_id="t1",
        action="msp_tenant_connected",
        actor="admin@example.com",
        target="t1",
        status="SUCCESS",
        reason=None,
        details={},
    )
    assert result is None
    session.close()


# --------------------------------------------------------------------------- #
# Remediation audit logger (remediation execution + break-glass use this).    #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("event_type", ["EXECUTE_STARTED", "EXECUTED"])
def test_remediation_audit_fails_closed_for_critical_event(event_type):
    with pytest.raises(AuditPersistenceError):
        remediation_audit_service.log_audit_event(
            db=_FailingSession(),
            tenant_id="t1",
            compliance_result_id=1,
            control_id="IDENTITY_UNUSED_ACCOUNT",
            resource_type="user",
            resource_id="user-1",
            event_type=event_type,
        )


def test_remediation_audit_fails_open_for_informational_event():
    result = remediation_audit_service.log_audit_event(
        db=_FailingSession(),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="user",
        resource_id="user-1",
        event_type="PREVIEWED",
    )
    assert result is None


# --------------------------------------------------------------------------- #
# Classification.                                                             #
# --------------------------------------------------------------------------- #


def test_critical_events_cover_state_changing_actions():
    for event in ("OFFBOARDING", "EXECUTE_STARTED", "EXECUTED", "ROLLED_BACK"):
        assert event in AUDIT_CRITICAL_EVENTS
    for event in ("PREVIEWED", "BLOCKED", "FAILED", "APPROVED", "VERIFIED"):
        assert event not in AUDIT_CRITICAL_EVENTS


# --------------------------------------------------------------------------- #
# Offboarding must propagate (not swallow) a critical audit failure.          #
# --------------------------------------------------------------------------- #


class _FakeTenant:
    id = "t1"
    admin_email = "admin@example.com"


def test_offboarding_aborts_when_audit_persistence_fails(monkeypatch):
    async def fake_snapshot(db, tenant, user_id):
        return {"account_enabled": True, "roles": [], "email": "user@example.com"}

    async def fake_token(tenant_id, db=None):
        return "token"

    async def fake_claims(db, tenant):
        return {"tid": tenant.id}

    monkeypatch.setattr(offboarding_execute, "snapshot_user_state", fake_snapshot)
    monkeypatch.setattr(offboarding_execute, "get_valid_access_token", fake_token)
    monkeypatch.setattr(offboarding_execute, "get_tenant_graph_token_claims", fake_claims)
    monkeypatch.setattr(offboarding_execute, "validate_required_graph_permissions", lambda **k: {})

    def raising_audit(**kwargs):
        raise AuditPersistenceError("audit unavailable")

    monkeypatch.setattr(offboarding_execute, "log_audit_event", raising_audit)

    with pytest.raises(AuditPersistenceError):
        asyncio.run(
            offboarding_execute.execute_offboarding(
                db=None,
                tenant=_FakeTenant(),
                user_id="user-1",
                options={
                    "revoke_sessions": False,
                    "remove_admin_roles": False,
                    "disable_account": False,
                },
                reason="test",
            )
        )
