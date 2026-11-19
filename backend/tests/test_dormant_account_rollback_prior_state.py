"""Review R2-20: dormant-account rollback restores the prior state, never more.

Before the fix:
- the snapshot read ``is_active`` (the Google adapter's key); the Microsoft
  adapter returns ``accountEnabled``, so the snapshot always said "enabled";
- the rollback ignored the snapshot and always re-enabled the account, so an
  account an admin had disabled before the fix was switched back on;
- the executed-audit lookup was not scoped to the tenant.
"""

import asyncio

import pytest

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant
from app.services.remediation.dormant_account_execute import DormantAccountExecutor
from app.services.remediation.rollback import dormant_account_rollback_executor as rollback_module
from app.services.remediation.rollback.dormant_account_rollback_executor import (
    DormantAccountRollbackError,
    rollback_dormant_account,
)

USER_ID = "user-dormant-1"


class _FakeAdapter:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.set_calls: list[bool] = []

    async def set_user_account_enabled(self, user_id, enabled):
        self.set_calls.append(enabled)
        self.enabled = enabled

    async def get_user_account_state(self, user_id):
        return {"id": user_id, "accountEnabled": self.enabled}


def _seed(db_session, *, tenant_id: str, audit_tenant_id: str | None = None, prior_enabled: bool = True) -> int:
    for tid in {tenant_id, audit_tenant_id or tenant_id}:
        if db_session.get(Tenant, tid) is None:
            db_session.add(Tenant(id=tid, tenant_name=tid))
    db_session.commit()
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id=USER_ID,
        framework="identity",
        passed=False,
        severity="MEDIUM",
        evidence={"user_id": USER_ID},
    )
    db_session.add(finding)
    db_session.commit()
    db_session.add(
        RemediationSnapshot(
            compliance_result_id=finding.id, state={"user_id": USER_ID, "accountEnabled": prior_enabled}
        )
    )
    db_session.add(
        RemediationAuditLog(
            tenant_id=audit_tenant_id or tenant_id,
            compliance_result_id=finding.id,
            control_id="IDENTITY_UNUSED_ACCOUNT",
            resource_type="USER",
            resource_id=USER_ID,
            decision="EXECUTED",
        )
    )
    db_session.commit()
    return finding.id


def test_snapshot_reads_microsoft_account_state():
    class _Graph:
        async def get_user_account_state(self, user_id):
            return {"id": user_id, "accountEnabled": False}

    snapshot = asyncio.run(DormantAccountExecutor().build_snapshot(_Graph(), {"user_id": USER_ID}))

    assert snapshot["accountEnabled"] is False


def test_rollback_re_enables_an_account_that_was_enabled(db_session, monkeypatch):
    finding_id = _seed(db_session, tenant_id="tenant-a", prior_enabled=True)
    adapter = _FakeAdapter(enabled=False)
    monkeypatch.setattr(rollback_module, "get_identity_provider_adapter", lambda **kwargs: adapter)

    result = asyncio.run(
        rollback_dormant_account(
            db=db_session,
            tenant=db_session.get(Tenant, "tenant-a"),
            compliance_result_id=finding_id,
            reason="test",
            requested_by="test",
        )
    )

    assert adapter.set_calls == [True]
    assert result["user_enabled"] is True


def test_rollback_leaves_an_account_that_was_already_disabled_disabled(db_session, monkeypatch):
    finding_id = _seed(db_session, tenant_id="tenant-b", prior_enabled=False)
    adapter = _FakeAdapter(enabled=False)
    monkeypatch.setattr(rollback_module, "get_identity_provider_adapter", lambda **kwargs: adapter)

    result = asyncio.run(
        rollback_dormant_account(
            db=db_session,
            tenant=db_session.get(Tenant, "tenant-b"),
            compliance_result_id=finding_id,
            reason="test",
            requested_by="test",
        )
    )

    assert adapter.set_calls == []
    assert result["user_enabled"] is False


def test_rollback_refuses_a_finding_of_another_tenant(db_session, monkeypatch):
    finding_id = _seed(db_session, tenant_id="tenant-owner", prior_enabled=True)
    db_session.add(Tenant(id="tenant-caller", tenant_name="tenant-caller"))
    db_session.commit()
    adapter = _FakeAdapter(enabled=False)
    monkeypatch.setattr(rollback_module, "get_identity_provider_adapter", lambda **kwargs: adapter)

    with pytest.raises(DormantAccountRollbackError):
        asyncio.run(
            rollback_dormant_account(
                db=db_session,
                tenant=db_session.get(Tenant, "tenant-caller"),
                compliance_result_id=finding_id,
                reason="test",
                requested_by="test",
            )
        )

    assert adapter.set_calls == []
