import asyncio
import logging

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB

from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.jobs import auto_execute_remediations
from app.services.remediation.execution.execution_eligibility import (
    check_execution_eligibility,
)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


def _create_tenant(db_session, tenant_id: str = "tenant-auto") -> Tenant:
    tenant = Tenant(
        id=tenant_id,
        tenant_name="Auto Tenant",
        oauth_token={"access_token": "token"},
    )
    db_session.add(tenant)
    db_session.commit()
    return tenant


class _SessionProxy:
    def __init__(self, session):
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    def close(self):
        return None


def _create_finding(
    db_session,
    *,
    tenant_id: str,
    control_id: str,
    resource_id: str,
    remediation_status: str = "PENDING",
    execution_attempts: int = 0,
    evidence: dict | None = None,
) -> ComplianceResult:
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="USER" if control_id == "IDENTITY_UNUSED_ACCOUNT" else "TENANT",
        resource_id=resource_id,
        severity="HIGH",
        passed=False,
        evidence=evidence or {},
        remediation_status=remediation_status,
        decision_status=remediation_status,
        execution_attempts=execution_attempts,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


def test_execution_eligibility_rejects_failed_and_attempt_limit(db_session):
    tenant = _create_tenant(db_session, "tenant-eligibility")
    failed = _create_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-failed",
        remediation_status="FAILED",
        evidence={"user_id": "user-failed", "account_enabled": True},
    )
    over_limit = _create_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-limit",
        remediation_status="APPROVED",
        execution_attempts=3,
        evidence={"user_id": "user-limit", "account_enabled": True},
    )

    failed_result = check_execution_eligibility(
        db=db_session,
        compliance_result_id=failed.id,
    )
    over_limit_result = check_execution_eligibility(
        db=db_session,
        compliance_result_id=over_limit.id,
    )

    assert failed_result["eligible"] is False
    assert failed_result["reason"] == "FAILED remediations must be approved before retry"
    assert over_limit_result["eligible"] is False
    assert over_limit_result["reason"] == "Execution attempt limit reached"


def test_auto_remediation_never_fetches_guest_invites_findings(monkeypatch, db_session, caplog):
    """F-2 mechanism: IDENTITY_GUEST_INVITES_OPEN is excluded from AUTO_REMEDIATION_CONTROLS,
    so its findings are never fetched by the job query — the DANGEROUS gate is irrelevant."""
    tenant = _create_tenant(db_session, "tenant-dangerous")
    finding = _create_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_id=tenant.id,
        evidence={},
    )

    async def fail_if_called(**kwargs):
        raise AssertionError("IDENTITY_GUEST_INVITES_OPEN must never be auto-executed")

    monkeypatch.setattr(
        auto_execute_remediations,
        "SyncSessionLocal",
        lambda: _SessionProxy(db_session),
    )
    monkeypatch.setattr(
        auto_execute_remediations,
        "execute_approved_remediation",
        fail_if_called,
    )
    monkeypatch.setattr(auto_execute_remediations.settings, "ENABLE_AUTO_REMEDIATION", True)

    with caplog.at_level(logging.INFO):
        asyncio.run(auto_execute_remediations._run_auto_remediations_async())

    # Finding untouched — never entered the processing loop.
    refreshed = db_session.get(ComplianceResult, finding.id)
    assert refreshed.remediation_status.value == "PENDING"
    assert "auto_remediation_eligible_findings count=0" in caplog.text


def test_auto_remediation_respects_baseline_and_cycle_limit(
    monkeypatch,
    db_session,
    caplog,
):
    tenant = _create_tenant(db_session, "tenant-safe")
    findings = []
    for idx in range(6):
        findings.append(
            _create_finding(
                db_session,
                tenant_id=tenant.id,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_id=f"user-{idx}",
                evidence={
                    "user_id": f"user-{idx}",
                    "account_enabled": True,
                    "is_admin": False,
                    "user_principal_name": f"user-{idx}@example.com",
                },
            )
        )

    executed_ids: list[int] = []

    async def fake_execute(**kwargs):
        compliance = db_session.get(ComplianceResult, kwargs["compliance_result_id"])
        executed_ids.append(compliance.id)
        assert compliance.remediation_status.value == "APPROVED"
        assert kwargs["action_type"] == "auto_execute"
        return compliance

    monkeypatch.setattr(
        auto_execute_remediations,
        "SyncSessionLocal",
        lambda: _SessionProxy(db_session),
    )
    monkeypatch.setattr(
        auto_execute_remediations,
        "execute_approved_remediation",
        fake_execute,
    )
    monkeypatch.setattr(
        auto_execute_remediations,
        "get_msp_baseline_sync",
        lambda db, organization_id: ["IDENTITY_UNUSED_ACCOUNT"],
    )
    monkeypatch.setattr(
        auto_execute_remediations,
        "check_execution_eligibility",
        lambda **kwargs: {"eligible": True},
    )

    async def _fake_has_token(tenant, db):
        return True

    monkeypatch.setattr(auto_execute_remediations, "has_delegated_oauth_token", _fake_has_token)
    monkeypatch.setattr(auto_execute_remediations.settings, "ENABLE_AUTO_REMEDIATION", True)

    with caplog.at_level(logging.INFO):
        asyncio.run(auto_execute_remediations._run_auto_remediations_async())

    assert len(executed_ids) == auto_execute_remediations.MAX_AUTO_REMEDIATIONS_PER_CYCLE
    assert "cycle_limit_reached" in caplog.text
    assert all(
        db_session.get(ComplianceResult, finding_id).remediation_status.value == "APPROVED"
        for finding_id in executed_ids
    )


def test_auto_remediation_skips_controls_outside_baseline(
    monkeypatch,
    db_session,
    caplog,
):
    tenant = _create_tenant(db_session, "tenant-baseline")
    finding = _create_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-baseline",
        evidence={
            "user_id": "user-baseline",
            "account_enabled": True,
            "is_admin": False,
        },
    )

    async def fail_if_called(**kwargs):
        raise AssertionError("controls outside the baseline must not auto-execute")

    monkeypatch.setattr(
        auto_execute_remediations,
        "SyncSessionLocal",
        lambda: _SessionProxy(db_session),
    )
    monkeypatch.setattr(
        auto_execute_remediations,
        "execute_approved_remediation",
        fail_if_called,
    )
    monkeypatch.setattr(
        auto_execute_remediations,
        "get_msp_baseline_sync",
        lambda db, organization_id: ["IDENTITY_GUEST_INVITES_OPEN"],
    )
    monkeypatch.setattr(auto_execute_remediations.settings, "ENABLE_AUTO_REMEDIATION", True)

    with caplog.at_level(logging.INFO):
        asyncio.run(auto_execute_remediations._run_auto_remediations_async())

    refreshed = db_session.get(ComplianceResult, finding.id)
    assert refreshed.remediation_status.value == "PENDING"
    assert "control_not_in_baseline" in caplog.text
