import asyncio

from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.services.break_glass_safeguards import merge_break_glass_exclusions
from app.services.remediation.execution.execution_eligibility import (
    check_execution_eligibility,
)
from app.services.remediation_execution_service import execute_approved_remediation


def _create_tenant(db_session, tenant_id: str) -> Tenant:
    tenant = Tenant(
        id=tenant_id,
        tenant_name="Break Glass Tenant",
        oauth_token={"access_token": "token"},
    )
    db_session.add(tenant)
    db_session.commit()
    return tenant


def _create_finding(
    db_session,
    *,
    tenant_id: str,
    control_id: str,
    resource_id: str,
    remediation_status: str = "APPROVED",
    evidence: dict | None = None,
) -> ComplianceResult:
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="USER",
        resource_id=resource_id,
        severity="HIGH",
        passed=False,
        evidence=evidence or {},
        remediation_status=remediation_status,
        decision_status=remediation_status,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


def test_execution_eligibility_rejects_break_glass_targets(db_session):
    tenant = _create_tenant(db_session, "tenant-break-glass-eligibility")
    finding = _create_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="bg-user-1",
        evidence={"user_id": "bg-user-1", "account_enabled": True},
    )
    db_session.add(
        BreakGlassAccount(
            tenant_id=tenant.id,
            user_external_id="bg-user-1",
        )
    )
    db_session.commit()

    result = check_execution_eligibility(
        db=db_session,
        compliance_result_id=finding.id,
        tenant_id=tenant.id,
    )

    assert result["allowed"] is False
    assert result["eligible"] is False
    assert result["reason"] == "Protected emergency account"
    assert result["block_reason"] == "BREAK_GLASS_PROTECTION"


def test_execute_approved_remediation_blocks_and_audits_break_glass_targets(db_session):
    tenant = _create_tenant(db_session, "tenant-break-glass-execution")
    finding = _create_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="bg-user-2",
        evidence={"user_id": "bg-user-2", "account_enabled": True},
    )
    db_session.add(
        BreakGlassAccount(
            tenant_id=tenant.id,
            user_external_id="bg-user-2",
        )
    )
    db_session.commit()

    result = asyncio.run(
        execute_approved_remediation(
            db=db_session,
            compliance_result_id=finding.id,
            tenant=tenant,
            tenant_id=tenant.id,
            execution_payload={},
        )
    )

    db_session.refresh(finding)
    audit = (
        db_session.query(RemediationAuditLog)
        .filter(RemediationAuditLog.compliance_result_id == finding.id)
        .order_by(RemediationAuditLog.id.desc())
        .first()
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "Protected emergency account"
    assert finding.evidence["is_break_glass"] is True
    assert finding.evidence["error_type"] == "BREAK_GLASS_PROTECTION"
    assert audit is not None
    assert audit.decision == "BLOCKED"
    assert audit.explanation_factors["is_break_glass"] is True


def test_conditional_access_payloads_preserve_break_glass_exclusions(db_session):
    tenant = _create_tenant(db_session, "tenant-break-glass-ca")
    db_session.add(
        BreakGlassAccount(
            tenant_id=tenant.id,
            user_external_id="bg-user-3",
        )
    )
    db_session.commit()

    payload = merge_break_glass_exclusions(
        db=db_session,
        tenant_id=tenant.id,
        policy_payload={
            "displayName": "Protect Admins",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": ["existing-user"],
                }
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        },
    )

    assert payload["conditions"]["users"]["excludeUsers"] == [
        "existing-user",
        "bg-user-3",
    ]
