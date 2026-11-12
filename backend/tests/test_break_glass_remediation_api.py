import asyncio
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.api.routes.compliance_results import serialize_compliance_result
from app.api.routes.remediation_execution import create_break_glass_accounts
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant


class _FakeRequest:
    def __init__(self, tenant_id: str, payload: dict | None = None):
        self.state = SimpleNamespace(tenant_id=tenant_id)
        self._payload = payload or {}

    async def json(self):
        return self._payload


def _seed_break_glass_finding(
    db_session, *, tenant_id: str, remediation_status: str = "PENDING", decision_status: str = "PENDING"
):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_BREAK_GLASS_ACCOUNT",
        resource_type="TENANT",
        resource_id=tenant_id,
        severity="HIGH",
        passed=False,
        evidence={"tenant_domain": "contoso.onmicrosoft.com"},
        remediation_status=remediation_status,
        decision_status=decision_status,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


def _seed_tenant(db_session, tenant_id: str) -> Tenant:
    tenant = Tenant(
        id=tenant_id,
        tenant_name="Break Glass API Tenant",
        domain="contoso.onmicrosoft.com",
        oauth_token={"access_token": "token"},
        last_delegated_auth_at=datetime.now(timezone.utc),
    )
    db_session.add(tenant)
    db_session.commit()
    return tenant


def test_break_glass_create_dry_run_returns_preview(monkeypatch, db_session):
    tenant = _seed_tenant(db_session, "tenant-break-glass-api-preview")
    finding = _seed_break_glass_finding(db_session, tenant_id=tenant.id)

    async def fake_preview(*, db, tenant, compliance):
        assert compliance.id == finding.id
        return {
            "changes": [
                {"action": "CREATE_USERS", "accounts": [{}, {}]},
                {"action": "EXCLUDE_FROM_CONDITIONAL_ACCESS", "policy_ids": ["policy-1", "policy-2"]},
            ]
        }

    monkeypatch.setattr(
        "app.api.routes.remediation_execution._build_control_preview",
        fake_preview,
    )

    response = asyncio.run(
        create_break_glass_accounts(
            request=_FakeRequest(tenant.id),
            dry_run=True,
            db=db_session,
            current_user=SimpleNamespace(id=uuid.uuid4(), email="admin@test.com"),
            current_tenant=tenant,
        )
    )
    body = json.loads(response.body)

    assert body["status"] == "preview"
    assert body["accounts_to_create"] == 2
    assert body["policies_to_modify"] == ["policy-1", "policy-2"]

    preview_audit = (
        db_session.query(RemediationAuditLog)
        .filter(RemediationAuditLog.compliance_result_id == finding.id)
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )
    assert preview_audit is not None
    assert preview_audit.decision == "PREVIEWED"


def test_break_glass_create_approves_and_executes(monkeypatch, db_session):
    tenant = _seed_tenant(db_session, "tenant-break-glass-api-execute")
    finding = _seed_break_glass_finding(db_session, tenant_id=tenant.id)

    async def fake_preview(*, db, tenant, compliance):
        return {
            "changes": [
                {"action": "CREATE_USERS", "accounts": [{}, {}]},
                {"action": "EXCLUDE_FROM_CONDITIONAL_ACCESS", "policy_ids": ["policy-1"]},
            ]
        }

    async def fake_execute(**kwargs):
        finding.remediation_status = "SUCCESS"
        return finding

    monkeypatch.setattr(
        "app.api.routes.remediation_execution._build_control_preview",
        fake_preview,
    )
    monkeypatch.setattr(
        "app.api.routes.remediation_execution.execute_approved_remediation",
        fake_execute,
    )

    response = asyncio.run(
        create_break_glass_accounts(
            request=_FakeRequest(tenant.id, {"approve": True}),
            dry_run=False,
            db=db_session,
            current_user=SimpleNamespace(id=uuid.uuid4(), email="owner@test.com"),
            current_tenant=tenant,
        )
    )
    body = json.loads(response.body)

    assert body["status"] == "executed"
    assert body["accounts_to_create"] == 2
    assert body["policies_to_modify"] == ["policy-1"]

    approved_audit = (
        db_session.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == finding.id,
            RemediationAuditLog.decision == "APPROVED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )
    assert approved_audit is not None
    assert approved_audit.approved_by == "owner@test.com"


def test_break_glass_failed_result_includes_cta():
    finding = ComplianceResult(
        id=42,
        tenant_id="tenant-cta",
        control_id="IDENTITY_BREAK_GLASS_ACCOUNT",
        resource_type="TENANT",
        resource_id="tenant-cta",
        passed=False,
        severity="HIGH",
        evidence={},
        decision_status="PENDING",
    )

    serialized = serialize_compliance_result(finding)

    assert serialized["remediation_cta"] == {
        "label": "Create Break-Glass Accounts",
        "method": "POST",
        "endpoint": "/api/v1/remediation/break-glass/create",
        "supports_dry_run": True,
        "supports_approval_flow": True,
    }
