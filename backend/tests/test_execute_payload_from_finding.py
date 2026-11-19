"""A fix acts only on the object in the finding, never on one named in the request
(review 2026-11-19, R1-2).

The execute route passed the raw JSON body to the executor, where it overrode the
finding's evidence ({**evidence, **execution_payload}). One POST with {"sp_id": ...},
{"illicit_grants": [...]}, {"user_id": ...} or {"allowInvitesFrom": "everyone"} made a
fix change a different object, or invert the fix. The only key a client may send is
selected_roles (IDENTITY_OVERPRIVILEGED_USER, checked against the approval).
"""

import asyncio
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import app.main  # noqa: F401  (registers every model for the db_session fixture)
from app.api.routes import remediation_execution as route
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant

HOSTILE = {
    "sp_id": "victim-sp",
    "user_id": "victim-user",
    "illicit_grants": [{"id": "victim-grant"}],
    "allowInvitesFrom": "everyone",
    "snapshot": {"accountEnabled": True},
    "rollout_phase": "full",
    "resource_id": "victim",
}


class _FakeRequest:
    def __init__(self, tenant_id: str, payload: dict):
        self.state = SimpleNamespace(tenant_id=tenant_id)
        self._payload = payload

    async def json(self):
        return self._payload


def _seed(db_session, tenant_id: str, control_id: str, evidence: dict) -> tuple[Tenant, ComplianceResult]:
    tenant = Tenant(
        id=tenant_id,
        tenant_name="Payload Tenant",
        domain="contoso.onmicrosoft.com",
        oauth_token={"access_token": "token"},
        last_delegated_auth_at=datetime.now(timezone.utc),
    )
    db_session.add(tenant)
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="SERVICE_PRINCIPAL",
        resource_id="finding-sp",
        severity="MEDIUM",
        passed=False,
        evidence=evidence,
        remediation_status="PENDING",
        decision_status="PENDING",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return tenant, finding


def _user():
    return SimpleNamespace(id=uuid.uuid4(), email="admin@test.com")


def test_execute_passes_only_selected_roles_to_the_executor(monkeypatch, db_session):
    tenant, finding = _seed(
        db_session, "tenant-payload-exec", "IDENTITY_STALE_SERVICE_PRINCIPAL", {"sp_id": "finding-sp"}
    )
    seen = {}

    async def fake_execute(**kwargs):
        seen["execution_payload"] = kwargs["execution_payload"]
        return {"status": "success"}

    monkeypatch.setattr(route, "execute_approved_remediation", fake_execute)
    asyncio.run(
        route.execute_remediation_endpoint(
            request=_FakeRequest(tenant.id, {**HOSTILE, "selected_roles": ["role-1"]}),
            compliance_result_id=finding.id,
            dry_run=False,
            db=db_session,
            current_user=_user(),
            current_tenant=tenant,
        )
    )
    assert seen["execution_payload"] == {"selected_roles": ["role-1"]}


def test_execute_without_selected_roles_sends_an_empty_payload(monkeypatch, db_session):
    tenant, finding = _seed(
        db_session, "tenant-payload-empty", "IDENTITY_STALE_SERVICE_PRINCIPAL", {"sp_id": "finding-sp"}
    )
    seen = {}

    async def fake_execute(**kwargs):
        seen["execution_payload"] = kwargs["execution_payload"]
        return {"status": "success"}

    monkeypatch.setattr(route, "execute_approved_remediation", fake_execute)
    asyncio.run(
        route.execute_remediation_endpoint(
            request=_FakeRequest(tenant.id, dict(HOSTILE)),
            compliance_result_id=finding.id,
            dry_run=False,
            db=db_session,
            current_user=_user(),
            current_tenant=tenant,
        )
    )
    assert seen["execution_payload"] == {}


def test_dry_run_preview_reads_the_finding_not_the_request(monkeypatch, db_session):
    tenant, finding = _seed(
        db_session, "tenant-payload-preview", "IDENTITY_STALE_SERVICE_PRINCIPAL", {"sp_id": "finding-sp"}
    )
    seen = {}

    class _Executor:
        async def preview(self, graph_client, evidence):
            seen["evidence"] = evidence
            return {"ok": True}

    monkeypatch.setitem(route.CONTROL_REGISTRY, "IDENTITY_STALE_SERVICE_PRINCIPAL", {"executor": _Executor()})
    asyncio.run(
        route.execute_remediation_endpoint(
            request=_FakeRequest(tenant.id, dict(HOSTILE)),
            compliance_result_id=finding.id,
            dry_run=True,
            db=db_session,
            current_user=_user(),
            current_tenant=tenant,
        )
    )
    evidence = seen["evidence"]
    assert evidence["sp_id"] == "finding-sp"
    assert evidence["resource_id"] == "finding-sp"
    for key in ("user_id", "illicit_grants", "allowInvitesFrom", "snapshot", "rollout_phase"):
        assert key not in evidence


def test_break_glass_create_passes_nothing_from_the_request(monkeypatch, db_session):
    tenant, finding = _seed(db_session, "tenant-payload-bg", "IDENTITY_BREAK_GLASS_ACCOUNT", {})
    seen = {}

    async def fake_preview(*, db, tenant, compliance):
        return {"changes": [{"action": "CREATE_USERS", "accounts": [{}, {}]}]}

    async def fake_execute(**kwargs):
        seen["execution_payload"] = kwargs["execution_payload"]
        finding.remediation_status = "SUCCESS"
        return finding

    monkeypatch.setattr(route, "_find_break_glass_finding", lambda *, db, tenant_id: finding)
    monkeypatch.setattr(route, "_build_control_preview", fake_preview)
    monkeypatch.setattr(route, "execute_approved_remediation", fake_execute)
    asyncio.run(
        route.create_break_glass_accounts(
            request=_FakeRequest(tenant.id, {**HOSTILE, "approve": True}),
            dry_run=False,
            db=db_session,
            current_user=_user(),
            current_tenant=tenant,
        )
    )
    assert seen["execution_payload"] == {}
