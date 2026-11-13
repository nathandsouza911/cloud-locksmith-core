"""The CA licence write-probe: valid payload, and never before the safety checks.

Found in the 2026-11-13 live run (LIVE_REMEDIATION_SCRIPT defects L4, L5):
  * Graph rejected the probe with 400 "1064: 'clientAppTypes' condition does not
    support []", so every CA fix was refused as NO_CA_LICENSE on a P1 tenant.
  * The probe creates and deletes a policy in the customer tenant. It ran in
    execute_approved_remediation before the preflight (break-glass) checks, and in
    the CA engine before the engine's own break-glass check. A tenant write must
    not happen before the read-only checks that would refuse the fix.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.graph_payloads import ConditionalAccessPolicySchema
from app.services import ca_policy_engine
from app.services.license_check_service import check_conditional_access_license


def test_probe_payload_is_accepted_by_graph_rules():
    sent: list[dict] = []

    class FakeGraph:
        tenant = None

        async def create_conditional_access_policy(self, payload):
            sent.append(payload)
            return {"id": "tmp"}

        async def delete_conditional_access_policy(self, policy_id):
            return None

    assert asyncio.run(check_conditional_access_license(FakeGraph())) is True
    payload = sent[0]
    assert payload["conditions"]["clientAppTypes"] == ["all"]
    ConditionalAccessPolicySchema(**payload)


def test_execute_does_not_probe_the_tenant_before_preflight(monkeypatch):
    """execute_approved_remediation must not run the write-probe itself; the CA
    engine probes after preflight and break-glass checks."""
    from app.services import remediation_execution_service as svc

    probe = AsyncMock(return_value=True)
    monkeypatch.setattr("app.services.license_check_service.check_conditional_access_license", probe)

    compliance = MagicMock(control_id="CA_LEGACY_AUTH_BLOCK", passed=True, tenant_id="t1")
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.one_or_none.return_value = compliance
    tenant = MagicMock(id="t1", provider="microsoft")

    try:
        asyncio.run(svc.execute_approved_remediation(db=db, compliance_result_id=1, tenant=tenant, tenant_id="t1"))
    except Exception:
        pass  # later steps may fail on the mocks; only the probe matters here

    probe.assert_not_called()


def _tenant():
    tenant = MagicMock()
    tenant.id = "tenant-probe-order"
    tenant.provider = "microsoft"
    return tenant


@pytest.mark.parametrize("entry", ["apply_control", "apply_break_glass_exclusion"])
def test_engine_checks_break_glass_before_the_write_probe(entry):
    probe = AsyncMock(return_value=True)
    with (
        patch.object(ca_policy_engine, "check_conditional_access_license", new=probe),
        patch.object(ca_policy_engine, "list_break_glass_user_ids", return_value=[]),
    ):
        with pytest.raises(ca_policy_engine.ControlEngineError):
            if entry == "apply_control":
                asyncio.run(
                    ca_policy_engine.apply_control(db=MagicMock(), tenant=_tenant(), control_id="CA_LEGACY_AUTH_BLOCK")
                )
            else:
                asyncio.run(ca_policy_engine.apply_break_glass_exclusion(db=MagicMock(), tenant=_tenant()))
    probe.assert_not_called()


@pytest.mark.parametrize("entry", ["apply_control", "apply_break_glass_exclusion"])
def test_engine_validates_break_glass_accounts_before_the_write_probe(entry):
    probe = AsyncMock(return_value=True)
    with (
        patch.object(ca_policy_engine, "check_conditional_access_license", new=probe),
        patch.object(ca_policy_engine, "list_break_glass_user_ids", return_value=["bg-1"]),
        patch.object(
            ca_policy_engine,
            "_validate_break_glass_accounts",
            new=AsyncMock(side_effect=ca_policy_engine.ControlEngineError("bg invalid")),
        ),
    ):
        with pytest.raises(ca_policy_engine.ControlEngineError):
            if entry == "apply_control":
                asyncio.run(
                    ca_policy_engine.apply_control(db=MagicMock(), tenant=_tenant(), control_id="CA_LEGACY_AUTH_BLOCK")
                )
            else:
                asyncio.run(ca_policy_engine.apply_break_glass_exclusion(db=MagicMock(), tenant=_tenant()))
    probe.assert_not_called()
