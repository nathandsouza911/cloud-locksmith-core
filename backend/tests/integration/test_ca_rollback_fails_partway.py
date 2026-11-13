"""A Conditional Access rollback that fails partway (LIVE_REMEDIATION_SCRIPT 7.3).

Cannot be produced safely in a real tenant, so a fake Graph fails between the
restore and the delete. Rollback order: re-create the snapshot's policies, verify,
then delete the managed policies that are no longer wanted.

Before: the engine recorded a partial execution and raised; the endpoint's catch-all
returned an opaque 500 "internal_error", wrote no audit record, and did not tell the
user that the tenant was left half-changed.

Now: 502 "rollback_incomplete" with a plain message, a ROLLBACK_FAILED audit record,
the finding stays rollback-able, and a retry converges to the pre-change state.
"""

import asyncio
import itertools
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.responses import JSONResponse

from app.api.v1 import remediation_rollback as rollback_api
from app.db.models.compliance_result import ComplianceResult
from app.db.models.control_execution import ControlExecution
from app.db.models.control_snapshot import ControlSnapshot
from app.db.models.control_state import ControlState
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.services import ca_policy_engine as engine
from app.services.graph_client import GraphAPIError

CONTROL = "CA_LEGACY_AUTH_BLOCK"
TENANT = "tenant-partial-rollback"
BREAK_GLASS = ["bg-1"]


class FakeTenantGraph:
    """In-memory Conditional Access policies; can fail deleting chosen ids."""

    def __init__(self, policies: list[dict]):
        self.policies = {p["id"]: dict(p) for p in policies}
        self.fail_delete: set[str] = set()
        self._ids = (f"created-{n}" for n in itertools.count(1))

    async def list_conditional_access_policies(self):
        return [dict(p) for p in self.policies.values()]

    async def create_conditional_access_policy(self, payload):
        policy = {**payload, "id": next(self._ids)}
        self.policies[policy["id"]] = policy
        return dict(policy)

    async def update_conditional_access_policy(self, policy_id, payload):
        self.policies[policy_id] = {**payload, "id": policy_id}
        return dict(self.policies[policy_id])

    async def delete_conditional_access_policy(self, policy_id):
        if policy_id in self.fail_delete:
            raise GraphAPIError(
                method="DELETE",
                path=f"/identity/conditionalAccess/policies/{policy_id}",
                status_code=429,
                response_body='{"error":{"code":"TooManyRequests"}}',
                category="THROTTLED",
            )
        self.policies.pop(policy_id, None)


def _policy(version: int, policy_id: str) -> dict:
    built = engine.build_policy(CONTROL, "audit", "full", BREAK_GLASS, target_group_id=None, policy_version=version)
    return {**built, "id": policy_id}


def _seed(db, *, prior: list[dict], current_id: str):
    tenant = Tenant(id=TENANT, tenant_name="partial rollback")
    db.add(tenant)
    db.commit()
    snapshot = ControlSnapshot(
        tenant_id=TENANT,
        control_id=CONTROL,
        policies=[engine._normalize_policy(p) for p in prior],
        managed_policy_ids=[p["id"] for p in prior],
    )
    db.add(snapshot)
    db.commit()
    db.add(
        ControlExecution(
            tenant_id=TENANT,
            control_id=CONTROL,
            mode="audit",
            rollout_phase="full",
            status="success",
            snapshot_id=snapshot.id,
            policies_created=[],
            policies_updated=[],
            managed_policy_ids=[current_id],
            verified=True,
        )
    )
    db.add(
        ControlState(
            tenant_id=TENANT,
            control_id=CONTROL,
            mode="audit",
            rollout_phase="full",
            rollout_percentage=100,
            managed_policy_ids=[current_id],
            policy_version=2 if prior else 1,
            status="active",
        )
    )
    finding = ComplianceResult(
        tenant_id=TENANT,
        control_id=CONTROL,
        resource_type="TENANT",
        resource_id=TENANT,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status="SUCCESS",
        decision_status="SUCCESS",
    )
    db.add(finding)
    db.commit()
    return tenant, finding


def _rollback(db, tenant, finding, graph: FakeTenantGraph):
    with (
        patch("app.services.remediation_executor.RemediationGraphClient", return_value=graph),
        patch.object(engine, "list_break_glass_user_ids", return_value=BREAK_GLASS),
        patch.object(engine, "_validate_break_glass_accounts", new=AsyncMock()),
        patch.object(engine, "retry_with_backoff", new=lambda fn, attempts=3: fn()),
        patch.object(rollback_api, "create_posture_snapshot", new=lambda *a, **kw: None),
    ):
        return asyncio.run(
            rollback_api.rollback_remediation(
                compliance_result_id=finding.id, payload=None, db=db, current_tenant=tenant
            )
        )


def _semantics(policies):
    return engine._sorted_policy_semantics(policies)


@pytest.mark.parametrize("had_prior_policy", [True, False], ids=["replaced-v1", "first-apply"])
def test_partial_rollback_is_reported_audited_and_completes_on_retry(db_session, had_prior_policy):
    prior = [_policy(1, "old-v1")] if had_prior_policy else []
    current = _policy(2 if had_prior_policy else 1, "new-current")
    tenant, finding = _seed(db_session, prior=prior, current_id=current["id"])
    graph = FakeTenantGraph([current])
    graph.fail_delete = {current["id"]}

    first = _rollback(db_session, tenant, finding, graph)

    # The user is told plainly that the rollback did not finish.
    assert isinstance(first, JSONResponse) and first.status_code == 502
    body = first.body.decode()
    assert '"reason":"rollback_incomplete"' in body
    assert "retry" in body.lower()
    # Audited, and the finding can still be rolled back.
    db_session.expire_all()
    failed = (
        db_session.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == finding.id, RemediationAuditLog.decision == "ROLLBACK_FAILED"
        )
        .count()
    )
    assert failed == 1
    assert db_session.get(ComplianceResult, finding.id).remediation_status == "SUCCESS"
    # What the tenant looks like in between: the change is still there.
    assert current["id"] in graph.policies

    graph.fail_delete = set()
    second = _rollback(db_session, tenant, finding, graph)

    assert not isinstance(second, JSONResponse), getattr(second, "body", second)
    assert second["status"] == "success"
    assert _semantics(graph.policies.values()) == _semantics(prior), "tenant equals the pre-change snapshot"
    db_session.expire_all()
    assert db_session.get(ComplianceResult, finding.id).remediation_status == "PENDING"


def test_rollback_refused_before_any_change_explains_why(db_session):
    """A precondition failure (no break-glass) changes nothing and says why (was a 500)."""
    current = _policy(1, "new-current")
    tenant, finding = _seed(db_session, prior=[], current_id=current["id"])
    graph = FakeTenantGraph([current])
    with (
        patch("app.services.remediation_executor.RemediationGraphClient", return_value=graph),
        patch.object(engine, "list_break_glass_user_ids", return_value=[]),
        patch.object(rollback_api, "create_posture_snapshot", new=lambda *a, **kw: None),
    ):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                rollback_api.rollback_remediation(
                    compliance_result_id=finding.id, payload=None, db=db_session, current_tenant=tenant
                )
            )
    assert exc.value.status_code == 400
    assert "break-glass" in str(exc.value.detail).lower()
    assert current["id"] in graph.policies
