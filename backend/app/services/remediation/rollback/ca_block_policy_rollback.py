"""Campaign rollback for CA_DEVICE_CODE_FLOW_BLOCK and CA_AUTHENTICATION_TRANSFER_BLOCK.

Security note: RemediationSnapshot has no tenant_id column. Tenant ownership is
validated by querying ComplianceResult with (id, tenant_id) before any snapshot
read — identical to the pattern in conditional_access_rollback.py.

Rollback semantics:
  - prior_policy present in snapshot: delete current policy by ID, re-create
    from the captured pre-execution dict. The policy ID is stable across
    updates, so deleting then re-creating is idempotent.
  - _no_prior_policy=True in snapshot: no CLX policy existed before apply.
    Find and delete any policy whose displayName starts with the control's
    CLX base name (e.g. "CLX-DEVICE-CODE-FLOW-BLOCK").
"""

from __future__ import annotations

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.ca_policy_engine import CONTROL_POLICY_MAP, normalize_control_id


class CABlockPolicyRollbackError(Exception):
    pass


async def rollback_ca_block_policy(
    *,
    db,
    tenant,
    compliance_result_id: int,
    control_id: str,
) -> dict:
    """Restore the CLX block policy to its pre-execution state.

    Zero-trust: validates tenant ownership before touching the snapshot.
    """
    if tenant is None:
        raise CABlockPolicyRollbackError("Rollback called without tenant context — this is a programming error.")

    compliance = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == tenant.id,
        )
        .one_or_none()
    )
    if compliance is None:
        raise CABlockPolicyRollbackError(
            f"Compliance result {compliance_result_id} not found for tenant {tenant.id}. " "Refusing to load snapshot."
        )

    snapshot_row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    if snapshot_row is None or not snapshot_row.state:
        raise CABlockPolicyRollbackError(
            f"No pre-execution snapshot found for compliance_result_id={compliance_result_id}"
        )

    payload = snapshot_row.state

    from app.services.graph_conditional_access import (
        create_conditional_access_policy,
        delete_conditional_access_policy,
        list_conditional_access_policies,
    )

    prior_policy = (payload or {}).get("prior_policy")
    if prior_policy and prior_policy.get("id"):
        await delete_conditional_access_policy(db, tenant, prior_policy["id"])
        await create_conditional_access_policy(db, tenant, prior_policy)
        return {"status": "rollback_complete", "policy_id": prior_policy["id"]}

    # No prior policy — find CLX policies by display-name prefix and delete them.
    normalized = normalize_control_id(control_id)
    policy_base_name = CONTROL_POLICY_MAP.get(normalized, "")
    if not policy_base_name:
        raise CABlockPolicyRollbackError(f"Cannot determine CLX policy base name for control {control_id}")

    existing_policies = await list_conditional_access_policies(db, tenant)
    deleted_ids: list[str] = []
    for policy in existing_policies:
        if not isinstance(policy, dict):
            continue
        display_name = policy.get("displayName") or ""
        policy_id = policy.get("id")
        if display_name.startswith(policy_base_name) and policy_id:
            await delete_conditional_access_policy(db, tenant, policy_id)
            deleted_ids.append(policy_id)

    return {
        "status": "rollback_complete",
        "deleted_policy_ids": deleted_ids,
        "reason": "no_prior_policy",
    }
