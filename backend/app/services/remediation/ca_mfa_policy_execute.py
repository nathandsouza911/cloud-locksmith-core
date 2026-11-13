"""Executor for CA_MFA_ADMINS, CA_MFA_ALL_USERS, and CA_LEGACY_AUTH_BLOCK.

These controls deploy CA policies that enforce MFA or block legacy authentication
protocols. Unlike the block-policy controls (device code flow, auth transfer), the
execution mode is variable — the policy can be created in audit (report-only) or
enforced (enabled) state. Mode is derived from evidence["enforcement_mode"] and
defaults to "audit" so that an unspecified mode always creates the policy in
report-only state, never enforced without an explicit caller decision.

Pre-flight gate (Wave 3B Phase 2):
  execute() runs PreFlightEngine before calling apply_control(). If any
  blocking pre-flight check fails, execute() returns a blocked result and
  no CA mutation occurs. Checks are control-specific:
    CA_MFA_ADMINS       — break-glass presence, admin MFA registration
    CA_MFA_ALL_USERS    — break-glass presence, partial-rollout MFA check
    CA_LEGACY_AUTH_BLOCK — break-glass presence, legacy auth usage scan

Rollback:
  - If a CLX policy existed before execution (update path): the pre-execution
    policy dict is captured in build_snapshot(); rollback deletes the current
    version and re-creates from snapshot.
  - If no policy existed (first apply): build_snapshot() records
    _no_prior_policy=True; rollback finds the CLX policy by display-name
    prefix and deletes it.

Security: graph_client.db and graph_client.tenant are the source of truth.
No tenant_id or mode is read from caller input without validation by the
underlying ca_policy_engine.apply_control().
"""

from __future__ import annotations

from app.services.ca_policy_engine import (
    CONTROL_POLICY_MAP,
    normalize_control_id,
)


class CAMFAPolicyExecutor:
    """Executor for CA_MFA_ADMINS, CA_MFA_ALL_USERS, and CA_LEGACY_AUTH_BLOCK."""

    def __init__(self, control_id: str) -> None:
        self._control_id = control_id

    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        """Capture the pre-execution CLX policy state for rollback."""
        normalized = normalize_control_id(self._control_id)
        policy_base_name = CONTROL_POLICY_MAP.get(normalized, "")
        existing_policies = await graph_client.list_conditional_access_policies()
        prior_policy = next(
            (
                p
                for p in existing_policies
                if isinstance(p, dict)
                and isinstance(p.get("displayName"), str)
                and p["displayName"].startswith(policy_base_name)
            ),
            None,
        )
        if prior_policy is None:
            return {"_no_prior_policy": True, "_control_id": self._control_id}
        return {"prior_policy": prior_policy, "_control_id": self._control_id}

    async def execute(self, graph_client, evidence: dict) -> dict:
        """Apply the CA policy for this control, guarded by pre-flight checks.

        Pre-flight runs first. If any blocking check fails, returns a blocked
        result immediately — no CA mutation occurs.

        Mode is derived from evidence["enforcement_mode"] — defaults to "audit"
        so that an unspecified mode creates the policy in report-only state.
        Rollout phase is derived from evidence["rollout_phase"] — defaults to
        None, which causes apply_control() to use the persisted ControlState
        rollout_phase or the control's structural default.
        """
        from app.services.remediation.preflight.engine import run_preflight

        ev = evidence or {}
        tenant_id = str(getattr(graph_client.tenant, "id", "") or "")

        report = await run_preflight(
            graph_client=graph_client,
            control_id=self._control_id,
            tenant_id=tenant_id,
            evidence=ev,
        )

        if not report.all_passed:
            return {
                "status": "blocked",
                "reason": "preflight_failed",
                "message": report.operator_summary,
                "preflight_report": report.to_dict(),
            }

        from app.services.ca_policy_engine import apply_control

        mode = ev.get("enforcement_mode") or "audit"
        rollout_phase = ev.get("rollout_phase")  # None → engine uses ControlState/default

        result = await apply_control(
            db=graph_client.db,
            tenant=graph_client.tenant,
            control_id=self._control_id,
            mode=mode,
            rollout_phase=rollout_phase,
        )
        ca_status = (result or {}).get("status")
        if ca_status in {"blocked", "partial", "failed"}:
            return result
        return {
            "status": "SUCCESS",
            "verified": result.get("verified", True),
            # "report_only": the policy exists as intended but protects no one, so the
            # finding must stay open (see execute_approved_remediation).
            "verification_scope": result.get("verification_scope"),
            "control_id": self._control_id,
            "snapshot": {
                "control_id": self._control_id,
                "ca_snapshot_id": result.get("snapshot_id"),
            },
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        """Restore the CA policy to its pre-execution state on error.

        Called by remediation_executor on GraphAPIError escaping from execute().
        apply_control() catches its own Graph errors internally, so this path
        fires only on unexpected exceptions (e.g. DB failures mid-execution).
        """
        prior_policy = (snapshot or {}).get("prior_policy")
        if prior_policy and prior_policy.get("id"):
            await graph_client.delete_conditional_access_policy(prior_policy["id"])
            await graph_client.create_conditional_access_policy(prior_policy)
            return
        # No prior policy existed: find CLX policy by display-name prefix and delete it.
        normalized = normalize_control_id(self._control_id)
        policy_base_name = CONTROL_POLICY_MAP.get(normalized, "")
        if not policy_base_name:
            return
        existing_policies = await graph_client.list_conditional_access_policies()
        for policy in existing_policies:
            if not isinstance(policy, dict):
                continue
            display_name = policy.get("displayName") or ""
            if display_name.startswith(policy_base_name) and policy.get("id"):
                await graph_client.delete_conditional_access_policy(policy["id"])
