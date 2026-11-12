"""MFA registration check for CA_MFA_ALL_USERS partial rollout.

MFARegistrationPartialCheck (BLOCKING when rollout_phase == "partial"):
  When a PARTIAL rollout is requested, the target group already exists in
  the tenant. Any user in that group who has zero MFA methods registered
  would be immediately locked out when the policy is applied. This check
  enumerates the existing rollout group's members and blocks execution if
  any are found without MFA.

  Pass-through conditions (no Graph calls made):
    - rollout_phase != "partial" → PASS immediately (FULL phase lockout risk
      is handled by the Admin MFA check for CA_MFA_ADMINS and break-glass
      for CA_MFA_ALL_USERS)
    - No rollout group exists in DB → PASS (no users targeted yet; the group
      will be created on first execution with a percentage selection)

  Fail closed: any exception during user MFA enumeration → FAIL.

UserImpactSummaryCheck (NON-BLOCKING):
  Returns total users, rollout phase, and targeted count for operator review.
  Fail-open: exceptions produce a PASS with an error note.
"""

from __future__ import annotations

from app.db.models.managed_rollout_group import ManagedRolloutGroup
from app.services.graph_auth_methods_service import fetch_authentication_methods
from app.services.graph_user_service import fetch_users
from app.services.remediation.preflight.base import PreFlightCheck, PreFlightResult
from app.services.rollout_group_service import get_group_members


class MFARegistrationPartialCheck(PreFlightCheck):
    check_id = "mfa_registration_partial"
    check_name = "MFA Registration Check (Partial Rollout)"
    blocking = True

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        rollout_phase = (evidence.get("rollout_phase") or "").lower()
        if rollout_phase != "partial":
            return self._pass(
                f"Rollout phase is '{rollout_phase or 'default'}' — MFA registration "
                "pre-check only applies to partial rollout.",
                {"rollout_phase": rollout_phase, "check_skipped": True},
            )

        try:
            group_record = (
                graph_client.db.query(ManagedRolloutGroup)
                .filter(
                    ManagedRolloutGroup.tenant_id == tenant_id,
                    ManagedRolloutGroup.control_id == "CA_MFA_ALL_USERS",
                    ManagedRolloutGroup.managed.is_(True),
                )
                .one_or_none()
            )
            if group_record is None:
                return self._pass(
                    "No rollout group exists yet for CA_MFA_ALL_USERS. "
                    "Group will be created on first execution; no users are "
                    "currently targeted.",
                    {"rollout_phase": rollout_phase, "group_exists": False},
                )

            group_id = group_record.graph_group_id
            member_ids = await get_group_members(graph_client, group_id)
            if not member_ids:
                return self._pass(
                    "Rollout group exists but has no members yet.",
                    {
                        "rollout_phase": rollout_phase,
                        "group_id": group_id,
                        "member_count": 0,
                    },
                )

            no_mfa: list[dict] = []
            for user_id in member_ids:
                result = await fetch_authentication_methods(graph_client.db, graph_client.tenant, user_id)
                methods = result.get("methods") or []
                if not methods:
                    no_mfa.append({"user_id": user_id})

            if no_mfa:
                count = len(no_mfa)
                return self._fail(
                    f"{count} user(s) in the partial rollout group have no MFA "
                    "methods registered. Applying CA_MFA_ALL_USERS in partial mode "
                    "would immediately lock them out.",
                    {
                        "rollout_phase": rollout_phase,
                        "group_id": group_id,
                        "member_count": len(member_ids),
                        "no_mfa_count": count,
                        "no_mfa_user_ids": [u["user_id"] for u in no_mfa],
                    },
                )

            return self._pass(
                f"All {len(member_ids)} user(s) in the partial rollout group have " "MFA methods registered.",
                {
                    "rollout_phase": rollout_phase,
                    "group_id": group_id,
                    "member_count": len(member_ids),
                    "no_mfa_count": 0,
                },
            )
        except Exception as exc:
            return self._fail(
                f"Partial rollout MFA registration check failed: " f"{type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )


class UserImpactSummaryCheck(PreFlightCheck):
    check_id = "user_impact_summary"
    check_name = "User Impact Summary"
    blocking = False

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        try:
            rollout_phase = (evidence.get("rollout_phase") or "full").lower()
            users = await fetch_users(graph_client.db, graph_client.tenant)
            total_users = len(users)

            if rollout_phase == "partial":
                group_record = (
                    graph_client.db.query(ManagedRolloutGroup)
                    .filter(
                        ManagedRolloutGroup.tenant_id == tenant_id,
                        ManagedRolloutGroup.control_id == "CA_MFA_ALL_USERS",
                        ManagedRolloutGroup.managed.is_(True),
                    )
                    .one_or_none()
                )
                if group_record is not None:
                    member_ids = await get_group_members(graph_client, group_record.graph_group_id)
                    targeted_users = len(member_ids)
                else:
                    targeted_users = 0
            else:
                targeted_users = total_users

            return self._pass(
                f"CA_MFA_ALL_USERS ({rollout_phase}) will target {targeted_users} " f"of {total_users} total user(s).",
                {
                    "total_users": total_users,
                    "targeted_users": targeted_users,
                    "rollout_phase": rollout_phase,
                },
            )
        except Exception as exc:
            return self._pass(
                f"User impact summary unavailable: {type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )
