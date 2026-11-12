"""Break-glass account presence check (shared, blocking).

Verifies before any CA mutation:
  1. At least one break-glass account is registered for this tenant.
  2. Every registered break-glass account ID is an active Global Administrator.

This is an early-exit gate that produces a clear operator error before
the CA policy engine runs its own _validate_break_glass_accounts() check.
Both checks must pass independently — this one surfaces the finding at
pre-flight time with structured evidence; the engine check is the final
enforcement gate inside apply_control().

Fail closed: any exception (Graph error, DB error) → FAIL.
"""

from __future__ import annotations

from app.services.break_glass_safeguards import list_break_glass_user_ids
from app.services.graph_directory_roles_service import fetch_directory_roles
from app.services.graph_role_members_service import fetch_role_members
from app.services.remediation.preflight.base import PreFlightCheck, PreFlightResult


class BreakGlassPresenceCheck(PreFlightCheck):
    check_id = "break_glass_presence"
    check_name = "Break-Glass Account Presence Check"
    blocking = True

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        try:
            break_glass_ids = list_break_glass_user_ids(
                db=graph_client.db,
                tenant_id=tenant_id,
            )
            if not break_glass_ids:
                return self._fail(
                    "No break-glass accounts are registered for this tenant. "
                    "CA policy mutations require at least one active Global "
                    "Administrator break-glass account before they can proceed.",
                    {"break_glass_ids": [], "registered_count": 0},
                )

            directory_roles = await fetch_directory_roles(graph_client.db, graph_client.tenant)
            global_admin_role_id = next(
                (
                    role.get("id")
                    for role in directory_roles
                    if isinstance(role, dict)
                    and role.get("displayName") == "Global Administrator"
                    and isinstance(role.get("id"), str)
                ),
                None,
            )
            if not global_admin_role_id:
                return self._fail(
                    "Global Administrator directory role is unavailable in this tenant. "
                    "Cannot verify break-glass account membership.",
                    {"reason": "global_admin_role_unavailable"},
                )

            members = await fetch_role_members(graph_client.db, graph_client.tenant, global_admin_role_id)
            global_admin_ids: set[str] = {
                m["id"] for m in members if isinstance(m, dict) and isinstance(m.get("id"), str) and m["id"]
            }
            invalid_ids = [uid for uid in break_glass_ids if uid not in global_admin_ids]
            if invalid_ids:
                return self._fail(
                    f"{len(invalid_ids)} registered break-glass account(s) are not "
                    "active Global Administrators and cannot provide emergency access.",
                    {
                        "registered_count": len(break_glass_ids),
                        "invalid_break_glass_ids": invalid_ids,
                    },
                )

            return self._pass(
                f"{len(break_glass_ids)} break-glass account(s) verified as active " "Global Administrators.",
                {
                    "registered_count": len(break_glass_ids),
                    "break_glass_ids": break_glass_ids,
                    "validated": True,
                },
            )
        except Exception as exc:
            return self._fail(
                f"Break-glass verification failed unexpectedly: " f"{type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )
