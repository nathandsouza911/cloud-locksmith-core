"""Admin MFA registration checks for CA_MFA_ADMINS.

AdminMFARegistrationCheck (BLOCKING):
  Fetches all members of the four highest-risk privileged roles and verifies
  that each has at least one MFA authentication method registered. If any
  admin has zero registered methods, enforcing CA_MFA_ADMINS would immediately
  lock them out — execution is blocked.

  Returns for each failing admin:
    user_id, display_name, user_principal_name

AdminImpactSummaryCheck (NON-BLOCKING):
  Returns admin count and affected count for operator review. Fail-open:
  exceptions produce a PASS with an error note (informational only).

The four roles checked match the roles targeted by CA_MFA_ADMINS policy:
  - Global Administrator
  - Privileged Role Administrator
  - Security Administrator
  - Conditional Access Administrator

(The full PRIVILEGED_ROLE_IDS set used for detection is wider; these four
are the ones that would be immediately locked out by the CA policy.)
"""

from __future__ import annotations

from app.services.graph_auth_methods_service import fetch_authentication_methods
from app.services.graph_directory_roles_service import fetch_directory_roles
from app.services.graph_role_members_service import fetch_role_members
from app.services.remediation.preflight.base import PreFlightCheck, PreFlightResult

# Template IDs for the four roles that are directly targeted by CA_MFA_ADMINS.
_MFA_ADMINS_TARGET_ROLE_TEMPLATE_IDS: frozenset[str] = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    }
)


async def _fetch_targeted_admin_members(graph_client) -> list[dict]:
    """Return deduplicated members of the four CA_MFA_ADMINS-targeted roles."""
    directory_roles = await fetch_directory_roles(graph_client.db, graph_client.tenant)
    matching_roles = [
        role
        for role in directory_roles
        if isinstance(role, dict)
        and (
            role.get("roleTemplateId") in _MFA_ADMINS_TARGET_ROLE_TEMPLATE_IDS
            or role.get("id") in _MFA_ADMINS_TARGET_ROLE_TEMPLATE_IDS
        )
        and isinstance(role.get("id"), str)
        and role["id"]
    ]

    seen: set[str] = set()
    members: list[dict] = []
    for role in matching_roles:
        for member in await fetch_role_members(graph_client.db, graph_client.tenant, role["id"]):
            if isinstance(member, dict) and isinstance(member.get("id"), str):
                uid = member["id"]
                if uid not in seen:
                    seen.add(uid)
                    members.append(member)
    return members


class AdminMFARegistrationCheck(PreFlightCheck):
    check_id = "admin_mfa_registration"
    check_name = "Admin MFA Registration Check"
    blocking = True

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        try:
            members = await _fetch_targeted_admin_members(graph_client)
            if not members:
                return self._pass(
                    "No privileged-role admins found in this tenant.",
                    {"admin_count": 0, "no_mfa_count": 0},
                )

            no_mfa: list[dict] = []
            for member in members:
                user_id = member.get("id") or ""
                if not user_id:
                    continue
                result = await fetch_authentication_methods(graph_client.db, graph_client.tenant, user_id)
                methods = result.get("methods") or []
                if not methods:
                    no_mfa.append(
                        {
                            "user_id": user_id,
                            "display_name": member.get("displayName") or "",
                            "user_principal_name": member.get("userPrincipalName") or "",
                        }
                    )

            if no_mfa:
                count = len(no_mfa)
                return self._fail(
                    f"{count} admin account(s) have no MFA methods registered. "
                    "Enforcing CA_MFA_ADMINS would immediately lock out these admins.",
                    {
                        "admin_count": len(members),
                        "no_mfa_count": count,
                        "no_mfa_accounts": no_mfa,
                    },
                )

            return self._pass(
                f"All {len(members)} targeted privileged-role admin(s) have MFA " "methods registered.",
                {"admin_count": len(members), "no_mfa_count": 0},
            )
        except Exception as exc:
            return self._fail(
                f"Admin MFA registration check failed: {type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )


class AdminImpactSummaryCheck(PreFlightCheck):
    check_id = "admin_impact_summary"
    check_name = "Admin Impact Summary"
    blocking = False

    async def run(
        self,
        *,
        graph_client,
        tenant_id: str,
        evidence: dict,
    ) -> PreFlightResult:
        try:
            members = await _fetch_targeted_admin_members(graph_client)
            admin_count = len(members)
            return self._pass(
                f"CA_MFA_ADMINS will apply to {admin_count} privileged-role admin " "account(s).",
                {"admin_count": admin_count, "affected_count": admin_count},
            )
        except Exception as exc:
            return self._pass(
                f"Admin impact summary unavailable: {type(exc).__name__}: {exc}",
                {"error": str(exc)},
            )
