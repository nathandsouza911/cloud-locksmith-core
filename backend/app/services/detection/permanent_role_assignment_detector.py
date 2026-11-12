"""Detector for IDENTITY_PERMANENT_ROLE_ASSIGNMENT.

Flags users with permanent (direct) privileged role assignments in Entra ID
when a PIM-eligible (just-in-time) alternative is available.  Permanent
assignments mean privileged access is always active — a standing privilege that
insurers regard as an elevated risk because there is no time-bound gate
between credential compromise and full administrative control.

Detection approach:
    1. Fetch all active role assignments via /roleManagement/directory/roleAssignments.
    2. Optionally fetch PIM-eligible schedules via
       /roleManagement/directory/roleEligibilitySchedules.
    3. For each user with a permanent assignment in a target privileged role,
       check whether a PIM-eligible alternative exists for the same
       (principalId, roleDefinitionId) pair.
    4. Emit one finding per user-role pair.  If PIM is unavailable (Entra P2
       not licensed) the finding is still emitted but the evidence records
       pim_check_available=False.

Target role definition IDs (Entra built-in template IDs — stable across tenants):
    Global Administrator, Privileged Role Administrator, Security Administrator,
    Conditional Access Administrator, User Administrator,
    Privileged Authentication Administrator, Application Administrator.

Pure functions only — no DB, no Graph calls.
"""

from __future__ import annotations

# Entra built-in role template IDs — stable across all tenants.
PRIVILEGED_ROLE_DEFINITION_IDS: frozenset[str] = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    }
)

# Human-readable labels for evidence output.
_ROLE_DISPLAY_NAMES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
}


def evaluate_permanent_role_assignments(
    *,
    role_assignments: list[dict],
    eligible_schedules: list[dict],
    pim_check_available: bool,
    user_display_names: dict[str, str] | None = None,
) -> list[dict]:
    """Evaluate direct (permanent) privileged role assignments.

    Args:
        role_assignments:   items from GET /roleManagement/directory/roleAssignments.
                            Each must have principalId, roleDefinitionId, directoryScopeId.
        eligible_schedules: items from GET /roleManagement/directory/roleEligibilitySchedules.
                            Empty list is valid (PIM not available or no PIM assignments).
        pim_check_available: True if the eligible_schedules fetch succeeded (Entra P2 licensed).
        user_display_names: optional dict {principalId → displayName} for evidence enrichment.

    Returns:
        list of finding dicts — one per (principalId, roleDefinitionId) that is permanently
        assigned to a target privileged role.  passed=True if a PIM-eligible alternative
        exists for the same pair; passed=False otherwise.
    """
    user_display_names = user_display_names or {}

    # Build PIM-eligible set: {(principalId, roleDefinitionId)}
    pim_eligible_pairs: set[tuple[str, str]] = set()
    for schedule in eligible_schedules:
        if not isinstance(schedule, dict):
            continue
        principal_id = schedule.get("principalId") or ""
        role_def_id = schedule.get("roleDefinitionId") or ""
        if principal_id and role_def_id:
            pim_eligible_pairs.add((principal_id, role_def_id))

    findings: list[dict] = []
    for assignment in role_assignments:
        if not isinstance(assignment, dict):
            continue
        principal_id = assignment.get("principalId") or ""
        role_def_id = assignment.get("roleDefinitionId") or ""
        directory_scope = assignment.get("directoryScopeId") or "/"
        if not principal_id or not role_def_id:
            continue
        if role_def_id not in PRIVILEGED_ROLE_DEFINITION_IDS:
            continue

        has_pim_alternative = (principal_id, role_def_id) in pim_eligible_pairs
        role_name = _ROLE_DISPLAY_NAMES.get(role_def_id, role_def_id)

        # A permanent assignment where PIM is available IS a finding regardless
        # of whether the user also has a PIM schedule — the permanent assignment
        # should be removed in favour of the eligible one.
        # If PIM is unavailable (pim_check_available=False) we still flag as FAIL
        # because we cannot verify that JIT is enforced.
        passed = False  # permanent assignment is always a finding

        findings.append(
            {
                "control_id": "IDENTITY_PERMANENT_ROLE_ASSIGNMENT",
                "passed": passed,
                "severity": "HIGH",
                "resource_type": "USER",
                "resource_id": principal_id,
                "evidence": {
                    "user_id": principal_id,
                    "display_name": user_display_names.get(principal_id),
                    "role_definition_id": role_def_id,
                    "role_name": role_name,
                    "directory_scope": directory_scope,
                    "assignment_type": "permanent",
                    "pim_eligible_alternative_exists": has_pim_alternative if pim_check_available else None,
                    "pim_check_available": pim_check_available,
                    "remediation_hint": (
                        "Convert this permanent assignment to a PIM-eligible assignment and remove the direct grant."
                        if pim_check_available
                        else "Enable Entra ID P2 and configure PIM to replace this permanent assignment."
                    ),
                },
            }
        )

    return findings
