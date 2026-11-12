"""Approval↔execution scope binding (H1 — TOCTOU protection).

When a finding is approved we capture its *scope* (server-side, from the
finding's own evidence — never from client input) and store a hash of it on the
finding. At execution time we require:

  1. the scope is unchanged since approval (a re-scan that altered the finding's
     roles forces re-approval), and
  2. any client-supplied ``selected_roles`` is a subset of the approved scope.

For controls with a fixed action (everything except IDENTITY_OVERPRIVILEGED_USER)
the role set is empty, so the hash binds only control_id + resource_id and these
checks are no-ops — the meaningful constraint is on the variable-payload
overprivileged-role removal.

Pure functions only — no DB, no Graph, no tenant resolution.
"""

from __future__ import annotations

import hashlib
import json


def _normalize_role_list(roles) -> list[str]:
    """Return a sorted, de-duplicated list of role identifiers from a mixed
    list of strings and dicts (role_id / id / role_name / displayName)."""
    out: list[str] = []
    for role in roles or []:
        if isinstance(role, str) and role.strip():
            out.append(role.strip())
        elif isinstance(role, dict):
            rid = role.get("role_id") or role.get("id") or role.get("role_name") or role.get("displayName")
            if isinstance(rid, str) and rid.strip():
                out.append(rid.strip())
    return sorted(set(out))


def evidence_roles(evidence: dict) -> list[str]:
    """The roles the finding currently exposes (the previewed/approved scope)."""
    if not isinstance(evidence, dict):
        return []
    return _normalize_role_list(evidence.get("current_roles") or evidence.get("roles"))


def selected_roles(payload: dict) -> list[str]:
    """The roles a client asked to act on at execute time."""
    if not isinstance(payload, dict):
        return []
    return _normalize_role_list(payload.get("selected_roles"))


def compute_scope_hash(control_id: str, resource_id, roles: list[str]) -> str:
    canonical = json.dumps(
        {
            "control_id": control_id,
            "resource_id": resource_id or "",
            "roles": sorted(roles),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def approved_scope(control_id: str, resource_id, evidence: dict) -> dict:
    """Snapshot the approved scope from the finding's evidence at approval time."""
    roles = evidence_roles(evidence)
    return {
        "approved_scope_hash": compute_scope_hash(control_id, resource_id, roles),
        "approved_roles": roles,
    }


def selected_roles_within_scope(payload: dict, *, approved_roles: list[str]) -> bool:
    requested = set(selected_roles(payload))
    if not requested:
        # Empty selection is rejected separately by the "no roles selected" guard.
        return True
    return requested <= set(approved_roles or [])


def scope_unchanged(control_id: str, resource_id, evidence: dict, *, approved_scope_hash: str) -> bool:
    current = compute_scope_hash(control_id, resource_id, evidence_roles(evidence))
    return current == approved_scope_hash


# Controls whose executed action varies by client payload and therefore must be
# bound to the approved scope. Everything else has a fixed action.
VARIABLE_PAYLOAD_CONTROLS = frozenset({"IDENTITY_OVERPRIVILEGED_USER"})


class ApprovalScopeError(ValueError):
    """Raised when execution diverges from the approved scope.

    ``reason`` is one of: "scope_changed" (finding drifted since approval —
    re-approval required) or "roles_exceeded" (client asked to act outside the
    approved scope).
    """

    def __init__(self, message: str, *, reason: str):
        super().__init__(message)
        self.reason = reason


def assert_execution_within_approved_scope(
    *,
    control_id: str,
    resource_id,
    evidence: dict,
    execution_payload: dict,
) -> None:
    """Fail closed if execution would diverge from what was approved.

    No-op for fixed-action controls. For variable-payload controls:
      * if an approved scope hash was captured, the finding's roles must be
        unchanged since approval (else ``reason="scope_changed"``);
      * the client's selected_roles must be a subset of the approved roles
        (else ``reason="roles_exceeded"``).
    Legacy approvals without a captured hash still get the subset check against
    the finding's current evidence roles.
    """
    if control_id not in VARIABLE_PAYLOAD_CONTROLS:
        return

    evidence = evidence if isinstance(evidence, dict) else {}
    approved_hash = evidence.get("approved_scope_hash")
    if approved_hash and not scope_unchanged(control_id, resource_id, evidence, approved_scope_hash=approved_hash):
        raise ApprovalScopeError(
            "Approved scope changed since approval — re-approval required",
            reason="scope_changed",
        )

    approved_roles = evidence.get("approved_roles")
    if approved_roles is None:
        approved_roles = evidence_roles(evidence)
    if not selected_roles_within_scope(execution_payload, approved_roles=approved_roles):
        raise ApprovalScopeError(
            "Selected roles exceed the approved scope — re-approval required",
            reason="roles_exceeded",
        )
