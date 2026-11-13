from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import inspect
import logging
import uuid
from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select

from app.db.models.control_execution import ControlExecution
from app.db.models.control_execution import ControlExecutionStatus
from app.db.models.control_state import (
    ControlMode,
    ControlRolloutPhase,
    ControlStateStatus,
)
from app.services.break_glass_safeguards import list_break_glass_user_ids
from app.services.control_snapshot_service import (
    create_snapshot,
    get_latest_snapshot,
    get_snapshot_by_id,
)
from app.services.control_state_service import create_or_update_control_state, get_control_state
from app.services.graph_client import GraphAPIError
from app.services.graph_directory_roles_service import fetch_directory_roles
from app.services.graph_role_members_service import fetch_role_members
from app.services.graph_user_service import fetch_users
from app.config import settings
from app.services.license_check_service import check_conditional_access_license
from app.services.ca_policy_states import CA_STATE_REPORT_ONLY
from app.services.remediation.mfa_policy import (
    PRIVILEGED_ROLE_IDS,
    build_authentication_transfer_block_policy,
    build_device_code_flow_block_policy,
    build_guest_mfa_policy,
    build_high_risk_sign_in_block_policy,
    build_legacy_auth_block_policy,
    build_mfa_admins_policy,
    build_mfa_all_users_policy,
    build_risk_based_step_up_mfa_policy,
)
from app.services.rollout_group_service import (
    add_users_to_group,
    create_rollout_group,
    get_group_members,
    remove_users_from_group,
)
from app.services.remediation.tenant_execution_lock import (
    TenantExecutionLockError,
    acquire_tenant_execution_lock,
    release_tenant_execution_lock,
)

logger = logging.getLogger(__name__)

CONTROL_MFA_ADMINS = "CA_MFA_ADMINS"
CONTROL_MFA_ALL_USERS = "CA_MFA_ALL_USERS"
CONTROL_LEGACY_AUTH_BLOCK = "CA_LEGACY_AUTH_BLOCK"
CONTROL_DEVICE_CODE_FLOW_BLOCK = "CA_DEVICE_CODE_FLOW_BLOCK"
CONTROL_AUTHENTICATION_TRANSFER_BLOCK = "CA_AUTHENTICATION_TRANSFER_BLOCK"
CONTROL_GUEST_MFA = "CA_GUEST_MFA"
CONTROL_BREAK_GLASS_EXCLUSION = "CA_BREAK_GLASS_EXCLUSION"
CONTROL_HIGH_RISK_SIGN_IN_BLOCK = "CA_HIGH_RISK_SIGN_IN_BLOCK"
CONTROL_RISK_BASED_STEP_UP_MFA = "CA_RISK_BASED_STEP_UP_MFA"

CONTROL_POLICY_MAP = {
    CONTROL_MFA_ADMINS: "CLX-MFA-ADMINS",
    CONTROL_MFA_ALL_USERS: "CLX-MFA-ALL-USERS",
    CONTROL_LEGACY_AUTH_BLOCK: "CLX-LEGACY-AUTH-BLOCK",
    CONTROL_DEVICE_CODE_FLOW_BLOCK: "CLX-DEVICE-CODE-FLOW-BLOCK",
    CONTROL_AUTHENTICATION_TRANSFER_BLOCK: "CLX-AUTHENTICATION-TRANSFER-BLOCK",
    CONTROL_GUEST_MFA: "CLX-GUEST-MFA",
    CONTROL_HIGH_RISK_SIGN_IN_BLOCK: "CLX-HIGH-RISK-SIGN-IN-BLOCK",
    CONTROL_RISK_BASED_STEP_UP_MFA: "CLX-RISK-BASED-STEP-UP-MFA",
}

SUPPORTED_CONTROL_IDS = {
    CONTROL_MFA_ADMINS,
    CONTROL_MFA_ALL_USERS,
    CONTROL_LEGACY_AUTH_BLOCK,
    CONTROL_DEVICE_CODE_FLOW_BLOCK,
    CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
    CONTROL_GUEST_MFA,
    CONTROL_BREAK_GLASS_EXCLUSION,
    CONTROL_HIGH_RISK_SIGN_IN_BLOCK,
    CONTROL_RISK_BASED_STEP_UP_MFA,
}

# Block policies use a fixed scope (all users / all apps); rollout phases
# other than FULL are rejected for them.
_BLOCK_POLICY_CONTROLS = {
    CONTROL_LEGACY_AUTH_BLOCK,
    CONTROL_DEVICE_CODE_FLOW_BLOCK,
    CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
    CONTROL_HIGH_RISK_SIGN_IN_BLOCK,
    CONTROL_RISK_BASED_STEP_UP_MFA,
}

IDENTITY_TO_CA_CONTROL = {
    "IDENTITY_ADMIN_NO_MFA": CONTROL_MFA_ADMINS,
    "IDENTITY_USER_NO_MFA": CONTROL_MFA_ALL_USERS,
    # Legacy lowercase IDs kept as aliases for any in-flight callers.
    "CA_MFA_ADMINS": CONTROL_MFA_ADMINS,
    "CA_MFA_ALL_USERS": CONTROL_MFA_ALL_USERS,
    "CA_LEGACY_AUTH_BLOCK": CONTROL_LEGACY_AUTH_BLOCK,
    "CA_DEVICE_CODE_FLOW_BLOCK": CONTROL_DEVICE_CODE_FLOW_BLOCK,
    "CA_AUTHENTICATION_TRANSFER_BLOCK": CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
    "CA_GUEST_MFA": CONTROL_GUEST_MFA,
    "CA_BREAK_GLASS_EXCLUSION": CONTROL_BREAK_GLASS_EXCLUSION,
    "CA_HIGH_RISK_SIGN_IN_BLOCK": CONTROL_HIGH_RISK_SIGN_IN_BLOCK,
    "CA_RISK_BASED_STEP_UP_MFA": CONTROL_RISK_BASED_STEP_UP_MFA,
}


class ControlEngineError(RuntimeError):
    pass


@asynccontextmanager
async def _tenant_ca_mutation_lock(db, tenant_id: str):
    has_connection = callable(getattr(db, "connection", None))
    if not has_connection:
        if settings.ENVIRONMENT.lower() == "production":
            raise ControlEngineError("Tenant CA mutation lock unavailable")
        yield
        return
    try:
        acquire_tenant_execution_lock(db=db, tenant_id=tenant_id, blocking=False)
    except TenantExecutionLockError as exc:
        raise ControlEngineError("Another Conditional Access mutation is already running for this tenant") from exc
    try:
        yield
    finally:
        release_tenant_execution_lock(db=db, tenant_id=tenant_id)


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


def normalize_control_id(control_id: str) -> str:
    normalized = str(control_id or "").strip().upper()
    normalized = IDENTITY_TO_CA_CONTROL.get(normalized, normalized)
    if normalized not in SUPPORTED_CONTROL_IDS:
        raise ControlEngineError(f"Unsupported control_id: {control_id}")
    return normalized


def _normalize_mode(mode: str | None) -> str:
    normalized = str(mode or ControlMode.AUDIT).strip().lower()
    if normalized not in ControlMode.ALL:
        raise ControlEngineError(f"Unsupported mode: {mode}")
    return normalized


def _normalize_rollout_phase(rollout_phase: str | None) -> str:
    normalized = str(rollout_phase or ControlRolloutPhase.NONE).strip().lower()
    if normalized not in ControlRolloutPhase.ALL:
        raise ControlEngineError(f"Unsupported rollout_phase: {rollout_phase}")
    return normalized


def _enforcement_mode(mode: str) -> str:
    return "ENFORCED" if mode == ControlMode.ENFORCED else "AUDIT"


def _default_rollout_phase(control_id: str) -> str:
    normalized_control_id = normalize_control_id(control_id)
    if normalized_control_id == CONTROL_MFA_ADMINS:
        return ControlRolloutPhase.ADMINS
    return ControlRolloutPhase.FULL


def _normalize_policy(policy: dict) -> dict:
    conditions = dict(policy.get("conditions") or {})
    auth_flows = conditions.get("authenticationFlows") or {}
    transfer_methods = auth_flows.get("transferMethods")
    if isinstance(transfer_methods, str):
        conditions["authenticationFlows"] = {
            **auth_flows,
            "transferMethods": [transfer_methods],
        }
    return {
        "id": policy.get("id"),
        "displayName": policy.get("displayName"),
        "state": policy.get("state"),
        "conditions": conditions,
        "grantControls": policy.get("grantControls") or {},
    }


def _comparable(value):
    """Graph returns unset CA fields as null or [] and adds @odata annotations; the
    payload we send omits them. Drop empty values and annotations, and compare lists of
    plain values regardless of order, so only meaningful differences count as drift."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if "@odata" in str(key):
                continue
            item = _comparable(item)
            if item is None or item == [] or item == {}:
                continue
            cleaned[key] = item
        return cleaned
    if isinstance(value, list):
        items = [_comparable(item) for item in value]
        if all(isinstance(item, (str, int, float, bool)) for item in items):
            return sorted(items, key=lambda item: (type(item).__name__, item))
        return items
    return value


def _normalize_policy_semantics(policy: dict) -> dict:
    normalized = _normalize_policy(policy)
    normalized.pop("id", None)
    return _comparable(normalized)


def get_control_policy_base_name(control_id: str) -> str:
    normalized_control_id = normalize_control_id(control_id)
    if normalized_control_id not in CONTROL_POLICY_MAP:
        raise ControlEngineError(f"Control {normalized_control_id} does not own a CLX policy")
    return CONTROL_POLICY_MAP[normalized_control_id]


def _sorted_policies(policies: Iterable[dict]) -> list[dict]:
    normalized = [_normalize_policy(policy) for policy in policies if isinstance(policy, dict)]
    return sorted(
        normalized,
        key=lambda policy: (
            str(policy.get("displayName") or ""),
            str(policy.get("id") or ""),
        ),
    )


def _sorted_policy_semantics(policies: Iterable[dict]) -> list[dict]:
    normalized = [_normalize_policy_semantics(policy) for policy in policies if isinstance(policy, dict)]
    return sorted(
        normalized,
        key=lambda policy: str(policy.get("displayName") or ""),
    )


def _normalize_managed_policy_ids(policy_ids: Iterable[str] | None) -> list[str]:
    if not policy_ids:
        return []
    return sorted(
        {str(policy_id).strip() for policy_id in policy_ids if isinstance(policy_id, str) and str(policy_id).strip()}
    )


def _policy_ids_from_policies(policies: Iterable[dict] | None) -> list[str]:
    return _normalize_managed_policy_ids(policy.get("id") for policy in policies or [] if isinstance(policy, dict))


def _managed_policy_ids_from_state(state) -> list[str]:
    return _normalize_managed_policy_ids(getattr(state, "managed_policy_ids", None))


def _managed_policy_ids_from_snapshot(snapshot) -> list[str]:
    explicit = _normalize_managed_policy_ids(getattr(snapshot, "managed_policy_ids", None))
    if explicit:
        return explicit
    return _policy_ids_from_policies(getattr(snapshot, "policies", None))


def _policy_targets_all_users(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    include_users = users.get("includeUsers") or []
    return "All" in include_users


async def _validate_break_glass_accounts(graph_client, break_glass_ids: list[str]) -> None:
    if not break_glass_ids:
        raise ControlEngineError("Break-glass accounts are required before CA mutation")

    global_admin_role_id = None
    directory_roles = await fetch_directory_roles(graph_client.db, graph_client.tenant)
    for role in directory_roles:
        if role.get("displayName") == "Global Administrator":
            global_admin_role_id = role.get("id")
            break
    if not isinstance(global_admin_role_id, str) or not global_admin_role_id:
        raise ControlEngineError("Global Administrator directory role is unavailable")

    members = await fetch_role_members(graph_client.db, graph_client.tenant, global_admin_role_id)
    global_admin_ids = {
        member.get("id")
        for member in members
        if isinstance(member, dict) and isinstance(member.get("id"), str) and member.get("id")
    }
    for user_id in break_glass_ids:
        if user_id not in global_admin_ids:
            raise ControlEngineError(f"Invalid break-glass account: {user_id}")


async def _fetch_admin_member_ids(graph_client) -> set[str]:
    directory_roles = await fetch_directory_roles(graph_client.db, graph_client.tenant)
    matching_roles = [
        role
        for role in directory_roles
        if (
            isinstance(role, dict)
            and (role.get("roleTemplateId") in PRIVILEGED_ROLE_IDS or role.get("id") in PRIVILEGED_ROLE_IDS)
            and isinstance(role.get("id"), str)
            and role.get("id")
        )
    ]
    admin_ids: set[str] = set()
    for role in matching_roles:
        for member in await fetch_role_members(
            graph_client.db,
            graph_client.tenant,
            role["id"],
        ):
            user_id = member.get("id") if isinstance(member, dict) else None
            if isinstance(user_id, str) and user_id:
                admin_ids.add(user_id)
    return admin_ids


async def calculate_affected_users(
    *,
    graph_client,
    policy: dict,
    break_glass_ids: list[str],
) -> int:
    excluded = set(break_glass_ids)
    users = (policy.get("conditions") or {}).get("users") or {}
    include_users = users.get("includeUsers") or []
    include_groups = users.get("includeGroups") or []
    include_roles = users.get("includeRoles") or []

    if "All" in include_users:
        all_users = await fetch_users(graph_client.db, graph_client.tenant)
        return sum(
            1
            for user in all_users
            if isinstance(user, dict)
            and isinstance(user.get("id"), str)
            and user.get("id")
            and user.get("id") not in excluded
        )

    affected_user_ids: set[str] = set()
    for group_id in include_groups:
        if isinstance(group_id, str) and group_id:
            affected_user_ids.update(await get_group_members(graph_client, group_id))

    if include_roles:
        affected_user_ids.update(await _fetch_admin_member_ids(graph_client))

    return len({user_id for user_id in affected_user_ids if user_id not in excluded})


def _policies_equal(current_policies: list[dict], expected_policies: list[dict]) -> bool:
    return _sorted_policy_semantics(current_policies) == _sorted_policy_semantics(expected_policies)


def detect_drift(current_policies: list[dict], expected_policies: list[dict]) -> bool:
    return not _policies_equal(current_policies, expected_policies)


async def retry_with_backoff(fn, *, attempts: int = 3):
    delays = [1, 2, 3]
    last_value = None
    for attempt in range(attempts):
        last_value = await fn()
        if last_value is not None:
            return last_value
        if attempt < attempts - 1:
            await asyncio.sleep(delays[min(attempt, len(delays) - 1)])
    return last_value


async def policy_matches_expected(
    *,
    graph_client,
    control_id: str,
    expected_policies: list[dict],
    managed_policy_ids: list[str] | None = None,
) -> bool:
    current_policies = await fetch_clx_policies(
        graph_client,
        control_id,
        managed_policy_ids=managed_policy_ids,
    )
    return not detect_drift(current_policies, expected_policies)


async def verify_exact_state(
    *,
    graph_client,
    control_id: str,
    expected_policies: list[dict],
    managed_policy_ids: list[str] | None = None,
    retries: int = 3,
) -> list[dict]:
    normalized_expected = _sorted_policy_semantics(expected_policies)

    async def _check():
        current_policies = await fetch_clx_policies(
            graph_client,
            control_id,
            managed_policy_ids=managed_policy_ids,
        )
        if _sorted_policy_semantics(current_policies) == normalized_expected:
            return current_policies
        return None

    current = await retry_with_backoff(_check, attempts=retries)
    if current is None:
        raise ControlEngineError("Exact state verification failed after retries")
    return current


def build_policy(
    control_id: str,
    mode: str,
    rollout_phase: str,
    break_glass_ids: list[str],
    *,
    target_group_id: str | None = None,
    policy_version: int | None = None,
) -> dict:
    normalized_control_id = normalize_control_id(control_id)
    if normalized_control_id == CONTROL_BREAK_GLASS_EXCLUSION:
        raise ControlEngineError(
            "CA_BREAK_GLASS_EXCLUSION does not own a CLX policy — " "use apply_break_glass_exclusion() instead"
        )
    normalized_mode = _normalize_mode(mode)
    normalized_rollout_phase = _normalize_rollout_phase(rollout_phase)
    if not break_glass_ids:
        raise ControlEngineError("Break-glass accounts are required before CA mutation")
    normalized_policy_version = int(policy_version or 1)
    if normalized_policy_version < 1:
        raise ControlEngineError("policy_version must be >= 1")
    display_name = f"{get_control_policy_base_name(normalized_control_id)}" f"-v{normalized_policy_version}"
    if normalized_rollout_phase == ControlRolloutPhase.NONE:
        raise ControlEngineError("Cannot apply control with no rollout scope")
    if normalized_control_id in _BLOCK_POLICY_CONTROLS and normalized_rollout_phase != ControlRolloutPhase.FULL:
        raise ControlEngineError(f"{normalized_control_id} only supports rollout_phase=FULL")

    enforcement_mode = _enforcement_mode(normalized_mode)
    if normalized_control_id == CONTROL_MFA_ADMINS:
        policy = build_mfa_admins_policy(enforcement_mode=enforcement_mode)
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    if normalized_control_id == CONTROL_LEGACY_AUTH_BLOCK:
        policy = build_legacy_auth_block_policy(
            enforcement_mode=enforcement_mode,
            exclude_users=break_glass_ids,
        )
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    if normalized_control_id == CONTROL_DEVICE_CODE_FLOW_BLOCK:
        policy = build_device_code_flow_block_policy(
            enforcement_mode=enforcement_mode,
            exclude_users=break_glass_ids,
        )
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    if normalized_control_id == CONTROL_AUTHENTICATION_TRANSFER_BLOCK:
        policy = build_authentication_transfer_block_policy(
            enforcement_mode=enforcement_mode,
            exclude_users=break_glass_ids,
        )
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    if normalized_control_id == CONTROL_GUEST_MFA:
        policy = build_guest_mfa_policy(
            enforcement_mode=enforcement_mode,
            exclude_users=break_glass_ids,
        )
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    if normalized_control_id == CONTROL_HIGH_RISK_SIGN_IN_BLOCK:
        policy = build_high_risk_sign_in_block_policy(
            enforcement_mode=enforcement_mode,
            exclude_users=break_glass_ids,
        )
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    if normalized_control_id == CONTROL_RISK_BASED_STEP_UP_MFA:
        policy = build_risk_based_step_up_mfa_policy(
            enforcement_mode=enforcement_mode,
            exclude_users=break_glass_ids,
        )
        policy["displayName"] = display_name
        users = dict((policy.get("conditions") or {}).get("users") or {})
        users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
        policy["conditions"]["users"] = users
        return policy

    policy = build_mfa_all_users_policy(
        enforcement_mode=enforcement_mode,
        exclude_users=break_glass_ids,
    )
    policy["displayName"] = display_name
    users = dict((policy.get("conditions") or {}).get("users") or {})
    if normalized_rollout_phase == ControlRolloutPhase.ADMINS:
        users["includeUsers"] = []
        users["includeRoles"] = list(PRIVILEGED_ROLE_IDS)
        users["includeGroups"] = []
    elif normalized_rollout_phase == ControlRolloutPhase.PARTIAL:
        if not target_group_id:
            raise ControlEngineError("target_group_id is required for partial rollout")
        users["includeUsers"] = []
        users["includeRoles"] = []
        users["includeGroups"] = [target_group_id]
    elif normalized_rollout_phase == ControlRolloutPhase.FULL:
        users["includeUsers"] = ["All"]
        users["includeRoles"] = []
        users["includeGroups"] = []
    else:
        users["includeUsers"] = []
        users["includeRoles"] = []
        users["includeGroups"] = []
    users["excludeUsers"] = list(dict.fromkeys(break_glass_ids))
    policy["conditions"]["users"] = users
    return policy


async def fetch_clx_policies(
    graph_client,
    control_id: str | None = None,
    *,
    managed_policy_ids: list[str] | None = None,
) -> list[dict]:
    policies = await graph_client.list_conditional_access_policies()
    tracked_ids = set(_normalize_managed_policy_ids(managed_policy_ids))
    # First apply for this control has no tracked IDs yet — return empty so
    # the caller creates the policy via Graph directly. On subsequent calls,
    # managed_policy_ids is populated from DB state.
    if not tracked_ids:
        return []
    return _sorted_policies(
        policy for policy in policies if isinstance(policy, dict) and str(policy.get("id") or "") in tracked_ids
    )


async def delete_clx_policies(
    graph_client,
    control_id: str,
    *,
    managed_policy_ids: list[str] | None = None,
) -> list[str]:
    current_policies = await fetch_clx_policies(
        graph_client,
        control_id,
        managed_policy_ids=managed_policy_ids,
    )
    deleted_policy_ids: list[str] = []
    for policy in current_policies:
        policy_id = policy.get("id")
        if not isinstance(policy_id, str) or not policy_id:
            continue
        await graph_client.delete_conditional_access_policy(policy_id)
        deleted_policy_ids.append(policy_id)
    return deleted_policy_ids


async def apply_policy(
    graph_client,
    policy: dict,
    *,
    control_id: str,
    managed_policy_ids: list[str] | None = None,
    cleanup: bool = True,
) -> dict:
    existing_policies = await fetch_clx_policies(
        graph_client,
        control_id,
        managed_policy_ids=managed_policy_ids,
    )
    existing = next(
        (current for current in existing_policies if current.get("displayName") == policy.get("displayName")),
        None,
    )
    action = "created"
    policy_id = None
    if existing and existing.get("id"):
        await graph_client.update_conditional_access_policy(existing["id"], policy)
        action = "updated"
        policy_id = existing["id"]
    else:
        created = await graph_client.create_conditional_access_policy(policy)
        policy_id = created.get("id")

    pruned_policy_ids: list[str] = []
    if cleanup:
        for current in existing_policies:
            current_id = current.get("id")
            if not isinstance(current_id, str) or not current_id or current_id == policy_id:
                continue
            await graph_client.delete_conditional_access_policy(current_id)
            pruned_policy_ids.append(current_id)

    return {
        "action": action,
        "policy_id": policy_id,
        "policy_name": policy.get("displayName"),
        "policy": _normalize_policy({**policy, "id": policy_id}),
        "pruned_policy_ids": pruned_policy_ids,
    }


async def apply_policies_bulk(
    *,
    graph_client,
    control_id: str,
    policies: list[dict],
    managed_policy_ids: list[str] | None = None,
) -> list[dict]:
    applied_policies: list[dict] = []
    for policy in _sorted_policies(policies):
        applied = await apply_policy(
            graph_client,
            policy,
            control_id=control_id,
            managed_policy_ids=managed_policy_ids,
            cleanup=False,
        )
        applied_policies.append(applied["policy"])
    return applied_policies


def _record_control_execution(
    *,
    db,
    tenant_id: str,
    control_id: str,
    mode: str,
    rollout_phase: str,
    status: str,
    snapshot_id,
    policies_created: list[dict] | None = None,
    policies_updated: list[dict] | None = None,
    managed_policy_ids: list[str] | None = None,
    error_message: str | None = None,
    verified: bool = False,
) -> ControlExecution:
    if status == ControlExecutionStatus.SUCCESS and snapshot_id is None:
        raise ControlEngineError("Successful control execution requires snapshot_id")
    if status == ControlExecutionStatus.SUCCESS and not verified:
        raise ControlEngineError("Successful control execution requires verified=True")
    if (
        status
        in {
            ControlExecutionStatus.BLOCKED,
            ControlExecutionStatus.PARTIAL,
            ControlExecutionStatus.FAILED,
        }
        and verified
    ):
        raise ControlEngineError(f"{status} control execution cannot be verified=True")
    execution = ControlExecution(
        tenant_id=tenant_id,
        control_id=control_id,
        mode=mode,
        rollout_phase=rollout_phase,
        status=status,
        policies_created=policies_created or [],
        policies_updated=policies_updated or [],
        managed_policy_ids=_normalize_managed_policy_ids(managed_policy_ids),
        snapshot_id=snapshot_id,
        error_message=error_message,
        verified=verified,
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)
    return execution


async def _verify_control_semantics(*, graph_client, control_id: str) -> bool:
    normalized_control_id = normalize_control_id(control_id)
    verifier_map = {
        CONTROL_MFA_ALL_USERS: verify_ca_mfa_all_users,
        CONTROL_MFA_ADMINS: verify_ca_mfa_admins,
        CONTROL_LEGACY_AUTH_BLOCK: verify_ca_legacy_auth_block,
        CONTROL_DEVICE_CODE_FLOW_BLOCK: verify_ca_device_code_flow_block,
        CONTROL_AUTHENTICATION_TRANSFER_BLOCK: verify_ca_authentication_transfer_block,
        CONTROL_GUEST_MFA: verify_ca_guest_mfa,
        CONTROL_BREAK_GLASS_EXCLUSION: verify_ca_break_glass_exclusion,
        CONTROL_HIGH_RISK_SIGN_IN_BLOCK: verify_ca_high_risk_sign_in_block,
        CONTROL_RISK_BASED_STEP_UP_MFA: verify_ca_risk_based_step_up_mfa,
    }
    verifier = verifier_map.get(normalized_control_id)
    if verifier is None:
        raise ControlEngineError(f"No semantic verifier registered for control {normalized_control_id}")
    return bool(await verifier(graph_client=graph_client))


async def update_rollout(
    *,
    db,
    tenant,
    control_id: str,
    percentage: int,
) -> dict:
    normalized_control_id = normalize_control_id(control_id)
    from app.services.remediation_executor import RemediationGraphClient

    rollout_percentage = max(0, min(100, int(percentage)))
    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    break_glass_ids = set(list_break_glass_user_ids(db=db, tenant_id=tenant.id))
    await _validate_break_glass_accounts(graph_client, list(break_glass_ids))

    group = await create_rollout_group(graph_client, tenant, normalized_control_id, db=db)
    group_id = group.get("id")
    if not isinstance(group_id, str) or not group_id:
        raise ControlEngineError("Rollout group creation failed")

    users = await fetch_users(db, tenant)
    eligible_user_ids = sorted(
        user.get("id")
        for user in users
        if isinstance(user, dict)
        and isinstance(user.get("id"), str)
        and user.get("id")
        and user.get("id") not in break_glass_ids
    )
    target_count = int(len(eligible_user_ids) * rollout_percentage / 100)
    selected_user_ids = eligible_user_ids[:target_count]

    current_members = set(await get_group_members(graph_client, group_id))
    desired_members = set(selected_user_ids)

    to_remove = sorted(current_members - desired_members)
    if to_remove:
        await remove_users_from_group(
            graph_client,
            group_id,
            to_remove,
            db=db,
            tenant_id=str(tenant.id),
            control_id=normalized_control_id,
        )
    to_add = sorted(desired_members - current_members)
    if to_add:
        await add_users_to_group(
            graph_client,
            group_id,
            to_add,
            db=db,
            tenant_id=str(tenant.id),
            control_id=normalized_control_id,
        )

    rollout_phase = (
        ControlRolloutPhase.NONE
        if rollout_percentage <= 0
        else (ControlRolloutPhase.FULL if rollout_percentage >= 100 else ControlRolloutPhase.PARTIAL)
    )
    await create_or_update_control_state(
        db,
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        rollout_phase=rollout_phase,
        rollout_percentage=rollout_percentage,
        target_group_id=group_id,
    )
    return {
        "rollout_percentage": rollout_percentage,
        "users_affected": len(selected_user_ids),
    }


async def _compute_expected_rollout_members(
    *,
    db,
    tenant,
    rollout_percentage: int,
    break_glass_ids: list[str],
) -> list[str]:
    users = await fetch_users(db, tenant)
    eligible_user_ids = sorted(
        user.get("id")
        for user in users
        if isinstance(user, dict)
        and isinstance(user.get("id"), str)
        and user.get("id")
        and user.get("id") not in set(break_glass_ids)
    )
    target_count = int(len(eligible_user_ids) * rollout_percentage / 100)
    return eligible_user_ids[:target_count]


async def _sync_rollout_group_members(
    *,
    graph_client,
    group_id: str,
    expected_members: list[str],
    db,
    tenant_id: str,
    control_id: str,
) -> None:
    current_members = set(await get_group_members(graph_client, group_id))
    desired_members = set(expected_members)
    to_remove = sorted(current_members - desired_members)
    to_add = sorted(desired_members - current_members)
    if to_remove:
        await remove_users_from_group(
            graph_client,
            group_id,
            to_remove,
            db=db,
            tenant_id=tenant_id,
            control_id=control_id,
        )
    if to_add:
        await add_users_to_group(
            graph_client,
            group_id,
            to_add,
            db=db,
            tenant_id=tenant_id,
            control_id=control_id,
        )


async def _verify_group_members_exact(
    *,
    graph_client,
    group_id: str,
    expected_members: list[str],
) -> list[str]:
    expected = set(expected_members)

    async def _check():
        current = sorted(await get_group_members(graph_client, group_id))
        if set(current) == expected:
            return current
        return None

    current = await retry_with_backoff(_check, attempts=3)
    if current is None:
        raise ControlEngineError("Exact state verification failed after retries")
    return current


async def apply_control(
    *,
    db,
    tenant,
    control_id: str,
    mode: str | None = None,
    rollout_phase: str | None = None,
    rollout_percentage: int | None = None,
    policy_version: int | None = None,
    last_applied_at: datetime | None = None,
) -> dict:
    normalized_control_id = normalize_control_id(control_id)
    from app.services.remediation_executor import RemediationGraphClient

    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    # Read-only safety checks first: the licence probe below writes to the tenant.
    break_glass_ids = list_break_glass_user_ids(db=db, tenant_id=tenant.id)
    if not break_glass_ids:
        raise ControlEngineError("Break-glass accounts are required before applying CLX Conditional Access policies")
    await _validate_break_glass_accounts(graph_client, break_glass_ids)
    if not await check_conditional_access_license(graph_client):
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            mode=_normalize_mode(mode if mode is not None else ControlMode.AUDIT),
            rollout_phase=_normalize_rollout_phase(
                rollout_phase if rollout_phase is not None else _default_rollout_phase(normalized_control_id)
            ),
            status=ControlExecutionStatus.BLOCKED,
            snapshot_id=None,
            error_message="NO_CA_LICENSE",
            verified=False,
        )
        return {
            "status": "blocked",
            "reason": "NO_CA_LICENSE",
            "verified": False,
            "control_id": normalized_control_id,
            "execution_id": str(execution.id),
        }

    current_state = await get_control_state(db, tenant.id, normalized_control_id)
    current_managed_policy_ids = _managed_policy_ids_from_state(current_state)
    requested_mode = _normalize_mode(mode if mode is not None else ControlMode.AUDIT)
    requested_rollout_phase = _normalize_rollout_phase(
        rollout_phase
        if rollout_phase is not None
        else (
            current_state.rollout_phase if current_state is not None else _default_rollout_phase(normalized_control_id)
        )
    )
    if requested_rollout_phase == ControlRolloutPhase.NONE:
        raise ControlEngineError("Cannot apply control with no rollout scope")
    requested_rollout_percentage = (
        rollout_percentage
        if rollout_percentage is not None
        else (
            current_state.rollout_percentage
            if current_state is not None
            else (100 if requested_rollout_phase == ControlRolloutPhase.FULL else 0)
        )
    )
    # Group identity always comes from DB state (set by create_rollout_group),
    # never from caller-supplied input.
    # Bootstrap case: first-time PARTIAL rollout with no existing state — create the
    # DB-tracked rollout group now so we have an ID to embed in the policy.
    if requested_rollout_phase == ControlRolloutPhase.PARTIAL and (
        current_state is None or current_state.target_group_id is None
    ):
        _bootstrap_group = await create_rollout_group(graph_client, tenant, normalized_control_id, db=db)
        requested_target_group_id = _bootstrap_group.get("id")
    else:
        requested_target_group_id = current_state.target_group_id if current_state is not None else None
    requested_policy_version = (
        policy_version
        if policy_version is not None
        else (current_state.policy_version if current_state is not None else 1)
    )
    desired_policy = build_policy(
        normalized_control_id,
        requested_mode,
        requested_rollout_phase,
        break_glass_ids,
        target_group_id=requested_target_group_id,
        policy_version=requested_policy_version,
    )
    normalized_expected_policies = [_normalize_policy(desired_policy)]

    # Drift / no-op only make sense when the engine manages a policy. With none (first
    # apply, or after a rollback emptied managed_policy_ids) the policy is created
    # below; otherwise a rolled-back control could never be applied again.
    if (
        current_state is not None
        and current_managed_policy_ids
        and current_state.mode == requested_mode
        and current_state.rollout_phase == requested_rollout_phase
        and current_state.rollout_percentage == requested_rollout_percentage
        and current_state.target_group_id == requested_target_group_id
        and current_state.policy_version == requested_policy_version
    ):
        policy_is_exact = await policy_matches_expected(
            graph_client=graph_client,
            control_id=normalized_control_id,
            expected_policies=normalized_expected_policies,
            managed_policy_ids=current_managed_policy_ids,
        )
        if not policy_is_exact:
            logger.warning(
                "ca_policy_drift_detected tenant_id=%s control_id=%s",
                tenant.id,
                normalized_control_id,
            )
            if not settings.ENABLE_AUTO_REMEDIATION:
                return {
                    "status": "drift_detected",
                    "verified": False,
                    "control_id": normalized_control_id,
                }
            # ENABLE_AUTO_REMEDIATION=True: fall through to re-apply below.
        else:
            if (
                requested_rollout_phase == ControlRolloutPhase.PARTIAL
                and isinstance(requested_target_group_id, str)
                and requested_target_group_id
            ):
                expected_members = await _compute_expected_rollout_members(
                    db=db,
                    tenant=tenant,
                    rollout_percentage=requested_rollout_percentage,
                    break_glass_ids=break_glass_ids,
                )
                actual_members = sorted(await get_group_members(graph_client, requested_target_group_id))
                if set(expected_members) != set(actual_members):
                    logger.warning(
                        "ca_rollout_group_drift_detected tenant_id=%s control_id=%s group_id=%s",
                        tenant.id,
                        normalized_control_id,
                        requested_target_group_id,
                    )
                    await _sync_rollout_group_members(
                        graph_client=graph_client,
                        group_id=requested_target_group_id,
                        expected_members=expected_members,
                        db=db,
                        tenant_id=str(tenant.id),
                        control_id=normalized_control_id,
                    )
                    await _verify_group_members_exact(
                        graph_client=graph_client,
                        group_id=requested_target_group_id,
                        expected_members=expected_members,
                    )
            affected_users = await calculate_affected_users(
                graph_client=graph_client,
                policy=desired_policy,
                break_glass_ids=break_glass_ids,
            )
            if affected_users <= 0 and normalized_control_id not in _BLOCK_POLICY_CONTROLS:
                raise ControlEngineError("Control applied but affects no users")
            return {
                "status": "no-op",
                "verified": True,
                "affected_users": affected_users,
                "control_id": normalized_control_id,
                "state": {
                    "mode": current_state.mode,
                    "rollout_phase": current_state.rollout_phase,
                    "rollout_percentage": current_state.rollout_percentage,
                    "target_group_id": current_state.target_group_id,
                    "policy_version": current_state.policy_version,
                    "status": current_state.status,
                },
            }

    state = await create_or_update_control_state(
        db,
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        mode=requested_mode,
        rollout_phase=requested_rollout_phase,
        rollout_percentage=requested_rollout_percentage,
        target_group_id=requested_target_group_id,
        policy_version=requested_policy_version,
        status=ControlStateStatus.ACTIVE,
        last_applied_at=last_applied_at,
    )

    existing_policies = await fetch_clx_policies(
        graph_client,
        normalized_control_id,
        managed_policy_ids=current_managed_policy_ids,
    )
    snapshot = await create_snapshot(
        db,
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        policies=existing_policies,
        managed_policy_ids=current_managed_policy_ids,
    )

    applied = None
    new_managed_policy_ids = current_managed_policy_ids
    try:
        applied = await apply_policy(
            graph_client,
            desired_policy,
            control_id=normalized_control_id,
            managed_policy_ids=current_managed_policy_ids,
        )
        new_managed_policy_ids = _normalize_managed_policy_ids(
            [
                *current_managed_policy_ids,
                applied.get("policy_id"),
            ]
        )
        pruned_policy_ids = set(applied.get("pruned_policy_ids") or [])
        if pruned_policy_ids:
            new_managed_policy_ids = [
                policy_id for policy_id in new_managed_policy_ids if policy_id not in pruned_policy_ids
            ]
        verified_structural = False
        try:
            await verify_exact_state(
                graph_client=graph_client,
                control_id=normalized_control_id,
                expected_policies=normalized_expected_policies,
                managed_policy_ids=new_managed_policy_ids,
            )
            verified_structural = True
        except ControlEngineError:
            verified_structural = False
        # The detectors count only enabled policies, so they cannot verify a report-only
        # policy. A report-only fix is verified structurally: the managed policy exists
        # exactly as intended, in the report-only state. It protects no one, so callers
        # must not treat it as resolving the finding (see verification_scope).
        report_only = desired_policy.get("state") == CA_STATE_REPORT_ONLY
        verification_scope = "report_only" if report_only else "enforced"
        if report_only:
            verified_semantic = True
        else:
            verified_semantic = await _verify_control_semantics(
                graph_client=graph_client,
                control_id=normalized_control_id,
            )
        affected_users = await calculate_affected_users(
            graph_client=graph_client,
            policy=desired_policy,
            break_glass_ids=break_glass_ids,
        )
        policies_created = [applied["policy"]] if applied["action"] == "created" else []
        policies_updated = [applied["policy"]] if applied["action"] == "updated" else []
        if not (verified_structural and verified_semantic):
            state = await create_or_update_control_state(
                db,
                tenant_id=tenant.id,
                control_id=normalized_control_id,
                status=ControlStateStatus.ERROR,
                managed_policy_ids=new_managed_policy_ids,
            )
            execution = _record_control_execution(
                db=db,
                tenant_id=tenant.id,
                control_id=normalized_control_id,
                mode=state.mode,
                rollout_phase=state.rollout_phase,
                status=ControlExecutionStatus.PARTIAL,
                snapshot_id=snapshot.id,
                policies_created=policies_created,
                policies_updated=policies_updated,
                managed_policy_ids=new_managed_policy_ids,
                error_message=(
                    f"VERIFICATION_FAILED structural={verified_structural} semantic={verified_semantic} "
                    f"scope={verification_scope}"
                ),
                verified=False,
            )
            return {
                "status": "partial",
                "reason": "verification_failed",
                "verified": False,
                "verification_scope": verification_scope,
                "control_id": normalized_control_id,
                "snapshot_id": str(snapshot.id),
                "execution_id": str(execution.id),
                "affected_users": affected_users,
                "verification": {
                    "structural": verified_structural,
                    "semantic": verified_semantic,
                },
                "policy_result": applied,
            }
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            status=ControlStateStatus.ACTIVE,
            managed_policy_ids=new_managed_policy_ids,
            last_applied_at=last_applied_at or datetime.utcnow(),
        )
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            mode=state.mode,
            rollout_phase=state.rollout_phase,
            status=ControlExecutionStatus.SUCCESS,
            snapshot_id=snapshot.id,
            policies_created=policies_created,
            policies_updated=policies_updated,
            managed_policy_ids=new_managed_policy_ids,
            verified=True,
        )
        return {
            "status": "success",
            "verified": True,
            "verification_scope": verification_scope,
            "affected_users": affected_users,
            "control_id": normalized_control_id,
            "snapshot_id": str(snapshot.id),
            "execution_id": str(execution.id),
            "state": {
                "mode": state.mode,
                "rollout_phase": state.rollout_phase,
                "rollout_percentage": state.rollout_percentage,
                "target_group_id": state.target_group_id,
                "policy_version": state.policy_version,
                "managed_policy_ids": new_managed_policy_ids,
                "status": state.status,
            },
            "policy_result": applied,
        }
    except GraphAPIError as exc:
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            status=ControlStateStatus.ERROR,
            managed_policy_ids=new_managed_policy_ids,
        )
        execution_status = ControlExecutionStatus.PARTIAL if applied is not None else ControlExecutionStatus.FAILED
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            mode=state.mode,
            rollout_phase=state.rollout_phase,
            status=execution_status,
            snapshot_id=snapshot.id,
            managed_policy_ids=new_managed_policy_ids,
            error_message=str(exc),
        )
        return {
            "status": execution_status,
            "reason": "partial_execution" if execution_status == ControlExecutionStatus.PARTIAL else "execution_failed",
            "verified": False,
            "control_id": normalized_control_id,
            "snapshot_id": str(snapshot.id),
            "execution_id": str(execution.id),
            "error": str(exc),
        }
    except Exception as exc:
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            status=ControlStateStatus.ERROR,
            managed_policy_ids=new_managed_policy_ids,
        )
        execution_status = ControlExecutionStatus.PARTIAL if applied is not None else ControlExecutionStatus.FAILED
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            mode=state.mode,
            rollout_phase=state.rollout_phase,
            status=execution_status,
            snapshot_id=snapshot.id,
            managed_policy_ids=new_managed_policy_ids,
            error_message=str(exc),
        )
        return {
            "status": execution_status,
            "reason": "partial_execution" if execution_status == ControlExecutionStatus.PARTIAL else "execution_failed",
            "verified": False,
            "control_id": normalized_control_id,
            "snapshot_id": str(snapshot.id),
            "execution_id": str(execution.id),
            "error": str(exc),
        }


async def rollback_control(
    *,
    db,
    tenant,
    execution_id: str | None = None,
    control_id: str | None = None,
    use_latest: bool = False,
) -> dict:
    from app.services.remediation_executor import RemediationGraphClient

    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    source_execution = None
    snapshot = None

    if use_latest:
        if not control_id:
            raise ControlEngineError("control_id is required when use_latest=True")
        normalized_control_id = normalize_control_id(control_id)
        snapshot = await get_latest_snapshot(db, tenant.id, normalized_control_id)
        if snapshot is None:
            raise ControlEngineError(f"No control snapshot found for {normalized_control_id}")
    else:
        if not execution_id:
            raise ControlEngineError("execution_id is required for rollback")
        try:
            parsed_execution_id = uuid.UUID(str(execution_id))
        except (TypeError, ValueError) as exc:
            raise ControlEngineError("execution_id must be a valid UUID") from exc
        result = await _maybe_await(
            db.execute(
                select(ControlExecution).where(
                    ControlExecution.id == parsed_execution_id,
                    ControlExecution.tenant_id == tenant.id,
                )
            )
        )
        source_execution = result.scalars().first()
        if source_execution is None:
            raise ControlEngineError("Control execution not found")
        # PARTIAL: the change was applied but not verified; the snapshot still holds the
        # pre-change state. FAILED: nothing was applied, so there is nothing to undo.
        if source_execution.status not in {ControlExecutionStatus.SUCCESS, ControlExecutionStatus.PARTIAL}:
            raise ControlEngineError("Cannot rollback a failed execution: nothing was applied")
        if source_execution.snapshot_id is None:
            raise ControlEngineError("Execution has no snapshot_id, cannot rollback safely")

        normalized_control_id = normalize_control_id(source_execution.control_id)
        if control_id is not None:
            requested_control_id = normalize_control_id(control_id)
            if requested_control_id != normalized_control_id:
                raise ControlEngineError("execution_id does not match the requested control_id")

        snapshot = await get_snapshot_by_id(
            db,
            tenant.id,
            source_execution.snapshot_id,
        )
        if snapshot is None:
            raise ControlEngineError("Execution snapshot not found, cannot rollback safely")
        if normalize_control_id(snapshot.control_id) != normalized_control_id:
            raise ControlEngineError("Execution snapshot does not match the execution control_id")

    break_glass_ids = list_break_glass_user_ids(db=db, tenant_id=tenant.id)
    if not break_glass_ids:
        raise ControlEngineError("Break-glass accounts are required before rollback")
    await _validate_break_glass_accounts(graph_client, break_glass_ids)

    current_state = await get_control_state(db, tenant.id, normalized_control_id)
    current_managed_policy_ids = _managed_policy_ids_from_state(current_state)
    snapshot_managed_policy_ids = _managed_policy_ids_from_snapshot(snapshot)
    recreated_policies: list[dict] = []
    restored_policy_ids: list[str] = []
    deleted_policy_ids: list[str] = []
    try:
        recreated_policies = await apply_policies_bulk(
            graph_client=graph_client,
            control_id=normalized_control_id,
            policies=snapshot.policies or [],
            managed_policy_ids=snapshot_managed_policy_ids,
        )
        restored_policy_ids = _policy_ids_from_policies(recreated_policies)
        await verify_exact_state(
            graph_client=graph_client,
            control_id=normalized_control_id,
            expected_policies=snapshot.policies or [],
            managed_policy_ids=restored_policy_ids,
        )
        superseded_policy_ids = [
            policy_id for policy_id in current_managed_policy_ids if policy_id not in set(restored_policy_ids)
        ]
        if superseded_policy_ids:
            deleted_policy_ids = await delete_clx_policies(
                graph_client,
                normalized_control_id,
                managed_policy_ids=superseded_policy_ids,
            )
    except GraphAPIError as exc:
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            status=ControlStateStatus.ERROR,
            managed_policy_ids=_normalize_managed_policy_ids([*current_managed_policy_ids, *restored_policy_ids]),
        )
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            mode=state.mode,
            rollout_phase=state.rollout_phase,
            status="partial",
            snapshot_id=snapshot.id,
            policies_created=recreated_policies,
            policies_updated=[],
            managed_policy_ids=_normalize_managed_policy_ids([*current_managed_policy_ids, *restored_policy_ids]),
            error_message=str(exc),
        )
        raise ControlEngineError(f"Rollback failed for {normalized_control_id}: {exc}") from exc
    except Exception as exc:
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            status=ControlStateStatus.ERROR,
            managed_policy_ids=_normalize_managed_policy_ids([*current_managed_policy_ids, *restored_policy_ids]),
        )
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
            mode=state.mode,
            rollout_phase=state.rollout_phase,
            status="partial",
            snapshot_id=snapshot.id,
            policies_created=recreated_policies,
            policies_updated=[],
            managed_policy_ids=_normalize_managed_policy_ids([*current_managed_policy_ids, *restored_policy_ids]),
            error_message=str(exc),
        )
        raise ControlEngineError(f"Rollback failed for {normalized_control_id}: {exc}") from exc

    state = await get_control_state(db, tenant.id, normalized_control_id)
    if state is None:
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=normalized_control_id,
        )
    state = await create_or_update_control_state(
        db,
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        status=ControlStateStatus.ACTIVE,
        managed_policy_ids=restored_policy_ids,
        last_applied_at=datetime.utcnow(),
    )
    execution = _record_control_execution(
        db=db,
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        mode=state.mode,
        rollout_phase=state.rollout_phase,
        status="success",
        snapshot_id=snapshot.id,
        policies_created=recreated_policies,
        policies_updated=[],
        managed_policy_ids=restored_policy_ids,
        verified=True,
    )
    return {
        "status": "success",
        "control_id": normalized_control_id,
        "snapshot_id": str(snapshot.id),
        "execution_id": str(execution.id),
        "rolled_back_execution_id": (str(source_execution.id) if source_execution is not None else None),
        "deleted_policy_ids": deleted_policy_ids,
        "recreated_policy_ids": [policy.get("id") for policy in recreated_policies if isinstance(policy, dict)],
    }


# ---------------------------------------------------------------------------
# CA_BREAK_GLASS_EXCLUSION — patches existing tenant policies to add
# break-glass exclusions. Operates on N policies, not a single CLX policy.
# ---------------------------------------------------------------------------

_BREAK_GLASS_EXCLUSION_ALLOWED_PATCH_KEY = "excludeUsers"


def _missing_break_glass_ids(policy: dict, break_glass_ids: list[str]) -> list[str]:
    users = (policy.get("conditions") or {}).get("users") or {}
    excluded = set(users.get("excludeUsers") or [])
    return [bg_id for bg_id in break_glass_ids if bg_id not in excluded]


def _build_exclude_users_patch(exclude_users: list[str]) -> dict:
    """Build a PATCH body that ONLY touches conditions.users.excludeUsers."""
    return {
        "conditions": {
            "users": {
                _BREAK_GLASS_EXCLUSION_ALLOWED_PATCH_KEY: list(dict.fromkeys(exclude_users)),
            }
        }
    }


def _merge_break_glass_rollback_exclusions(
    *,
    prior_exclude_users: list[str],
    live_exclude_users: list[str],
    added_exclusions: list[str],
) -> list[str]:
    added = set(added_exclusions)
    target: list[str] = []
    for user_id in list(prior_exclude_users) + [user_id for user_id in live_exclude_users if user_id not in added]:
        if isinstance(user_id, str) and user_id and user_id not in target:
            target.append(user_id)
    return target


async def _get_live_policy_by_id(graph_client, policy_id: str) -> dict | None:
    live_policies = await graph_client.list_conditional_access_policies()
    return next(
        (policy for policy in live_policies if isinstance(policy, dict) and policy.get("id") == policy_id),
        None,
    )


async def apply_break_glass_exclusion(
    *,
    db,
    tenant,
    last_applied_at: datetime | None = None,
) -> dict:
    """
    Patches every enabled, effective tenant CA policy missing any break-glass
    exclusion. Snapshots the prior excludeUsers per policy for rollback.
    """
    from app.services.remediation_executor import RemediationGraphClient

    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    # Read-only safety checks first: the licence probe below writes to the tenant.
    break_glass_ids = list_break_glass_user_ids(db=db, tenant_id=tenant.id)
    if not break_glass_ids:
        raise ControlEngineError("Break-glass accounts are required before applying CA_BREAK_GLASS_EXCLUSION")
    await _validate_break_glass_accounts(graph_client, break_glass_ids)
    if not await check_conditional_access_license(graph_client):
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=CONTROL_BREAK_GLASS_EXCLUSION,
            mode=ControlMode.ENFORCED,
            rollout_phase=ControlRolloutPhase.FULL,
            status=ControlExecutionStatus.BLOCKED,
            snapshot_id=None,
            error_message="NO_CA_LICENSE",
            verified=False,
        )
        return {
            "status": "blocked",
            "reason": "NO_CA_LICENSE",
            "verified": False,
            "control_id": CONTROL_BREAK_GLASS_EXCLUSION,
            "execution_id": str(execution.id),
        }

    all_policies = await graph_client.list_conditional_access_policies()
    diffs: list[dict] = []
    for policy in all_policies:
        if policy.get("state") != "enabled":
            continue
        conditions = policy.get("conditions")
        if not isinstance(conditions, dict) or "users" not in conditions:
            continue
        missing = _missing_break_glass_ids(policy, break_glass_ids)
        if not missing:
            continue
        users = (policy.get("conditions") or {}).get("users") or {}
        prior_exclude_users = list(users.get("excludeUsers") or [])
        diffs.append(
            {
                "policy_id": policy.get("id"),
                "policy_name": policy.get("displayName"),
                "prior_exclude_users": prior_exclude_users,
                "added_exclusions": [bg_id for bg_id in break_glass_ids if bg_id not in prior_exclude_users],
            }
        )

    snapshot = await create_snapshot(
        db,
        tenant_id=tenant.id,
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        policies=diffs,
    )

    state_record = await create_or_update_control_state(
        db,
        tenant_id=tenant.id,
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        mode=ControlMode.ENFORCED,
        rollout_phase=ControlRolloutPhase.FULL,
        status=ControlStateStatus.ACTIVE,
        last_applied_at=last_applied_at or datetime.utcnow(),
    )

    if not diffs:
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=CONTROL_BREAK_GLASS_EXCLUSION,
            mode=state_record.mode,
            rollout_phase=state_record.rollout_phase,
            status="success",
            snapshot_id=snapshot.id,
            policies_updated=[],
            verified=True,
        )
        return {
            "status": "ALREADY_CONFIGURED",
            "verified": True,
            "control_id": CONTROL_BREAK_GLASS_EXCLUSION,
            "snapshot_id": str(snapshot.id),
            "execution_id": str(execution.id),
            "policies_updated": [],
        }

    patched: list[dict] = []
    skipped: list[dict] = []
    try:
        for diff in diffs:
            policy_id = diff["policy_id"]
            try:
                # TOCTOU mitigation: re-fetch the live policy and merge against
                # its current excludeUsers, not the snapshot's prior value.
                live_policies = await graph_client.list_conditional_access_policies()
                live = next(
                    (p for p in live_policies if p.get("id") == policy_id),
                    None,
                )
                if live is None:
                    skipped.append({**diff, "reason": "policy_not_found"})
                    continue
                if live.get("state") != "enabled":
                    skipped.append({**diff, "reason": "policy_not_enabled"})
                    continue
                live_conditions = live.get("conditions")
                if not isinstance(live_conditions, dict) or "users" not in live_conditions:
                    skipped.append({**diff, "reason": "policy_missing_users_conditions"})
                    continue
                live_exclude = list(((live.get("conditions") or {}).get("users") or {}).get("excludeUsers") or [])
                merged = list(dict.fromkeys(live_exclude + break_glass_ids))
                patch_body = _build_exclude_users_patch(merged)
                await graph_client.update_conditional_access_policy(policy_id, patch_body)
                patched.append(
                    {
                        "policy_id": policy_id,
                        "policy_name": diff.get("policy_name"),
                        "added_exclusions": [bg_id for bg_id in break_glass_ids if bg_id not in live_exclude],
                    }
                )
            except GraphAPIError as exc:
                if getattr(exc, "status_code", None) == 404:
                    skipped.append({**diff, "reason": "policy_not_found"})
                    continue
                raise

        verified = await verify_ca_break_glass_exclusion(graph_client=graph_client)
    except GraphAPIError as exc:
        await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=CONTROL_BREAK_GLASS_EXCLUSION,
            status=ControlStateStatus.ERROR,
        )
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=CONTROL_BREAK_GLASS_EXCLUSION,
            mode=state_record.mode,
            rollout_phase=state_record.rollout_phase,
            status="partial",
            snapshot_id=snapshot.id,
            policies_updated=patched,
            error_message=str(exc),
        )
        return {
            "status": "partial",
            "reason": "partial_execution",
            "verified": False,
            "control_id": CONTROL_BREAK_GLASS_EXCLUSION,
            "snapshot_id": str(snapshot.id),
            "execution_id": str(execution.id),
            "policies_updated": patched,
            "policies_skipped": skipped,
            "error": str(exc),
        }

    status = "success" if verified else "partial"
    execution = _record_control_execution(
        db=db,
        tenant_id=tenant.id,
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        mode=state_record.mode,
        rollout_phase=state_record.rollout_phase,
        status=status,
        snapshot_id=snapshot.id,
        policies_updated=patched,
        verified=verified,
    )
    return {
        "status": status,
        "verified": verified,
        "control_id": CONTROL_BREAK_GLASS_EXCLUSION,
        "snapshot_id": str(snapshot.id),
        "execution_id": str(execution.id),
        "policies_updated": patched,
        "policies_skipped": skipped,
    }


async def rollback_break_glass_exclusion(
    *,
    db,
    tenant,
    execution_id: str | None = None,
    use_latest: bool = False,
) -> dict:
    """
    Restores the snapshotted prior excludeUsers per policy. The PATCH body is
    built from a single allow-listed key — no other policy field can be touched.
    """
    from app.services.remediation_executor import RemediationGraphClient

    graph_client = RemediationGraphClient(db=db, tenant=tenant)

    source_execution = None
    snapshot = None
    if use_latest:
        snapshot = await get_latest_snapshot(db, tenant.id, CONTROL_BREAK_GLASS_EXCLUSION)
        if snapshot is None:
            raise ControlEngineError(f"No control snapshot found for {CONTROL_BREAK_GLASS_EXCLUSION}")
    else:
        if not execution_id:
            raise ControlEngineError("execution_id is required for rollback")
        try:
            parsed_execution_id = uuid.UUID(str(execution_id))
        except (TypeError, ValueError) as exc:
            raise ControlEngineError("execution_id must be a valid UUID") from exc
        result = await _maybe_await(
            db.execute(
                select(ControlExecution).where(
                    ControlExecution.id == parsed_execution_id,
                    ControlExecution.tenant_id == tenant.id,
                )
            )
        )
        source_execution = result.scalars().first()
        if source_execution is None:
            raise ControlEngineError("Control execution not found")
        if source_execution.status != ControlExecutionStatus.SUCCESS:
            raise ControlEngineError("Cannot rollback failed/partial execution")
        if source_execution.snapshot_id is None:
            raise ControlEngineError("Execution has no snapshot_id, cannot rollback safely")
        if source_execution.control_id != CONTROL_BREAK_GLASS_EXCLUSION:
            raise ControlEngineError("execution_id does not belong to CA_BREAK_GLASS_EXCLUSION")
        snapshot = await get_snapshot_by_id(db, tenant.id, source_execution.snapshot_id)
        if snapshot is None:
            raise ControlEngineError("Execution snapshot not found, cannot rollback safely")

    diffs = list(snapshot.policies or [])
    restored: list[dict] = []
    skipped: list[dict] = []
    expected_exclusions_by_policy: dict[str, list[str]] = {}
    for diff in diffs:
        if not isinstance(diff, dict):
            continue
        policy_id = diff.get("policy_id")
        prior = diff.get("prior_exclude_users") or []
        added_exclusions = diff.get("added_exclusions") or []
        if not isinstance(policy_id, str) or not policy_id:
            continue
        try:
            live = await _get_live_policy_by_id(graph_client, policy_id)
            if live is None:
                skipped.append({"policy_id": policy_id, "reason": "policy_not_found"})
                continue
            live_exclude = list(((live.get("conditions") or {}).get("users") or {}).get("excludeUsers") or [])
            target_exclusions = _merge_break_glass_rollback_exclusions(
                prior_exclude_users=list(prior),
                live_exclude_users=live_exclude,
                added_exclusions=list(added_exclusions),
            )
            expected_exclusions_by_policy[policy_id] = target_exclusions
            # Safety: build PATCH body from a single allow-listed key. No other
            # policy field can be reached even if the snapshot was tampered with.
            patch_body = _build_exclude_users_patch(target_exclusions)
            await graph_client.update_conditional_access_policy(policy_id, patch_body)
            restored.append(
                {
                    "policy_id": policy_id,
                    "prior_exclude_users": prior,
                    "restored_exclude_users": target_exclusions,
                }
            )
        except GraphAPIError as exc:
            if getattr(exc, "status_code", None) == 404:
                skipped.append({"policy_id": policy_id, "reason": "policy_not_found"})
                continue
            raise ControlEngineError(f"Rollback failed for policy {policy_id}: {exc}") from exc

    verification_errors: list[dict] = []
    for policy_id, expected_exclusions in expected_exclusions_by_policy.items():
        live = await _get_live_policy_by_id(graph_client, policy_id)
        live_exclude = list(((live or {}).get("conditions") or {}).get("users", {}).get("excludeUsers") or [])
        if set(live_exclude) != set(expected_exclusions):
            verification_errors.append(
                {
                    "policy_id": policy_id,
                    "expected_exclude_users": expected_exclusions,
                    "actual_exclude_users": live_exclude,
                }
            )

    if skipped or verification_errors:
        state = await create_or_update_control_state(
            db,
            tenant_id=tenant.id,
            control_id=CONTROL_BREAK_GLASS_EXCLUSION,
            status=ControlStateStatus.ERROR,
        )
        execution = _record_control_execution(
            db=db,
            tenant_id=tenant.id,
            control_id=CONTROL_BREAK_GLASS_EXCLUSION,
            mode=state.mode,
            rollout_phase=state.rollout_phase,
            status=ControlExecutionStatus.PARTIAL,
            snapshot_id=snapshot.id,
            policies_updated=restored,
            error_message="BREAK_GLASS_ROLLBACK_VERIFICATION_FAILED",
            verified=False,
        )
        raise ControlEngineError("Break-glass rollback verification failed; " f"execution_id={execution.id}")

    state = await create_or_update_control_state(
        db,
        tenant_id=tenant.id,
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        status=ControlStateStatus.ACTIVE,
        last_applied_at=datetime.utcnow(),
    )
    execution = _record_control_execution(
        db=db,
        tenant_id=tenant.id,
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        mode=state.mode,
        rollout_phase=state.rollout_phase,
        status=ControlExecutionStatus.SUCCESS,
        snapshot_id=snapshot.id,
        policies_updated=restored,
        verified=True,
    )
    return {
        "status": "success",
        "verified": True,
        "control_id": CONTROL_BREAK_GLASS_EXCLUSION,
        "snapshot_id": str(snapshot.id),
        "execution_id": str(execution.id),
        "rolled_back_execution_id": (str(source_execution.id) if source_execution is not None else None),
        "restored_policies": restored,
        "skipped_policies": skipped,
    }


# ---------------------------------------------------------------------------
# Top-level dispatchers — route between standard CLX path and break-glass path.
# ---------------------------------------------------------------------------


async def apply_control_dispatch(
    *,
    db,
    tenant,
    control_id: str,
    mode: str | None = None,
    rollout_phase: str | None = None,
    rollout_percentage: int | None = None,
    policy_version: int | None = None,
    last_applied_at: datetime | None = None,
) -> dict:
    normalized_control_id = normalize_control_id(control_id)
    if normalized_control_id != CONTROL_BREAK_GLASS_EXCLUSION:
        from app.services.control_enforcement_service import evaluate_action
        from app.services.graph_client import GraphBlockedError
        from app.services.remediation.lifecycle import BlockReason

        decision = await evaluate_action(tenant, normalized_control_id, "execute", db=db)
        if not decision.get("allowed"):
            raise GraphBlockedError(
                status="blocked",
                reason=BlockReason.POLICY_RESTRICTION.value,
                message=str(
                    decision.get("notes") or decision.get("reason") or "Control not supported for this provider"
                ),
                tenant_id=getattr(tenant, "id", None),
            )
    if normalized_control_id == CONTROL_BREAK_GLASS_EXCLUSION:
        return await apply_break_glass_exclusion(
            db=db,
            tenant=tenant,
            last_applied_at=last_applied_at,
        )
    return await apply_control(
        db=db,
        tenant=tenant,
        control_id=normalized_control_id,
        mode=mode,
        rollout_phase=rollout_phase,
        rollout_percentage=rollout_percentage,
        # target_group_id intentionally omitted — group identity derived from DB via create_rollout_group
        policy_version=policy_version,
        last_applied_at=last_applied_at,
    )


async def rollback_control_dispatch(
    *,
    db,
    tenant,
    execution_id: str | None = None,
    control_id: str | None = None,
    use_latest: bool = False,
) -> dict:
    if control_id is not None:
        normalized = normalize_control_id(control_id)
        if normalized == CONTROL_BREAK_GLASS_EXCLUSION:
            return await rollback_break_glass_exclusion(
                db=db,
                tenant=tenant,
                execution_id=execution_id,
                use_latest=use_latest,
            )
    if execution_id is not None and not use_latest:
        try:
            parsed_execution_id = uuid.UUID(str(execution_id))
        except (TypeError, ValueError) as exc:
            raise ControlEngineError("execution_id must be a valid UUID") from exc
        result = await _maybe_await(
            db.execute(
                select(ControlExecution).where(
                    ControlExecution.id == parsed_execution_id,
                    ControlExecution.tenant_id == tenant.id,
                )
            )
        )
        execution_row = result.scalars().first()
        if execution_row is not None and execution_row.control_id == CONTROL_BREAK_GLASS_EXCLUSION:
            return await rollback_break_glass_exclusion(
                db=db,
                tenant=tenant,
                execution_id=execution_id,
                use_latest=False,
            )
    return await rollback_control(
        db=db,
        tenant=tenant,
        execution_id=execution_id,
        control_id=control_id,
        use_latest=use_latest,
    )


# ---------------------------------------------------------------------------
# Locked public mutation entrypoints. The heavy implementations above stay
# intact; these wrappers place the tenant-wide advisory lock inside the CA
# engine so API and remediation callers share the same guard.
_update_rollout_unlocked = update_rollout
_apply_control_unlocked = apply_control
_rollback_control_unlocked = rollback_control
_apply_break_glass_exclusion_unlocked = apply_break_glass_exclusion
_rollback_break_glass_exclusion_unlocked = rollback_break_glass_exclusion


async def update_rollout(*, db, tenant, control_id: str, percentage: int) -> dict:
    async with _tenant_ca_mutation_lock(db, tenant.id):
        return await _update_rollout_unlocked(
            db=db,
            tenant=tenant,
            control_id=control_id,
            percentage=percentage,
        )


async def apply_control(
    *,
    db,
    tenant,
    control_id: str,
    mode: str | None = None,
    rollout_phase: str | None = None,
    rollout_percentage: int | None = None,
    policy_version: int | None = None,
    last_applied_at: datetime | None = None,
) -> dict:
    async with _tenant_ca_mutation_lock(db, tenant.id):
        return await _apply_control_unlocked(
            db=db,
            tenant=tenant,
            control_id=control_id,
            mode=mode,
            rollout_phase=rollout_phase,
            rollout_percentage=rollout_percentage,
            # target_group_id intentionally omitted — group identity derived from DB via create_rollout_group
            policy_version=policy_version,
            last_applied_at=last_applied_at,
        )


async def rollback_control(
    *,
    db,
    tenant,
    execution_id: str | None = None,
    control_id: str | None = None,
    use_latest: bool = False,
) -> dict:
    async with _tenant_ca_mutation_lock(db, tenant.id):
        return await _rollback_control_unlocked(
            db=db,
            tenant=tenant,
            execution_id=execution_id,
            control_id=control_id,
            use_latest=use_latest,
        )


async def apply_break_glass_exclusion(
    *,
    db,
    tenant,
    last_applied_at: datetime | None = None,
) -> dict:
    async with _tenant_ca_mutation_lock(db, tenant.id):
        return await _apply_break_glass_exclusion_unlocked(
            db=db,
            tenant=tenant,
            last_applied_at=last_applied_at,
        )


async def rollback_break_glass_exclusion(
    *,
    db,
    tenant,
    execution_id: str | None = None,
    use_latest: bool = False,
) -> dict:
    async with _tenant_ca_mutation_lock(db, tenant.id):
        return await _rollback_break_glass_exclusion_unlocked(
            db=db,
            tenant=tenant,
            execution_id=execution_id,
            use_latest=use_latest,
        )


# Verifiers — thin wrappers around detection functions with retry/backoff.
# Source of truth lives in the detector; verifiers just rerun it post-apply.
# ---------------------------------------------------------------------------

_VERIFIER_DELAYS = [2, 5, 10]


async def _retry_verifier(check_fn, *, attempts: int = 3) -> bool:
    last_value = False
    for attempt in range(attempts):
        last_value = bool(await check_fn())
        if last_value:
            return True
        if attempt < attempts - 1:
            await asyncio.sleep(_VERIFIER_DELAYS[min(attempt, len(_VERIFIER_DELAYS) - 1)])
    return last_value


async def _build_tenant_graph_context(graph_client):
    from app.services.graph.tenant_graph_context import TenantGraphContext

    policies = await graph_client.list_conditional_access_policies()
    break_glass_accounts = list(list_break_glass_user_ids(db=graph_client.db, tenant_id=graph_client.tenant.id))
    return TenantGraphContext(
        tenant_id=graph_client.tenant.id,
        fetched_at=datetime.utcnow(),
        conditional_access_policies=policies,
        break_glass_accounts=break_glass_accounts,
    )


def _verifier_passed(findings) -> bool:
    if not findings:
        return False
    first = findings[0]
    return bool(isinstance(first, dict) and first.get("passed"))


async def verify_ca_mfa_all_users(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_mfa_checks import (
        detect_ca_mfa_all_users,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_mfa_all_users(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_mfa_admins(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_mfa_checks import (
        detect_ca_mfa_admins,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_mfa_admins(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_legacy_auth_block(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_auth_vector_checks import (
        detect_ca_legacy_auth_other_blocked,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_legacy_auth_other_blocked(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_device_code_flow_block(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_auth_vector_checks import (
        detect_ca_device_code_flow_blocked,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_device_code_flow_blocked(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_authentication_transfer_block(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_auth_vector_checks import (
        detect_ca_authentication_transfer_blocked,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_authentication_transfer_blocked(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_guest_mfa(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_guest_mfa import (
        detect_ca_guest_mfa,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_guest_mfa(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_break_glass_exclusion(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_policy_checks import (
        detect_ca_break_glass_excluded,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_break_glass_excluded(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_high_risk_sign_in_block(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_risk_checks import (
        detect_ca_high_risk_sign_in_block,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_high_risk_sign_in_block(ctx=ctx))

    return await _retry_verifier(_check)


async def verify_ca_risk_based_step_up_mfa(*, graph_client) -> bool:
    from app.services.detection.conditional_access.ca_risk_checks import (
        detect_ca_risk_based_step_up_mfa,
    )

    async def _check() -> bool:
        ctx = await _build_tenant_graph_context(graph_client)
        return _verifier_passed(await detect_ca_risk_based_step_up_mfa(ctx=ctx))

    return await _retry_verifier(_check)
