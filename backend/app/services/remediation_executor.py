from app.services.ca_policy_states import CA_STATE_REPORT_ONLY
from app.utils.datetime import to_naive_utc, utc_now
import inspect
import logging

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.ca_policy_engine import (
    CONTROL_MFA_ADMINS,
    _default_rollout_phase,
    apply_control,
    normalize_control_id,
)
from app.services.control_state_service import get_control_state
from app.services.control_enforcement_service import evaluate_action
from app.services.graph_client import (
    GraphAPIError,
    GraphBlockedError,
    classify_graph_api_error,
    describe_graph_api_error,
)
from app.services.identity_providers import get_identity_provider_adapter
from app.services.policy_hashing import compute_policy_hash
from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.remediation_audit_service import log_audit_event
from app.services.remediation.mfa_policy import compute_desired_policy_hash, normalize_policy
from app.services.remediation.lifecycle import (
    BlockReason,
    current_remediation_status,
    normalize_block_reason,
)


class RemediationExecutionError(Exception):
    pass


logger = logging.getLogger(__name__)

_CA_MFA_CONTROLS = {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"}


class RemediationGraphClient:
    def __init__(self, *, db: Session, tenant):
        self.db = db
        self.tenant = tenant
        self._adapter = get_identity_provider_adapter(db=db, tenant=tenant)

    @property
    def adapter(self):
        return self._adapter

    def __getattr__(self, name: str):
        return getattr(self._adapter, name)


def _ensure_executor_purity(executor, control_id: str):
    module = inspect.getmodule(executor.__class__)
    if module is None:
        return

    module_source = inspect.getsource(module)
    execute_source = inspect.getsource(executor.execute)
    if "import requests" in module_source or "requests." in module_source:
        raise RemediationExecutionError(
            f"Executor for control '{control_id}' uses raw requests instead of graph_client"
        )
    if any(token in execute_source for token in ["httpx.", "requests.", "tenant.get_graph_client("]):
        raise RemediationExecutionError(f"Executor for control '{control_id}' bypasses graph_client")
    _FORBIDDEN_GRAPH_HELPERS = {
        "graph_get",
        "graph_post",
        "graph_patch",
        "graph_delete",
        "graph_get_app",
        "MicrosoftGraphClient",
        "validate_tenant_graph_permissions",
    }
    if any(token in execute_source for token in _FORBIDDEN_GRAPH_HELPERS):
        raise RemediationExecutionError(
            f"Executor for control '{control_id}' calls graph_client helpers directly instead of using the adapter"
        )


def _build_snapshot_state(control_id: str, execution_result: dict):
    snapshot_state = execution_result.get("snapshot") or {}
    desired_state = execution_result.get("desired_state")
    current_state = execution_result.get("current_state")
    if desired_state is not None:
        snapshot_state = {
            **snapshot_state,
            "desired_state": desired_state,
            "desired_hash": compute_desired_policy_hash(desired_state)
            if isinstance(desired_state, dict)
            else compute_policy_hash(desired_state),
        }
    if current_state is not None:
        snapshot_state = {
            **snapshot_state,
            "current_state": current_state,
            "current_hash": compute_policy_hash(current_state),
        }
    if control_id in {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"} and desired_state:
        snapshot_state["normalized_desired_state"] = normalize_policy(desired_state)
    if control_id == "IDENTITY_ILLICIT_CONSENT_GRANTS":
        execution_outcome = execution_result.get("result")
        if isinstance(execution_outcome, dict):
            snapshot_state = {
                **snapshot_state,
                "result": execution_outcome,
            }
    return snapshot_state


def _validate_snapshot_state(control_id: str, control_config: dict, snapshot_state: dict) -> None:
    required_keys = control_config.get("snapshot_required_keys") or []
    if not required_keys:
        return
    if not isinstance(snapshot_state, dict) or not snapshot_state:
        raise RemediationExecutionError(f"Snapshot missing for control '{control_id}'")
    missing_keys = [key for key in required_keys if snapshot_state.get(key) in (None, [], {})]
    if missing_keys:
        raise RemediationExecutionError(
            f"Snapshot missing required keys for control '{control_id}': {', '.join(missing_keys)}"
        )


def _resource_metadata(evidence: dict) -> tuple[str, str | None]:
    resource_type = evidence.get("resource_type")
    resource_id = evidence.get("resource_id")
    user_id = evidence.get("user_id")
    if resource_type == "TENANT":
        return "TENANT", resource_id
    if resource_type == "SERVICE_PRINCIPAL" and resource_id:
        return "SERVICE_PRINCIPAL", resource_id
    if user_id:
        return "USER", user_id
    if resource_id:
        return "TENANT", resource_id
    return "TENANT", None


def _control_registry_metadata(control_id: str) -> dict:
    control_meta = CONTROL_REGISTRY.get(control_id)
    found = control_meta is not None
    logger.info(
        "CONTROL_REGISTRY_LOOKUP %s",
        {
            "control_id": control_id,
            "found": found,
        },
    )
    if not found:
        logger.warning(
            "Missing control registry entry for snapshot validation control_id=%s",
            control_id,
        )
        return {}
    return control_meta


def _persist_pre_execution_snapshot(
    *,
    db: Session,
    result: ComplianceResult,
    control_id: str,
    snapshot_state: dict,
):
    control_meta = _control_registry_metadata(control_id)
    _validate_snapshot_state(control_id, control_meta, snapshot_state)

    existing_snapshot = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == result.id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    # Reuse this snapshot only if it belongs to an in-flight execution (state_after
    # not yet written).  A completed snapshot (state_after IS NOT NULL) belongs to a
    # prior execution cycle; re-using it would attempt a second state_after write,
    # which the immutability guard correctly rejects.  In that case fall through and
    # create a fresh snapshot for this execution.
    if existing_snapshot is not None and existing_snapshot.state_after is None:
        return existing_snapshot, existing_snapshot.state or snapshot_state

    policy_hash = None
    if isinstance(snapshot_state, dict) and snapshot_state:
        policy_hash = compute_policy_hash(snapshot_state)

    snapshot = RemediationSnapshot(
        compliance_result_id=result.id,
        state=snapshot_state,
        created_at=to_naive_utc(utc_now()),
        policy_snapshot=snapshot_state if snapshot_state else None,
        policy_version=(result.remediation_count_7d or 0) + 1,
        policy_hash=policy_hash,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot, snapshot_state


def _should_attempt_rollback(*, control_id: str, snapshot_state: dict) -> bool:
    if control_id == "IDENTITY_BREAK_GLASS_ACCOUNT":
        logger.info(
            "ROLLBACK_SKIPPED %s",
            {
                "control_id": control_id,
                "reason": "break_glass_rollback_disabled",
            },
        )
        return False
    return isinstance(snapshot_state, dict) and bool(snapshot_state)


def _build_partial_success_response(
    *,
    execution_result: dict | None,
    persisted_snapshot: RemediationSnapshot | None,
    warning_message: str,
) -> dict:
    response = dict(execution_result or {})
    response["operation_status"] = response.get("operation_status") or response.get("status")
    response["status"] = "success"
    response["verified"] = bool(response.get("verified", True))
    response["snapshot_id"] = getattr(persisted_snapshot, "id", None)
    response["warning_flag"] = True
    warnings = response.get("warnings")
    if not isinstance(warnings, list):
        warnings = []
    warnings.append(
        {
            "stage": "post_processing",
            "message": warning_message,
        }
    )
    response["warnings"] = warnings
    return response


def _redact_sensitive_execution_result(value):
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if key.lower() == "password" else _redact_sensitive_execution_result(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_sensitive_execution_result(item) for item in value]
    return value


async def execute_remediation(
    *,
    db: Session,
    tenant,
    compliance_result_id: int,
    control_id: str,
    executor,
    evidence: dict,
    action_type: str = "execute",
):
    result = db.get(ComplianceResult, compliance_result_id)
    if not result:
        raise RemediationExecutionError("Compliance result not found")

    remediation_status = current_remediation_status(result)
    if remediation_status != "EXECUTING":
        raise RemediationExecutionError(f"Invalid state for execution: {remediation_status}")

    if not hasattr(executor, "execute"):
        raise RemediationExecutionError(f"Executor for control '{control_id}' is missing an async execute method")
    if not hasattr(executor, "rollback"):
        raise RemediationExecutionError(f"Executor for control '{control_id}' is missing an async rollback method")

    _ensure_executor_purity(executor, control_id)

    if control_id == "IDENTITY_OVERPRIVILEGED_USER":
        selected_roles = evidence.get("selected_roles")
        if not isinstance(selected_roles, list) or not selected_roles:
            logger.warning(
                "EXECUTION_SKIPPED %s",
                {
                    "compliance_result_id": compliance_result_id,
                    "control_id": control_id,
                    "reason": "missing_roles",
                },
            )
            raise RemediationExecutionError("No roles selected for removal")

    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    execution_result = None
    snapshot_state = {}
    persisted_snapshot = None

    try:
        enforcement_decision = await evaluate_action(
            tenant,
            control_id,
            action_type,
            db=db,
        )
        if not enforcement_decision.get("allowed"):
            raise GraphBlockedError(
                status="blocked",
                reason=BlockReason.POLICY_RESTRICTION.value,
                message=str(
                    enforcement_decision.get("notes")
                    or enforcement_decision.get("reason")
                    or "Remediation blocked by provider capability policy"
                ),
                tenant_id=getattr(tenant, "id", None),
            )
        if enforcement_decision.get("mode") == "manual":
            logger.info(
                "CONTROL_ENFORCEMENT_MANUAL %s",
                {
                    "tenant_id": getattr(tenant, "id", None),
                    "compliance_result_id": compliance_result_id,
                    "control_id": control_id,
                    "action_type": action_type,
                    "reason": enforcement_decision.get("reason"),
                },
            )
        if control_id in _CA_MFA_CONTROLS:
            ca_control_id = normalize_control_id(control_id)
            state = await get_control_state(db, tenant.id, ca_control_id)
            effective_mode = getattr(state, "mode", None) or "audit"
            effective_rollout_phase = getattr(state, "rollout_phase", None)
            effective_rollout_percentage = getattr(state, "rollout_percentage", None)
            effective_policy_version = getattr(state, "policy_version", None)
            snapshot_state = {
                "policy_name": ("CLX-MFA-ADMINS" if ca_control_id == CONTROL_MFA_ADMINS else "CLX-MFA-ALL-USERS"),
                "ca_control_id": ca_control_id,
                "mode": effective_mode,
                "rollout_phase": effective_rollout_phase,
            }
        elif hasattr(executor, "build_snapshot"):
            snapshot_state = await executor.build_snapshot(graph_client, evidence)
        persisted_snapshot, snapshot_state = _persist_pre_execution_snapshot(
            db=db,
            result=result,
            control_id=control_id,
            snapshot_state=snapshot_state,
        )
        logger.info(
            "EXECUTION_STARTED %s",
            {
                "compliance_result_id": compliance_result_id,
                "control_id": control_id,
                "selected_roles": evidence.get("selected_roles", []),
                "snapshot_id": getattr(persisted_snapshot, "id", None),
            },
        )
        logger.info(f"[REMEDIATION] Executing {control_id} for tenant {tenant.id}")
        logger.info("executing_control control_id=%s", control_id)
        if control_id in _CA_MFA_CONTROLS:
            execution_result = await apply_control(
                db=db,
                tenant=tenant,
                control_id=control_id,
                mode=effective_mode,
                rollout_phase=effective_rollout_phase,
                rollout_percentage=effective_rollout_percentage,
                policy_version=effective_policy_version,
                last_applied_at=to_naive_utc(utc_now()),
            )
            execution_result = {
                **execution_result,
                "control_id": control_id,
                "snapshot": {
                    **snapshot_state,
                    "control_snapshot_id": execution_result.get("snapshot_id"),
                    "ca_control_id": ca_control_id,
                },
                "desired_state": {
                    "displayName": execution_result.get("policy_result", {}).get(
                        "policy_name",
                        "CLX-MFA-ADMINS" if ca_control_id == CONTROL_MFA_ADMINS else "CLX-MFA-ALL-USERS",
                    ),
                    "state": "enabled" if effective_mode == "enforced" else CA_STATE_REPORT_ONLY,
                    "rollout_phase": effective_rollout_phase or _default_rollout_phase(ca_control_id),
                },
            }
        else:
            execution_result = await executor.execute(
                graph_client,
                {
                    **evidence,
                    "snapshot": snapshot_state,
                },
            )
        execution_result = execution_result or {}
        if execution_result.get("status") == "blocked":
            execution_result["snapshot_id"] = getattr(persisted_snapshot, "id", None)
            return execution_result
        if execution_result.get("status") in {"failed", "partial"}:
            execution_result["snapshot_id"] = getattr(persisted_snapshot, "id", None)
            return execution_result
    except ValidationError as exc:
        raise RemediationExecutionError(f"Payload validation failed: {exc}") from exc
    except GraphBlockedError as exc:
        db.rollback()
        result.execution_finished_at = to_naive_utc(utc_now())
        db.commit()

        resource_type, resource_id = _resource_metadata(evidence)
        log_audit_event(
            db=db,
            tenant_id=result.tenant_id,
            compliance_result_id=result.id,
            control_id=result.control_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type="BLOCKED",
            confidence=1.0,
            metadata={
                "snapshot_id": getattr(persisted_snapshot, "id", None),
                "failure_type": exc.reason,
                "block_reason": normalize_block_reason(exc.reason),
                "message": exc.message,
            },
        )
        return {
            "status": exc.status,
            "reason": exc.reason,
            "block_reason": normalize_block_reason(exc.reason),
            "message": exc.message,
            "snapshot_id": getattr(persisted_snapshot, "id", None),
        }
    except GraphAPIError as exc:
        db.rollback()

        if _should_attempt_rollback(control_id=control_id, snapshot_state=snapshot_state):
            try:
                await executor.rollback(graph_client, snapshot_state)
            except Exception as rollback_exc:
                logger.error(
                    "ROLLBACK_FAILED %s",
                    {
                        "compliance_result_id": compliance_result_id,
                        "control_id": control_id,
                        "snapshot_id": getattr(persisted_snapshot, "id", None),
                        "error": str(rollback_exc),
                    },
                )
                log_audit_event(
                    db=db,
                    tenant_id=result.tenant_id,
                    compliance_result_id=result.id,
                    control_id=result.control_id,
                    resource_type=_resource_metadata(evidence)[0],
                    resource_id=_resource_metadata(evidence)[1],
                    event_type="ROLLBACK_FAILED",
                    confidence=0.0,
                    metadata={
                        "snapshot_id": getattr(persisted_snapshot, "id", None),
                        "error": str(rollback_exc),
                    },
                )

        result.execution_finished_at = to_naive_utc(utc_now())
        db.commit()

        failure_type = classify_graph_api_error(exc)
        resource_type, resource_id = _resource_metadata(evidence)
        log_audit_event(
            db=db,
            tenant_id=result.tenant_id,
            compliance_result_id=result.id,
            control_id=result.control_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type="FAILED",
            confidence=0.0,
            metadata={
                "snapshot_id": getattr(persisted_snapshot, "id", None),
                "error": describe_graph_api_error(exc),
                "failure_type": failure_type,
                "graph_status_code": exc.status_code,
            },
        )
        raise
    except Exception as exc:
        db.rollback()

        if _should_attempt_rollback(control_id=control_id, snapshot_state=snapshot_state):
            try:
                await executor.rollback(graph_client, snapshot_state)
            except Exception as rollback_exc:
                logger.error(
                    "ROLLBACK_FAILED %s",
                    {
                        "compliance_result_id": compliance_result_id,
                        "control_id": control_id,
                        "snapshot_id": getattr(persisted_snapshot, "id", None),
                        "error": str(rollback_exc),
                    },
                )
                log_audit_event(
                    db=db,
                    tenant_id=result.tenant_id,
                    compliance_result_id=result.id,
                    control_id=result.control_id,
                    resource_type=_resource_metadata(evidence)[0],
                    resource_id=_resource_metadata(evidence)[1],
                    event_type="ROLLBACK_FAILED",
                    confidence=0.0,
                    metadata={
                        "snapshot_id": getattr(persisted_snapshot, "id", None),
                        "error": str(rollback_exc),
                    },
                )

        result.execution_finished_at = to_naive_utc(utc_now())
        db.commit()

        resource_type, resource_id = _resource_metadata(evidence)
        log_audit_event(
            db=db,
            tenant_id=result.tenant_id,
            compliance_result_id=result.id,
            control_id=result.control_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type="FAILED",
            confidence=0.0,
            metadata={
                "snapshot_id": getattr(persisted_snapshot, "id", None),
                "error": str(exc),
            },
        )

        raise RemediationExecutionError(str(exc)) from exc

    try:
        # Persist the post-execution state atomically with execution completion
        # so rollback has a durable record of what the executor actually achieved.
        # The snapshot row is otherwise immutable; state_after is the single
        # permitted NULL->value transition (enforced by the model event listener).
        post_execution_state = _build_snapshot_state(control_id, execution_result)
        if persisted_snapshot is not None and post_execution_state:
            persisted_snapshot.state_after = post_execution_state
            db.add(persisted_snapshot)
        result.execution_finished_at = to_naive_utc(utc_now())
        db.commit()

        resource_type, resource_id = _resource_metadata(evidence)
        log_audit_event(
            db=db,
            tenant_id=result.tenant_id,
            compliance_result_id=result.id,
            control_id=result.control_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type="EXECUTED",
            confidence=1.0,
            metadata={
                "executor": control_id,
                "snapshot_id": getattr(persisted_snapshot, "id", None),
            },
        )
    except Exception as exc:
        warning_message = str(exc)
        logger.warning(
            "POST_PROCESSING_FAILED %s",
            {
                "compliance_result_id": compliance_result_id,
                "control_id": control_id,
                "snapshot_id": getattr(persisted_snapshot, "id", None),
                "error": warning_message,
            },
        )
        db.rollback()
        result.execution_finished_at = to_naive_utc(utc_now())
        db.commit()

        return _build_partial_success_response(
            execution_result=execution_result,
            persisted_snapshot=persisted_snapshot,
            warning_message=warning_message,
        )

    execution_result["snapshot_id"] = getattr(persisted_snapshot, "id", None)
    execution_result["operation_status"] = execution_result.get("operation_status") or execution_result.get("status")
    execution_result["status"] = "success"
    execution_result["verified"] = bool(execution_result.get("verified", True))
    logger.info("execution_success control_id=%s", execution_result.get("control_id"))
    return execution_result
