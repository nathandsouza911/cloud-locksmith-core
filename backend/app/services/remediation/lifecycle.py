from enum import Enum
import logging

from app.db.models.compliance_result import (
    ExposureStatus,
    RemediationStatus,
    ResolutionSource,
)

logger = logging.getLogger(__name__)


class RemediationLifecycleState(str, Enum):
    PENDING = RemediationStatus.PENDING.value
    APPROVED = RemediationStatus.APPROVED.value
    EXECUTING = RemediationStatus.EXECUTING.value
    SUCCESS = RemediationStatus.SUCCESS.value
    FAILED = RemediationStatus.FAILED.value
    BLOCKED = RemediationStatus.BLOCKED.value
    IGNORED = RemediationStatus.IGNORED.value


class TransitionEvent(str, Enum):
    SCAN_DETECTED = "SCAN_DETECTED"
    SCAN_RESOLVED = "SCAN_RESOLVED"
    EXECUTE = "EXECUTE"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PERMISSION_BLOCK = "PERMISSION_BLOCK"
    IGNORE = "IGNORE"
    UNIGNORE = "UNIGNORE"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    APPROVE = "APPROVE"


class BlockReason(str, Enum):
    PRIVILEGED_USER = "PRIVILEGED_USER"
    POLICY_RESTRICTION = "POLICY_RESTRICTION"
    BREAK_GLASS_PROTECTION = "BREAK_GLASS_PROTECTION"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    PREFLIGHT_FAILED = "PREFLIGHT_FAILED"
    UNKNOWN = "UNKNOWN"


class InvalidStateTransitionError(ValueError):
    pass


ALLOWED_RESOLUTION_SOURCES = {
    ResolutionSource.SYSTEM.value,
    ResolutionSource.EXTERNAL.value,
    ResolutionSource.BASELINE_UPDATE.value,
    ResolutionSource.OFFBOARDING.value,
}


PERMANENT_BLOCK_REASONS = {
    BlockReason.PRIVILEGED_USER.value,
    BlockReason.POLICY_RESTRICTION.value,
    BlockReason.BREAK_GLASS_PROTECTION.value,
}

LEGACY_TO_REMEDIATION_STATUS = {
    "OPEN": RemediationStatus.PENDING.value,
    "PENDING": RemediationStatus.PENDING.value,
    "PENDING_APPROVAL": RemediationStatus.PENDING.value,
    "MANUAL_ACTION_REQUIRED": RemediationStatus.PENDING.value,
    "REVIEW_REQUIRED": RemediationStatus.PENDING.value,
    # UNKNOWN means the enforcement state could not be determined (e.g. Graph
    # fetch failed).  Treat as PENDING for lifecycle purposes so state-machine
    # transitions remain valid.  The raw "UNKNOWN" string is preserved in the
    # decision_status String column so the UI can display it correctly.
    "UNKNOWN": RemediationStatus.PENDING.value,
    "APPROVED": RemediationStatus.APPROVED.value,
    "EXECUTING": RemediationStatus.EXECUTING.value,
    "EXECUTED": RemediationStatus.SUCCESS.value,
    "VERIFIED": RemediationStatus.SUCCESS.value,
    "AUTO_REMEDIATED": RemediationStatus.SUCCESS.value,
    "SUCCESS": RemediationStatus.SUCCESS.value,
    "FAILED": RemediationStatus.FAILED.value,
    "BLOCKED": RemediationStatus.BLOCKED.value,
    "IGNORED": RemediationStatus.IGNORED.value,
    "ROLLED_BACK": RemediationStatus.PENDING.value,
    "RESOLVED": RemediationStatus.PENDING.value,
}

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    RemediationStatus.PENDING.value: {
        RemediationStatus.APPROVED.value,
        RemediationStatus.IGNORED.value,
        RemediationStatus.BLOCKED.value,
    },
    RemediationStatus.APPROVED.value: {
        RemediationStatus.EXECUTING.value,
        RemediationStatus.IGNORED.value,
        RemediationStatus.BLOCKED.value,
        RemediationStatus.PENDING.value,
    },
    RemediationStatus.EXECUTING.value: {
        RemediationStatus.SUCCESS.value,
        RemediationStatus.FAILED.value,
        RemediationStatus.BLOCKED.value,
    },
    RemediationStatus.SUCCESS.value: {
        RemediationStatus.PENDING.value,
    },
    RemediationStatus.FAILED.value: {
        RemediationStatus.APPROVED.value,
        RemediationStatus.IGNORED.value,
        RemediationStatus.PENDING.value,
    },
    RemediationStatus.BLOCKED.value: {
        RemediationStatus.PENDING.value,
        RemediationStatus.IGNORED.value,
    },
    RemediationStatus.IGNORED.value: {
        RemediationStatus.PENDING.value,
    },
}


def normalize_block_reason(reason: str | None) -> str:
    if not reason:
        return BlockReason.UNKNOWN.value

    normalized = str(reason).strip().upper()
    if normalized in {item.value for item in BlockReason}:
        return normalized
    return BlockReason.UNKNOWN.value


def should_enter_blocked_state(reason: str | None) -> bool:
    return normalize_block_reason(reason) in PERMANENT_BLOCK_REASONS


def normalize_remediation_status(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = str(value).strip().upper()
    if not normalized:
        return None
    if normalized in {item.value for item in RemediationStatus}:
        return normalized
    return LEGACY_TO_REMEDIATION_STATUS.get(normalized)


def sync_legacy_decision_status(result) -> None:
    remediation_status = normalize_remediation_status(getattr(result, "remediation_status", None))
    if remediation_status:
        result.remediation_status = remediation_status
        result.decision_status = remediation_status


def normalize_resolution_source(value) -> str:
    if isinstance(value, ResolutionSource):
        candidate = value.value
    elif value is None:
        candidate = None
    else:
        candidate = str(value).strip().upper()

    if candidate in ALLOWED_RESOLUTION_SOURCES:
        return candidate
    return ResolutionSource.SYSTEM.value


def current_exposure_status(result) -> str:
    exposure_status = getattr(result, "exposure_status", None)
    if hasattr(exposure_status, "value"):
        return exposure_status.value
    if exposure_status:
        return str(exposure_status)
    return ExposureStatus.RESOLVED.value if getattr(result, "passed", False) else ExposureStatus.ACTIVE.value


def current_remediation_status(result) -> str:
    remediation_status = normalize_remediation_status(getattr(result, "remediation_status", None))
    if remediation_status:
        return remediation_status

    decision_status = normalize_remediation_status(getattr(result, "decision_status", None))
    if decision_status:
        return decision_status

    return RemediationStatus.PENDING.value


def validate_transition(current_state: str | None, next_state: str | None) -> None:
    current = normalize_remediation_status(current_state) or RemediationStatus.PENDING.value
    target = normalize_remediation_status(next_state)
    if target is None:
        raise InvalidStateTransitionError("Invalid state transition")
    if current == target:
        return
    allowed = ALLOWED_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidStateTransitionError(f"Invalid state transition: {current} -> {target}")


def _apply_state(result, next_state: str) -> None:
    normalized = normalize_remediation_status(next_state) or RemediationStatus.PENDING.value
    result.remediation_status = normalized
    result.decision_status = normalized


def _log_transition(result, *, from_state: str, to_state: str, event: str) -> None:
    logger.info(
        "remediation_transition %s",
        {
            "finding_id": getattr(result, "id", None),
            "tenant_id": getattr(result, "tenant_id", None),
            "control_id": getattr(result, "control_id", None),
            "resource_id": getattr(result, "resource_id", None),
            "from": from_state,
            "to": to_state,
            "event": event,
        },
    )


def _log_scan_update(
    finding,
    *,
    old_exposure: str,
    new_exposure: str,
    old_remediation: str,
    new_remediation: str,
) -> None:
    logger.info(
        "finding_scan_update %s",
        {
            "finding_id": getattr(finding, "id", None),
            "old_exposure": old_exposure,
            "new_exposure": new_exposure,
            "old_remediation": old_remediation,
            "new_remediation": new_remediation,
            "event": "SCAN_UPDATE",
        },
    )


def _require(flag: bool, message: str) -> None:
    if not flag:
        raise InvalidStateTransitionError(message)


def resolve_next_state(
    event: str | TransitionEvent,
    finding,
    *,
    eligibility_passed: bool = False,
    drift_detected: bool = False,
) -> str:
    event_value = event.value if isinstance(event, TransitionEvent) else str(event)
    current = current_remediation_status(finding)

    if event_value == TransitionEvent.APPROVE.value:
        _require(
            current in {RemediationStatus.PENDING.value, RemediationStatus.FAILED.value},
            "Invalid state transition",
        )
        return RemediationStatus.APPROVED.value

    if event_value == TransitionEvent.SCAN_DETECTED.value:
        return RemediationStatus.PENDING.value

    if event_value == TransitionEvent.SCAN_RESOLVED.value:
        return current

    if event_value == TransitionEvent.EXECUTE.value:
        _require(
            current == RemediationStatus.APPROVED.value,
            "Invalid state transition",
        )
        _require(eligibility_passed, "Eligibility check failed for EXECUTE")
        return RemediationStatus.EXECUTING.value

    if event_value == TransitionEvent.SUCCESS.value:
        _require(current == RemediationStatus.EXECUTING.value, "Invalid state transition")
        return RemediationStatus.SUCCESS.value

    if event_value == TransitionEvent.FAILURE.value:
        _require(current == RemediationStatus.EXECUTING.value, "Invalid state transition")
        return RemediationStatus.FAILED.value

    if event_value == TransitionEvent.PERMISSION_BLOCK.value:
        _require(
            current
            in {
                RemediationStatus.PENDING.value,
                RemediationStatus.APPROVED.value,
                RemediationStatus.EXECUTING.value,
            },
            "Invalid state transition",
        )
        return RemediationStatus.BLOCKED.value

    if event_value == TransitionEvent.IGNORE.value:
        _require(
            current
            in {
                RemediationStatus.PENDING.value,
                RemediationStatus.APPROVED.value,
                RemediationStatus.FAILED.value,
                RemediationStatus.BLOCKED.value,
            },
            "Invalid state transition",
        )
        return RemediationStatus.IGNORED.value

    if event_value == TransitionEvent.UNIGNORE.value:
        _require(current == RemediationStatus.IGNORED.value, "Invalid state transition")
        return RemediationStatus.PENDING.value

    if event_value == TransitionEvent.DRIFT_DETECTED.value:
        _require(drift_detected, "DRIFT_DETECTED event requires drift_detected=True")
        _require(current == RemediationStatus.SUCCESS.value, "Invalid state transition")
        return RemediationStatus.PENDING.value

    raise InvalidStateTransitionError(f"Unknown remediation transition event: {event_value}")


def transition(
    event: str | TransitionEvent,
    finding,
    *,
    eligibility_passed: bool = False,
    drift_detected: bool = False,
) -> str:
    event_value = event.value if isinstance(event, TransitionEvent) else str(event)
    current = current_remediation_status(finding)
    next_state = resolve_next_state(
        event_value,
        finding,
        eligibility_passed=eligibility_passed,
        drift_detected=drift_detected,
    )
    validate_transition(current, next_state)
    _apply_state(finding, next_state)
    _log_transition(finding, from_state=current, to_state=next_state, event=event_value)
    return next_state


def can_transition(
    event: str | TransitionEvent,
    finding,
    *,
    eligibility_passed: bool = False,
    drift_detected: bool = False,
) -> tuple[bool, str | None, str | None]:
    try:
        next_state = resolve_next_state(
            event,
            finding,
            eligibility_passed=eligibility_passed,
            drift_detected=drift_detected,
        )
        validate_transition(current_remediation_status(finding), next_state)
        return True, None, next_state
    except InvalidStateTransitionError as exc:
        return False, str(exc), None


def update_finding_state(finding, scan_result) -> None:
    previous_exposure = current_exposure_status(finding)
    previous_remediation = current_remediation_status(finding)
    evaluated_at = scan_result.evaluated_at
    passed = bool(scan_result.passed)

    finding.evaluated_at = evaluated_at
    finding.passed = passed

    if not passed:
        finding.exposure_status = ExposureStatus.ACTIVE.value
        finding.last_seen_at = evaluated_at
        finding.resolved_by = None

        if getattr(finding, "first_seen_at", None) is None:
            finding.first_seen_at = evaluated_at

        if previous_exposure == ExposureStatus.RESOLVED.value:
            validate_transition(previous_remediation, RemediationStatus.PENDING.value)
            _apply_state(finding, RemediationStatus.PENDING.value)
            finding.drift_count = (getattr(finding, "drift_count", 0) or 0) + 1
            finding.drift_detected_at = evaluated_at

        _log_scan_update(
            finding,
            old_exposure=previous_exposure,
            new_exposure=ExposureStatus.ACTIVE.value,
            old_remediation=previous_remediation,
            new_remediation=current_remediation_status(finding),
        )
        return

    finding.exposure_status = ExposureStatus.RESOLVED.value
    if previous_exposure != ExposureStatus.RESOLVED.value:
        finding.resolved_at = evaluated_at
    # Scan-driven resolutions are system-observed state changes, not external input.
    finding.resolved_by = normalize_resolution_source(ResolutionSource.SYSTEM)

    _log_scan_update(
        finding,
        old_exposure=previous_exposure,
        new_exposure=ExposureStatus.RESOLVED.value,
        old_remediation=previous_remediation,
        new_remediation=current_remediation_status(finding),
    )


def reconcile_rolled_back_state(result) -> None:
    current = current_remediation_status(result)
    if current == RemediationStatus.IGNORED.value:
        transition(TransitionEvent.UNIGNORE, result)
    elif current != RemediationStatus.PENDING.value:
        _apply_state(result, RemediationStatus.PENDING.value)
        _log_transition(
            result,
            from_state=current,
            to_state=RemediationStatus.PENDING.value,
            event="ROLLBACK_RESET",
        )
    if hasattr(result, "last_remediated_at"):
        result.last_remediated_at = None
