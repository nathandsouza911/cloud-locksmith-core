"""Audit-event criticality classification (security audit finding M3).

Security-critical, state-changing actions must NOT be reported as successful if
their immutable audit record cannot be persisted. The audit loggers raise
:class:`AuditPersistenceError` for these events (fail closed) and keep the prior
fail-open behaviour for everything else (informational events such as previews).

The identifiers here are matched against the ``action`` of the hash-chain audit
logger (``app.services.audit.audit_logger``) and the ``event_type`` of the
remediation audit logger (``app.services.remediation_audit_service``).
"""

from __future__ import annotations


class AuditPersistenceError(RuntimeError):
    """Raised when a security-critical audit record cannot be persisted.

    Propagating this aborts the surrounding operation so an action with no
    durable evidence is never reported as successful.
    """


# Events that must never proceed without a persisted audit record.
AUDIT_CRITICAL_EVENTS = frozenset(
    {
        # Hash-chain logger (action)
        "OFFBOARDING",
        # Remediation logger (event_type)
        "EXECUTE_STARTED",  # gates remediation + break-glass before the Graph call
        "EXECUTED",
        "ROLLED_BACK",
    }
)


def is_critical_audit_event(identifier: str | None) -> bool:
    return identifier in AUDIT_CRITICAL_EVENTS
