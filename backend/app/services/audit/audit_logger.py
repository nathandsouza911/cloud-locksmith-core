import hashlib
import json
import logging

from sqlalchemy import desc, text

from app.db.models.audit_log import AuditLog
from app.services.audit.critical_events import (
    AuditPersistenceError,
    is_critical_audit_event,
)

logger = logging.getLogger(__name__)

# Sentinel used as previous_hash for the first row in a tenant's chain.
_GENESIS = "GENESIS"


def _compute_sequence_hash(
    *,
    row_id: int,
    action: str,
    actor: str,
    target: str,
    tenant_id: str,
    created_at_iso: str,
    details: dict,
    previous_hash: str,
) -> str:
    """SHA-256 over the canonical pipe-delimited chain payload.

    Field order is fixed — never reorder without a migration + re-hash.
    The pipe separator prevents value-boundary ambiguity.

    Formula:
        SHA256(id | action | actor | target | tenant_id | created_at | details_json | previous_hash)

    details_json is json.dumps(details, sort_keys=True, default=str) — the same
    canonical serialization applied by the immutability trigger so that any
    out-of-band mutation to the details column invalidates the hash.
    """
    details_str = json.dumps(details or {}, sort_keys=True, default=str)
    payload = "|".join(
        [
            str(row_id),
            action,
            actor,
            target,
            tenant_id,
            created_at_iso,
            details_str,
            previous_hash,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_audit_event(
    *,
    db,
    tenant_id: str,
    action: str,
    actor: str,
    target: str,
    status: str,
    reason: str | None,
    details: dict,
) -> AuditLog | None:
    """Append an immutable, hash-chained entry to the audit log.

    The write is two-phase within a single transaction:
      1. Acquire a transaction-scoped advisory lock on the tenant's chain key.
         This serialises all concurrent inserts for the same tenant — unlike
         SELECT FOR UPDATE, the advisory lock is re-acquired AFTER any waiting
         period, so the subsequent read always sees the latest committed row.
      2. INSERT the row — lets Postgres assign id and created_at.
      3. Compute sequence_hash using the server-assigned values, then UPDATE
         sequence_hash and previous_hash (the DB trigger allows this one
         write-once transition; all subsequent UPDATEs and DELETEs are blocked).

    Failure handling is criticality-aware (M3): for security-critical actions
    (see ``AUDIT_CRITICAL_EVENTS`` — e.g. OFFBOARDING) a persistence failure
    raises ``AuditPersistenceError`` so the caller aborts rather than proceed
    without durable evidence. Informational actions remain fail-open (return
    None). All failures are logged regardless.
    """
    try:
        # ── 1. Advisory lock: serialises all concurrent inserts for this tenant.
        # pg_advisory_xact_lock is transaction-scoped — released automatically
        # on COMMIT or ROLLBACK.  A second call with the same key blocks until
        # the first transaction ends, then re-reads the current chain tail,
        # preventing the fork race that SELECT FOR UPDATE cannot avoid.
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": f"audit:{tenant_id}"},
        )
        previous_row = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).order_by(desc(AuditLog.id)).first()
        previous_hash = previous_row.sequence_hash if (previous_row and previous_row.sequence_hash) else _GENESIS

        # ── 2. INSERT the row; sequence_hash / previous_hash stay NULL for now.
        entry = AuditLog(
            tenant_id=tenant_id,
            action=action,
            actor=actor,
            target=target,
            status=status,
            reason=reason,
            details=details,
        )
        db.add(entry)
        db.flush()  # writes the row; Postgres assigns id and created_at
        db.refresh(entry)  # populates server_default values on the Python object

        # ── 3. Compute the hash using the DB-assigned id and created_at.
        sequence_hash = _compute_sequence_hash(
            row_id=entry.id,
            action=entry.action,
            actor=entry.actor,
            target=entry.target,
            tenant_id=entry.tenant_id,
            created_at_iso=entry.created_at.isoformat(),
            details=entry.details or {},
            previous_hash=previous_hash,
        )

        # ── 4. Write hashes back (trigger permits this one NULL → value UPDATE).
        entry.sequence_hash = sequence_hash
        entry.previous_hash = previous_hash
        db.commit()
        db.refresh(entry)

        return entry

    except Exception as exc:
        db.rollback()
        logger.error(
            "audit_log_write_failed action=%s tenant_id=%s actor=%s target=%s status=%s",
            action,
            tenant_id,
            actor,
            target,
            status,
            exc_info=True,
        )
        # Fail closed for security-critical, state-changing actions: the caller
        # must abort rather than report success without durable evidence.
        # Informational actions keep the prior fail-open behaviour.
        if is_critical_audit_event(action):
            raise AuditPersistenceError(
                f"Failed to persist critical audit event action={action} " f"tenant_id={tenant_id}"
            ) from exc
        return None
