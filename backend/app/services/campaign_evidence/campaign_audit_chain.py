"""Append-only, hash-chained campaign audit event writer and verifier.

Pattern mirrors app/services/audit/audit_logger.py exactly:
  1. Advisory lock on campaign_id — serialises concurrent writes.
  2. INSERT with sequence_hash / previous_hash = NULL.
  3. Flush → refresh (DB assigns id + created_at).
  4. Compute sequence_hash.
  5. UPDATE hash fields (immutability trigger allows this once-only transition).

Hash formula:
    SHA256(id | campaign_id | organization_id | event_type | actor |
           created_at_iso | payload_json | previous_hash)
"""

import hashlib
import json
import logging

from sqlalchemy import desc, text
from sqlalchemy.orm import Session

from app.db.models.campaign_audit_event import CampaignAuditEvent

logger = logging.getLogger(__name__)

_GENESIS = "GENESIS"

# Event type constants — exhaustive list; add here before using elsewhere.
CAMPAIGN_CREATED = "campaign_created"
CAMPAIGN_APPROVED = "campaign_approved"
CAMPAIGN_PARTIALLY_APPROVED = "campaign_partially_approved"
CAMPAIGN_EXECUTED = "campaign_executed"
CAMPAIGN_VERIFIED = "campaign_verified"
DRIFT_DETECTED = "drift_detected"
CAMPAIGN_ROLLBACK = "campaign_rollback"
CAMPAIGN_ARCHIVED = "campaign_archived"
CAMPAIGN_CANCELLED = "campaign_cancelled"


def _canonical_payload(payload: dict) -> str:
    return json.dumps(payload or {}, sort_keys=True, default=str)


def _compute_sequence_hash(
    id: str,
    campaign_id: str,
    organization_id: str,
    event_type: str,
    actor: str,
    created_at_iso: str,
    payload_json: str,
    previous_hash: str,
) -> str:
    """SHA-256 over pipe-delimited canonical fields.

    Field order is fixed — do not reorder without a re-hash migration.
    """
    raw = "|".join(
        [
            str(id),
            str(campaign_id),
            str(organization_id),
            event_type,
            actor,
            created_at_iso,
            payload_json,
            previous_hash,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append_campaign_audit_event(
    db: Session,
    *,
    campaign_id,
    organization_id,
    event_type: str,
    actor: str,
    payload: dict,
) -> "CampaignAuditEvent | None":
    """Append an immutable hash-chained event to a campaign's audit chain.

    Fails open (returns None, logs error) — callers must not rely on this
    for flow control. The campaign operation completes regardless.
    """
    try:
        # 1. Acquire per-campaign advisory lock — prevents fork race.
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": f"campaign_audit:{campaign_id}"},
        )

        # 2. Read tail of this campaign's chain.
        prev_event = (
            db.query(CampaignAuditEvent)
            .filter(CampaignAuditEvent.campaign_id == campaign_id)
            .order_by(desc(CampaignAuditEvent.created_at))
            .first()
        )
        previous_hash = prev_event.sequence_hash if (prev_event and prev_event.sequence_hash) else _GENESIS

        # 3. INSERT with NULL hashes — DB assigns id + created_at.
        event = CampaignAuditEvent(
            campaign_id=campaign_id,
            organization_id=organization_id,
            event_type=event_type,
            actor=actor,
            payload=payload or {},
        )
        db.add(event)
        db.flush()
        db.refresh(event)

        # 4. Compute hash using DB-assigned values.
        payload_json = _canonical_payload(event.payload)
        sequence_hash = _compute_sequence_hash(
            id=str(event.id),
            campaign_id=str(event.campaign_id),
            organization_id=str(event.organization_id),
            event_type=event.event_type,
            actor=event.actor,
            created_at_iso=event.created_at.isoformat(),
            payload_json=payload_json,
            previous_hash=previous_hash,
        )

        # 5. Write hashes back (trigger permits this one NULL → value transition).
        event.sequence_hash = sequence_hash
        event.previous_hash = previous_hash
        db.commit()
        db.refresh(event)
        return event

    except Exception:
        db.rollback()
        logger.exception(
            "campaign_audit_event_write_failed campaign_id=%s event_type=%s",
            campaign_id,
            event_type,
        )
        return None


def verify_campaign_chain(
    db: Session,
    campaign_id: str,
    expected_org_id: str | None = None,
) -> dict:
    """Re-derive every sequence_hash and validate the chain for a campaign.

    Returns::

        {
            "valid": bool,
            "campaign_id": str,
            "total_events": int,
            "verified_events": int,
            "errors": list[str],
            "head_hash": str | None,
        }

    Cross-tenant replay detection: if expected_org_id is provided, any event
    with a different organization_id is flagged as an error (the org_id is
    embedded in every hash, so a replayed event from another org will also fail
    hash verification — this is an additional belt-and-suspenders check).
    """
    events = (
        db.query(CampaignAuditEvent)
        .filter(CampaignAuditEvent.campaign_id == campaign_id)
        .order_by(CampaignAuditEvent.created_at.asc())
        .all()
    )

    if not events:
        return {
            "valid": True,
            "campaign_id": str(campaign_id),
            "total_events": 0,
            "verified_events": 0,
            "errors": [],
            "head_hash": None,
        }

    errors: list[str] = []
    expected_previous = _GENESIS
    verified = 0

    for event in events:
        # Org isolation check.
        if expected_org_id and str(event.organization_id) != str(expected_org_id):
            errors.append(
                f"event {event.id}: organization_id {event.organization_id!r} "
                f"does not match expected {expected_org_id!r} — possible cross-tenant replay"
            )

        if event.sequence_hash is None:
            # Legacy row written before chain tracking existed.
            errors.append(f"event {event.id}: missing sequence_hash (legacy row)")
            continue

        # Chain linkage check.
        if event.previous_hash != expected_previous:
            errors.append(
                f"event {event.id}: previous_hash mismatch "
                f"(expected {expected_previous[:16]}..., "
                f"got {(event.previous_hash or 'None')[:16]}...)"
            )

        # Hash re-derivation.
        payload_json = _canonical_payload(event.payload)
        expected_hash = _compute_sequence_hash(
            id=str(event.id),
            campaign_id=str(event.campaign_id),
            organization_id=str(event.organization_id),
            event_type=event.event_type,
            actor=event.actor,
            created_at_iso=event.created_at.isoformat(),
            payload_json=payload_json,
            previous_hash=event.previous_hash or _GENESIS,
        )
        if event.sequence_hash != expected_hash:
            errors.append(f"event {event.id}: sequence_hash corrupted — row may have been tampered")
        else:
            verified += 1

        expected_previous = event.sequence_hash

    return {
        "valid": len(errors) == 0,
        "campaign_id": str(campaign_id),
        "total_events": len(events),
        "verified_events": verified,
        "errors": errors,
        "head_hash": events[-1].sequence_hash if events else None,
    }


def verify_chain_offline(events: list[dict], expected_org_id: str | None = None) -> dict:
    """Re-verify chain integrity from an exported list of event dicts.

    Same logic as verify_campaign_chain but accepts dicts (from JSON export)
    instead of ORM objects. Used for offline insurer verification.

    Each event dict has keys: id, campaign_id, organization_id, event_type,
    actor, created_at (ISO string), payload (dict), sequence_hash, previous_hash.

    Returns same structure as verify_campaign_chain.
    """
    errors: list[str] = []
    expected_previous_hash = _GENESIS
    campaign_id = None
    verified_events = 0

    for event in events:
        if campaign_id is None:
            campaign_id = event.get("campaign_id")

        if expected_org_id and event.get("organization_id") != expected_org_id:
            errors.append(f"event {event.get('id')}: organization_id mismatch")

        payload_json = _canonical_payload(event.get("payload") or {})
        derived = _compute_sequence_hash(
            event["id"],
            event["campaign_id"],
            event["organization_id"],
            event["event_type"],
            event["actor"],
            event["created_at"],  # already ISO string
            payload_json,
            expected_previous_hash,
        )

        if event.get("previous_hash") != expected_previous_hash:
            errors.append(f"event {event.get('id')}: previous_hash mismatch")

        if event.get("sequence_hash") != derived:
            errors.append(f"event {event.get('id')}: sequence_hash corrupted or mismatch")

        expected_previous_hash = event.get("sequence_hash")
        verified_events += 1

    return {
        "valid": len(errors) == 0,
        "campaign_id": campaign_id,
        "total_events": len(events),
        "verified_events": verified_events,
        "errors": errors,
        "head_hash": events[-1]["sequence_hash"] if events else None,
    }
