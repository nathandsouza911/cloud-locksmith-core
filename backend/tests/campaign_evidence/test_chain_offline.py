"""Tests for verify_chain_offline — offline (dict-based) chain integrity verification."""

import uuid
from datetime import datetime, timezone

from app.services.campaign_evidence.campaign_audit_chain import (
    _GENESIS,
    _canonical_payload,
    _compute_sequence_hash,
    CAMPAIGN_CREATED,
    verify_chain_offline,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_offline_chain(campaign_id: str, org_id: str, count: int = 3) -> list[dict]:
    """Build a valid chain as a list of dicts (simulating a JSON export)."""
    events = []
    prev = _GENESIS
    for i in range(count):
        eid = str(uuid.uuid4())
        ts = datetime(2026, 1, 1, i, 0, 0, tzinfo=timezone.utc).isoformat()
        payload = {"step": i}
        payload_json = _canonical_payload(payload)
        seq = _compute_sequence_hash(
            eid,
            campaign_id,
            org_id,
            CAMPAIGN_CREATED,
            f"user{i}@x.com",
            ts,
            payload_json,
            prev,
        )
        events.append(
            {
                "id": eid,
                "campaign_id": campaign_id,
                "organization_id": org_id,
                "event_type": CAMPAIGN_CREATED,
                "actor": f"user{i}@x.com",
                "created_at": ts,
                "payload": payload,
                "sequence_hash": seq,
                "previous_hash": prev,
            }
        )
        prev = seq
    return events


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_verify_chain_offline_valid_chain():
    """A correctly-built chain exported as dicts verifies cleanly."""
    campaign_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    events = _build_offline_chain(campaign_id, org_id, count=3)

    result = verify_chain_offline(events)

    assert result["valid"] is True
    assert result["total_events"] == 3
    assert result["verified_events"] == 3
    assert result["errors"] == []
    assert result["head_hash"] == events[-1]["sequence_hash"]
    assert result["campaign_id"] == campaign_id


def test_verify_chain_offline_detects_tamper():
    """Mutating sequence_hash of event[0] causes both a hash mismatch on event[0]
    and a previous_hash mismatch on event[1]."""
    campaign_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    events = _build_offline_chain(campaign_id, org_id, count=3)

    # Corrupt the stored sequence_hash on the first event
    events[0]["sequence_hash"] = "a" * 64

    result = verify_chain_offline(events)

    assert result["valid"] is False
    assert len(result["errors"]) >= 1
    assert any("corrupted" in e or "mismatch" in e for e in result["errors"])


def test_verify_chain_offline_empty_chain():
    """An empty event list is considered valid with no head_hash."""
    result = verify_chain_offline([])

    assert result["valid"] is True
    assert result["total_events"] == 0
    assert result["verified_events"] == 0
    assert result["head_hash"] is None
    assert result["errors"] == []


def test_verify_chain_offline_org_id_mismatch_flagged():
    """When expected_org_id is provided, events from a different org are flagged."""
    campaign_id = str(uuid.uuid4())
    org_a = str(uuid.uuid4())
    org_b = str(uuid.uuid4())
    events = _build_offline_chain(campaign_id, org_a, count=2)

    result = verify_chain_offline(events, expected_org_id=org_b)

    assert result["valid"] is False
    assert any("organization_id" in e for e in result["errors"])
