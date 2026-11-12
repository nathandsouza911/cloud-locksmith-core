from sqlalchemy import inspect


def test_campaign_audit_event_table_has_required_columns(db_session):
    """Table must exist with hash-chain columns."""
    inspector = inspect(db_session.get_bind())
    cols = {c["name"] for c in inspector.get_columns("campaign_audit_events")}
    assert "id" in cols
    assert "campaign_id" in cols
    assert "organization_id" in cols
    assert "event_type" in cols
    assert "actor" in cols
    assert "payload" in cols
    assert "created_at" in cols
    assert "sequence_hash" in cols
    assert "previous_hash" in cols


# ── Task 3: CampaignAuditChain service tests ─────────────────────────────────

import uuid
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.services.campaign_evidence.campaign_audit_chain import (
    _compute_sequence_hash,
    _canonical_payload,
    verify_campaign_chain,
    CAMPAIGN_CREATED,
    CAMPAIGN_APPROVED,
    _GENESIS,
)


# ── Pure function unit tests (no DB) ────────────────────────────────────────


def test_compute_sequence_hash_is_deterministic():
    h1 = _compute_sequence_hash(
        "id1", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"
    )
    h2 = _compute_sequence_hash(
        "id1", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"
    )
    assert h1 == h2
    assert len(h1) == 64


def test_compute_sequence_hash_sensitive_to_each_field():
    base = ("id1", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS")
    base_hash = _compute_sequence_hash(*base)
    variants = [
        ("id2", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"),
        ("id1", "camp2", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"),
        ("id1", "camp1", "org2", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"),
        ("id1", "camp1", "org1", "campaign_approved", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"),
        ("id1", "camp1", "org1", "campaign_created", "other@x.com", "2026-01-01T00:00:00+00:00", "{}", "GENESIS"),
        ("id1", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-02T00:00:00+00:00", "{}", "GENESIS"),
        ("id1", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", '{"k":"v"}', "GENESIS"),
        ("id1", "camp1", "org1", "campaign_created", "user@x.com", "2026-01-01T00:00:00+00:00", "{}", "OTHERHASH"),
    ]
    for variant in variants:
        assert _compute_sequence_hash(*variant) != base_hash, f"Variant {variant[0]} didn't change hash"


def test_canonical_payload_order_independent():
    a = _canonical_payload({"b": 2, "a": 1})
    b = _canonical_payload({"a": 1, "b": 2})
    assert a == b


def test_canonical_payload_matches_sorted_json():
    result = _canonical_payload({"z": 3, "a": 1})
    assert result == json.dumps({"a": 1, "z": 3}, sort_keys=True, default=str)


# ── Chain verifier tests (mocked DB) ─────────────────────────────────────────


def _make_event(event_id, campaign_id, org_id, event_type, actor, created_at, payload, seq_hash, prev_hash):
    e = MagicMock()
    e.id = event_id
    e.campaign_id = campaign_id
    e.organization_id = org_id
    e.event_type = event_type
    e.actor = actor
    e.created_at = created_at
    e.payload = payload
    e.sequence_hash = seq_hash
    e.previous_hash = prev_hash
    return e


def _make_db_with_events(events):
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = events
    return mock_db


def _build_valid_chain(campaign_id, org_id, count=2):
    events = []
    prev = _GENESIS
    for i in range(count):
        eid = uuid.uuid4()
        ts = datetime(2026, 1, 1, i, 0, 0, tzinfo=timezone.utc)
        payload = {"step": i}
        payload_json = _canonical_payload(payload)
        seq = _compute_sequence_hash(
            str(eid),
            str(campaign_id),
            str(org_id),
            CAMPAIGN_CREATED,
            f"user{i}@x.com",
            ts.isoformat(),
            payload_json,
            prev,
        )
        events.append(_make_event(eid, campaign_id, org_id, CAMPAIGN_CREATED, f"user{i}@x.com", ts, payload, seq, prev))
        prev = seq
    return events


def test_verify_campaign_chain_valid():
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=3)
    mock_db = _make_db_with_events(events)

    result = verify_campaign_chain(mock_db, str(campaign_id))

    assert result["valid"] is True
    assert result["total_events"] == 3
    assert result["verified_events"] == 3
    assert result["errors"] == []
    assert result["head_hash"] == events[-1].sequence_hash


def test_verify_campaign_chain_empty():
    mock_db = _make_db_with_events([])
    result = verify_campaign_chain(mock_db, str(uuid.uuid4()))
    assert result["valid"] is True
    assert result["total_events"] == 0
    assert result["head_hash"] is None


def test_verify_campaign_chain_broken_previous_hash():
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=2)
    # Tamper: break the chain linkage on event[1]
    events[1].previous_hash = "badhash"
    mock_db = _make_db_with_events(events)

    result = verify_campaign_chain(mock_db, str(campaign_id))
    assert result["valid"] is False
    assert any("previous_hash" in e for e in result["errors"])


def test_verify_campaign_chain_tampered_sequence_hash():
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=2)
    # Tamper: corrupt the stored sequence_hash on event[0]
    events[0].sequence_hash = "a" * 64
    mock_db = _make_db_with_events(events)

    result = verify_campaign_chain(mock_db, str(campaign_id))
    assert result["valid"] is False
    assert any("corrupted" in e or "mismatch" in e for e in result["errors"])


def test_verify_campaign_chain_cross_tenant_replay_detected():
    """An event whose hash was computed with org_a but stored under org_b fails."""
    campaign_id = uuid.uuid4()
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()

    eid = uuid.uuid4()
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    payload_json = _canonical_payload({})
    # Hash computed with org_a
    seq = _compute_sequence_hash(
        str(eid), str(campaign_id), str(org_a), CAMPAIGN_CREATED, "u@x.com", ts.isoformat(), payload_json, _GENESIS
    )
    # Event stored as org_b (cross-tenant replay attempt)
    event = _make_event(eid, campaign_id, org_b, CAMPAIGN_CREATED, "u@x.com", ts, {}, seq, _GENESIS)
    mock_db = _make_db_with_events([event])

    result = verify_campaign_chain(mock_db, str(campaign_id))
    assert result["valid"] is False


def test_verify_campaign_chain_org_id_isolation():
    """expected_org_id mismatch is flagged as an error."""
    campaign_id = uuid.uuid4()
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_a, count=1)
    mock_db = _make_db_with_events(events)

    result = verify_campaign_chain(mock_db, str(campaign_id), expected_org_id=str(org_b))
    assert result["valid"] is False
    assert any("organization_id" in e for e in result["errors"])


# ── Task 4: Lifecycle hook integration tests ──────────────────────────────────

from unittest.mock import patch as mock_patch  # noqa: E402


def test_create_campaign_plan_appends_created_event(db_session):
    """create_campaign_plan must write a campaign_created audit event."""
    from app.services.campaign_evidence.campaign_audit_chain import CAMPAIGN_CREATED
    from app.services.remediation.fleet.campaign_service import create_campaign_plan

    appended = []

    def capture_event(db, *, campaign_id, organization_id, event_type, actor, payload):
        appended.append({"event_type": event_type, "actor": actor, "payload": payload})
        return MagicMock(sequence_hash="abc123")

    # resolve_allowed_tenant_ids queries UserTenantAccess which is not in the SQLite
    # test DB — mock it to return an empty set so the function proceeds normally.
    with (
        mock_patch(
            "app.services.remediation.fleet.campaign_service.resolve_allowed_tenant_ids",
            return_value=set(),
        ),
        mock_patch(
            "app.services.remediation.fleet.campaign_service.append_campaign_audit_event",
            side_effect=capture_event,
        ),
    ):
        create_campaign_plan(
            db_session,
            organization_id=uuid.uuid4(),
            user_id="user-123",
            created_by="admin@example.com",
            control_ids=[],
            target_tenant_ids=[],
            dry_run=False,
        )

    assert any(e["event_type"] == CAMPAIGN_CREATED for e in appended), "campaign_created event not appended"


# ── Task 9: Comprehensive chain integrity tests ──────────────────────────────


def test_verify_campaign_chain_detects_all_breaks_in_long_chain():
    """All corrupted events are reported, not just the first."""
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=5)

    # Corrupt events at index 1 and 3
    events[1].sequence_hash = "corrupted1" + "a" * 54
    events[3].sequence_hash = "corrupted3" + "b" * 54

    mock_db = _make_db_with_events(events)
    result = verify_campaign_chain(mock_db, str(campaign_id))

    assert result["valid"] is False
    # Should detect multiple issues
    assert len(result["errors"]) >= 2


def test_verify_campaign_chain_payload_mutation_detected():
    """If payload is mutated after hashing, the sequence_hash no longer matches."""
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=1)

    # Mutate payload after the hash was computed
    events[0].payload = {"injected": "malicious_data"}

    mock_db = _make_db_with_events(events)
    result = verify_campaign_chain(mock_db, str(campaign_id))

    assert result["valid"] is False
    assert any("corrupted" in e or "mismatch" in e for e in result["errors"])


def test_verify_campaign_chain_event_type_mutation_detected():
    """If event_type is changed after hashing, verification fails."""
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=1)

    # Mutate event_type (e.g., change created to approved to hide an approval)
    events[0].event_type = CAMPAIGN_APPROVED

    mock_db = _make_db_with_events(events)
    result = verify_campaign_chain(mock_db, str(campaign_id))

    assert result["valid"] is False


def test_verify_campaign_chain_actor_mutation_detected():
    """If actor is changed after hashing, verification fails."""
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()
    events = _build_valid_chain(campaign_id, org_id, count=1)

    events[0].actor = "attacker@evil.com"  # mutate

    mock_db = _make_db_with_events(events)
    result = verify_campaign_chain(mock_db, str(campaign_id))

    assert result["valid"] is False
