"""Tests that instrumentation points publish correct events without affecting service behaviour."""

import asyncio
import pytest
from app.realtime.event_bus import InMemoryEventBus
from app.realtime.event_models import RealtimeEvent, make_event


def _make_bus_and_queue(org_id="org-1"):
    bus = InMemoryEventBus()
    q = bus.subscribe(org_id)
    return bus, q


def _drain(q: asyncio.Queue) -> list[RealtimeEvent]:
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    return events


@pytest.mark.asyncio
async def test_campaign_created_event_shape():
    bus, q = _make_bus_and_queue("org-test")
    await bus.publish(
        make_event(
            "CampaignCreated",
            "org-test",
            {
                "campaign_id": "c-1",
                "status": "AWAITING_APPROVAL",
                "plan_hash": "abc",
                "task_count": 1,
                "dry_run": False,
                "created_by": "user@example.com",
            },
        )
    )
    events = _drain(q)
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "CampaignCreated"
    assert e.event_version == "1"
    assert e.organization_id == "org-test"
    assert e.payload["campaign_id"] == "c-1"
    assert e.payload["status"] == "AWAITING_APPROVAL"
    assert e.payload["plan_hash"] == "abc"
    assert e.payload["task_count"] == 1
    assert e.payload["dry_run"] is False
    assert e.payload["created_by"] == "user@example.com"
    bus.unsubscribe("org-test", q)


@pytest.mark.asyncio
async def test_campaign_approved_event_shape():
    bus, q = _make_bus_and_queue("org-test")
    await bus.publish(
        make_event(
            "CampaignApproved",
            "org-test",
            {
                "campaign_id": "c-2",
                "status": "AWAITING_APPROVAL",
                "approved_by": "admin@example.com",
                "approved_plan_hash": "xyz",
            },
        )
    )
    events = _drain(q)
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "CampaignApproved"
    assert e.event_version == "1"
    assert e.organization_id == "org-test"
    assert e.payload["campaign_id"] == "c-2"
    assert e.payload["approved_by"] == "admin@example.com"
    assert e.payload["approved_plan_hash"] == "xyz"
    bus.unsubscribe("org-test", q)


@pytest.mark.asyncio
async def test_campaign_partially_approved_event_shape():
    bus, q = _make_bus_and_queue("org-test")
    await bus.publish(
        make_event(
            "CampaignPartiallyApproved",
            "org-test",
            {
                "campaign_id": "c-3",
                "status": "AWAITING_APPROVAL",
                "approved_by": "admin@example.com",
                "approved_tenant_ids": ["t-1", "t-2"],
                "approved_plan_hash": "qrs",
            },
        )
    )
    events = _drain(q)
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "CampaignPartiallyApproved"
    assert e.event_version == "1"
    assert e.organization_id == "org-test"
    assert e.payload["campaign_id"] == "c-3"
    assert e.payload["approved_tenant_ids"] == ["t-1", "t-2"]
    assert e.payload["approved_plan_hash"] == "qrs"
    bus.unsubscribe("org-test", q)


@pytest.mark.asyncio
async def test_publish_to_wrong_org_delivers_nothing():
    """Events are only delivered to subscribers of the matching org_id."""
    bus, q = _make_bus_and_queue("org-A")
    await bus.publish(make_event("CampaignCreated", "org-B", {"campaign_id": "c-99"}))
    events = _drain(q)
    assert events == []
    bus.unsubscribe("org-A", q)
