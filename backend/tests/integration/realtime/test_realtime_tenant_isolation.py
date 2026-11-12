"""
CRITICAL security tests: SSE must never deliver one org's events to another org's connection.
These tests verify the tenant isolation invariant at the bus level.
"""

import pytest
from app.realtime.event_bus import InMemoryEventBus
from app.realtime.event_models import make_event


@pytest.fixture()
def bus():
    return InMemoryEventBus()


@pytest.mark.asyncio
async def test_org_a_events_do_not_reach_org_b(bus):
    q_a = bus.subscribe("org-a")
    q_b = bus.subscribe("org-b")

    await bus.publish(make_event("CampaignCreated", "org-a", {"campaign_id": "c-1"}))

    assert not q_a.empty(), "org-a subscriber must receive org-a event"
    assert q_b.empty(), "CRITICAL: org-b subscriber must NOT receive org-a event"

    bus.unsubscribe("org-a", q_a)
    bus.unsubscribe("org-b", q_b)


@pytest.mark.asyncio
async def test_org_b_events_do_not_reach_org_a(bus):
    q_a = bus.subscribe("org-a")
    q_b = bus.subscribe("org-b")

    await bus.publish(make_event("TaskFailed", "org-b", {"task_id": "t-1"}))

    assert q_a.empty(), "CRITICAL: org-a subscriber must NOT receive org-b event"
    assert not q_b.empty(), "org-b subscriber must receive org-b event"

    bus.unsubscribe("org-a", q_a)
    bus.unsubscribe("org-b", q_b)


@pytest.mark.asyncio
async def test_multiple_orgs_isolated_under_concurrent_publish(bus):
    queues = {f"org-{i}": bus.subscribe(f"org-{i}") for i in range(5)}

    for i in range(5):
        await bus.publish(make_event("CampaignCreated", f"org-{i}", {"campaign_id": f"c-{i}"}))

    for i in range(5):
        org = f"org-{i}"
        q = queues[org]
        assert not q.empty(), f"{org} must have received its own event"
        evt = q.get_nowait()
        assert evt.organization_id == org, f"CRITICAL: {org} received event for {evt.organization_id}"
        assert q.empty(), f"CRITICAL: {org} received extra events"

    for org, q in queues.items():
        bus.unsubscribe(org, q)


@pytest.mark.asyncio
async def test_unsubscribed_org_receives_nothing(bus):
    q = bus.subscribe("org-a")
    bus.unsubscribe("org-a", q)

    await bus.publish(make_event("CampaignCreated", "org-a", {}))
    assert q.empty(), "Unsubscribed queue must not receive events"


@pytest.mark.asyncio
async def test_organization_id_in_event_matches_subscription_org(bus):
    q = bus.subscribe("org-correct")
    evt = make_event("TaskExecuted", "org-correct", {"task_id": "t-1"})
    await bus.publish(evt)

    received = q.get_nowait()
    assert received.organization_id == "org-correct"
    bus.unsubscribe("org-correct", q)


@pytest.mark.asyncio
async def test_publish_uses_event_organization_id_not_request_param(bus):
    """Verify bus routes by event.organization_id, not any external input."""
    q_real = bus.subscribe("org-real")
    q_evil = bus.subscribe("org-evil")

    # Simulate an attacker who somehow gets an event with org-real embedded
    evt = make_event("CampaignCreated", "org-real", {"campaign_id": "stolen"})
    await bus.publish(evt)

    assert not q_real.empty()
    assert q_evil.empty(), "CRITICAL: attacker org must not receive org-real events"

    bus.unsubscribe("org-real", q_real)
    bus.unsubscribe("org-evil", q_evil)
