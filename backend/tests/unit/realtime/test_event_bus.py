import asyncio
import pytest
from app.realtime.event_bus import InMemoryEventBus
from app.realtime.event_models import make_event


@pytest.fixture()
def bus():
    return InMemoryEventBus()


@pytest.mark.asyncio
async def test_subscribe_returns_queue(bus):
    q = bus.subscribe("org-1")
    assert isinstance(q, asyncio.Queue)
    bus.unsubscribe("org-1", q)


@pytest.mark.asyncio
async def test_publish_delivers_to_subscriber(bus):
    q = bus.subscribe("org-1")
    evt = make_event("CampaignCreated", "org-1", {})
    await bus.publish(evt)
    received = q.get_nowait()
    assert received.event_id == evt.event_id
    bus.unsubscribe("org-1", q)


@pytest.mark.asyncio
async def test_publish_does_not_deliver_to_other_org(bus):
    q1 = bus.subscribe("org-1")
    q2 = bus.subscribe("org-2")
    evt = make_event("CampaignCreated", "org-1", {})
    await bus.publish(evt)
    assert not q1.empty()
    assert q2.empty()
    bus.unsubscribe("org-1", q1)
    bus.unsubscribe("org-2", q2)


@pytest.mark.asyncio
async def test_multiple_subscribers_same_org(bus):
    q1 = bus.subscribe("org-1")
    q2 = bus.subscribe("org-1")
    evt = make_event("TaskFailed", "org-1", {})
    await bus.publish(evt)
    assert not q1.empty()
    assert not q2.empty()
    bus.unsubscribe("org-1", q1)
    bus.unsubscribe("org-1", q2)


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery(bus):
    q = bus.subscribe("org-1")
    bus.unsubscribe("org-1", q)
    evt = make_event("CampaignCreated", "org-1", {})
    await bus.publish(evt)
    assert q.empty()


@pytest.mark.asyncio
async def test_queue_full_drops_event_and_increments_metric(bus, monkeypatch):
    incremented = []
    monkeypatch.setattr("app.realtime.event_bus.increment", lambda name, amount=1: incremented.append(name))
    q = bus.subscribe("org-1")
    # Fill queue to max (100)
    for i in range(100):
        await q.put(make_event("CampaignCreated", "org-1", {}))
    # One more publish should drop and increment metric
    evt = make_event("CampaignCreated", "org-1", {})
    await bus.publish(evt)
    assert "queue_drop_count" in incremented
    bus.unsubscribe("org-1", q)


@pytest.mark.asyncio
async def test_publish_fail_open_on_exception(bus):
    # publish must not raise even if internal state is weird
    evt = make_event("CampaignCreated", "bad-org", {})
    await bus.publish(evt)  # no subscriber — should not raise
