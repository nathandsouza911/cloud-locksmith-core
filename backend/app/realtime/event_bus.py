from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import defaultdict

from app.core.metrics import increment
from app.realtime.event_models import RealtimeEvent

logger = logging.getLogger(__name__)

_QUEUE_MAX = 100


class RealtimeEventBus(ABC):
    @abstractmethod
    def subscribe(self, organization_id: str) -> asyncio.Queue: ...

    @abstractmethod
    def unsubscribe(self, organization_id: str, queue: asyncio.Queue) -> None: ...

    @abstractmethod
    async def publish(self, event: RealtimeEvent) -> None: ...


class InMemoryEventBus(RealtimeEventBus):
    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)

    def subscribe(self, organization_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._subscribers[organization_id].append(q)
        return q

    def unsubscribe(self, organization_id: str, queue: asyncio.Queue) -> None:
        queues = self._subscribers.get(organization_id, [])
        try:
            queues.remove(queue)
        except ValueError:
            pass

    async def publish(self, event: RealtimeEvent) -> None:
        try:
            for q in list(self._subscribers.get(event.organization_id, [])):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    increment("queue_drop_count")
                    logger.warning(
                        "realtime_queue_full org_id=%s event_type=%s — event dropped",
                        event.organization_id,
                        event.event_type,
                    )
        except Exception:
            logger.exception("realtime_bus_publish_error event_type=%s", event.event_type)


_bus: InMemoryEventBus | None = None


def get_event_bus() -> InMemoryEventBus:
    global _bus
    if _bus is None:
        _bus = InMemoryEventBus()
    return _bus
