from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.api.dependencies.current_user import get_current_user
from app.realtime.event_bus import get_event_bus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["realtime"])

_HEARTBEAT_INTERVAL = 15  # seconds


@router.get("/realtime/stream")
async def sse_stream(current_user=Depends(get_current_user)):
    organization_id: str = current_user.organization_id
    bus = get_event_bus()
    queue = bus.subscribe(organization_id)

    async def _generate():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_INTERVAL)
                    data = json.dumps(event.model_dump())
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            bus.unsubscribe(organization_id, queue)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
