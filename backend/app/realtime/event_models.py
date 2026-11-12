from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel

from app.utils.datetime import utc_now


class RealtimeEvent(BaseModel, frozen=True):
    event_id: str
    event_type: str
    event_version: str
    organization_id: str
    occurred_at: str
    payload: dict[str, Any]


def make_event(
    event_type: str,
    organization_id: str,
    payload: dict[str, Any],
) -> RealtimeEvent:
    return RealtimeEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        event_version="1",
        organization_id=organization_id,
        occurred_at=utc_now().isoformat(),
        payload=payload,
    )
