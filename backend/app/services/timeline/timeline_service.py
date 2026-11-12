"""Client Timeline — merge, order and paginate operational history.

Read-only aggregation. The timeline owns no storage; it projects rows that
already exist in the review, remediation, verification, audit, report and
posture subsystems into one chronological narrative.

Pagination is cursor-based rather than offset-based because the underlying
sources keep growing: an offset page would silently skip rows once new events
land between requests. The cursor records the exact position — timestamp,
source and id — so paging is stable regardless of what is written meanwhile.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Sequence

from sqlalchemy.orm import Session

from app.services.timeline.sources import TIMELINE_SOURCES
from app.services.timeline.timeline_event import TimelineEvent
from app.utils.datetime import ensure_utc

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


@dataclass(frozen=True)
class TimelinePage:
    events: list[TimelineEvent] = field(default_factory=list)
    next_cursor: str | None = None
    has_more: bool = False


def encode_cursor(event: TimelineEvent) -> str:
    payload = {
        "timestamp": event.timestamp.isoformat(),
        "source": event.source_system,
        "id": event.id,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: str | None) -> dict | None:
    """Decode a cursor, or raise ``ValueError`` if it is not one.

    Failing loudly matters: silently treating a malformed cursor as "start from
    the beginning" would make a paging bug look like duplicated data rather than
    an error.
    """
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        payload = json.loads(raw)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("Malformed timeline cursor") from exc

    if not isinstance(payload, dict) or not {
        "timestamp",
        "source",
        "id",
    } <= set(payload):
        raise ValueError("Malformed timeline cursor")

    try:
        payload["timestamp_parsed"] = ensure_utc(datetime.fromisoformat(payload["timestamp"]))
    except (TypeError, ValueError) as exc:
        raise ValueError("Malformed timeline cursor") from exc

    return payload


def _cursor_position(payload: dict) -> tuple:
    return (payload["timestamp_parsed"], payload["source"], payload["id"])


def build_timeline(
    db: Session,
    *,
    tenant_id: str,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
    workflow_id: str | None = None,
    event_types: Sequence[str] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> TimelinePage:
    """Merge every source into one newest-first page for a single tenant.

    Tenant isolation is enforced inside each source adapter; ``tenant_id`` here
    is the server-resolved value from the route dependency, never client input.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    cursor_payload = decode_cursor(cursor)

    # Upper time bound: the caller's `until`, narrowed by the cursor position.
    upper_bound = ensure_utc(until)
    if cursor_payload is not None:
        cursor_ts = cursor_payload["timestamp_parsed"]
        upper_bound = cursor_ts if upper_bound is None else min(upper_bound, cursor_ts)

    # Over-fetch by one per source so `has_more` is known without a second pass.
    # Each source can contribute at most `limit + 1` to the merged page.
    per_source_limit = limit + 1

    merged: list[TimelineEvent] = []
    for source in TIMELINE_SOURCES:
        try:
            merged.extend(
                source.fetch(
                    db,
                    tenant_id=tenant_id,
                    until=upper_bound,
                    since=ensure_utc(since),
                    limit=per_source_limit,
                )
            )
        except Exception:
            # One unavailable subsystem must not blank the whole timeline —
            # a partial narrative is far more useful than an error page.
            logger.exception(
                "timeline_source_failed source=%s tenant_id=%s",
                source.source_system,
                tenant_id,
            )

    merged = list(_apply_filters(merged, workflow_id=workflow_id, event_types=event_types))
    merged.sort(key=lambda event: event.sort_key, reverse=True)

    if cursor_payload is not None:
        # Strictly past the cursor position. The tuple comparison is why
        # sort_key includes source and id: timestamps alone collide.
        position = _cursor_position(cursor_payload)
        merged = [event for event in merged if event.sort_key < position]

    page = merged[:limit]
    has_more = len(merged) > limit

    return TimelinePage(
        events=page,
        next_cursor=encode_cursor(page[-1]) if (page and has_more) else None,
        has_more=has_more,
    )


def _apply_filters(
    events: Iterable[TimelineEvent],
    *,
    workflow_id: str | None,
    event_types: Sequence[str] | None,
) -> Iterable[TimelineEvent]:
    allowed_types = set(event_types) if event_types else None
    for event in events:
        if workflow_id is not None and event.workflow_id != workflow_id:
            continue
        if allowed_types is not None and event.event_type not in allowed_types:
            continue
        yield event
