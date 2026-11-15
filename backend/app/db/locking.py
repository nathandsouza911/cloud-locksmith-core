"""Row locks that never wait inside the event loop.

Most endpoints are async but use a synchronous SQLAlchemy session. A blocking
``SELECT ... FOR UPDATE`` that waits for another request's lock blocks the whole event
loop, so the request holding the lock (usually awaiting a network call) can never
finish and the API freezes. Take such locks with ``nowait=True`` and treat
``is_lock_not_available`` as "someone else is already doing this".
"""

from __future__ import annotations

from sqlalchemy.exc import OperationalError

LOCK_NOT_AVAILABLE = "55P03"


def is_lock_not_available(exc: BaseException) -> bool:
    return (
        isinstance(exc, OperationalError) and getattr(getattr(exc, "orig", None), "pgcode", None) == LOCK_NOT_AVAILABLE
    )
