import logging
import time
from threading import Lock

from app.config import settings

logger = logging.getLogger(__name__)

# In-memory fallback used when Redis is unavailable.
_fallback: dict[str, float] = {}
_lock = Lock()


def _try_redis_set(jti: str, ttl: int) -> bool:
    try:
        from app.core.redis_client import redis_client

        redis_client.setex(f"denylist:{jti}", ttl, "1")
        return True
    except Exception:
        if settings.ENVIRONMENT.lower() == "production":
            logger.error("redis_denylist_write_failed jti=%s failing_closed", jti)
            raise
        logger.warning("redis_denylist_write_failed jti=%s using in-memory fallback", jti)
        return False


def _try_redis_exists(jti: str) -> bool | None:
    """Returns True/False if Redis available, None if unavailable."""
    try:
        from app.core.redis_client import redis_client

        return redis_client.exists(f"denylist:{jti}") == 1
    except Exception:
        if settings.ENVIRONMENT.lower() == "production":
            logger.error("redis_denylist_read_failed jti=%s failing_closed", jti)
            return True
        logger.warning("redis_denylist_read_failed jti=%s using in-memory fallback", jti)
        return None


def revoke(jti: str, expires_at: float) -> None:
    ttl = int(expires_at - time.time())
    if ttl <= 0:
        return
    if _try_redis_set(jti, ttl):
        return
    with _lock:
        _fallback[jti] = expires_at
        _prune_unsafe()


def is_revoked(jti: str) -> bool:
    result = _try_redis_exists(jti)
    if result is not None:
        return result
    with _lock:
        _prune_unsafe()
        return jti in _fallback


def _prune_unsafe() -> None:
    """Remove expired entries. Must be called while _lock is held."""
    now = time.time()
    expired = [k for k, v in _fallback.items() if v <= now]
    for k in expired:
        del _fallback[k]
