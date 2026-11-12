import redis
from app.config import settings

_SOCKET_TIMEOUT = 5
_CONNECT_TIMEOUT = 5


def _build_redis_client() -> redis.Redis:
    if settings.REDIS_URL:
        return redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=_CONNECT_TIMEOUT,
            socket_timeout=_SOCKET_TIMEOUT,
        )
    return redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD or None,
        decode_responses=True,
        socket_connect_timeout=_CONNECT_TIMEOUT,
        socket_timeout=_SOCKET_TIMEOUT,
    )


redis_client = _build_redis_client()


def verify_redis_available_in_production() -> None:
    if settings.ENVIRONMENT.lower() != "production":
        return
    try:
        redis_client.ping()
    except Exception as exc:
        raise RuntimeError(
            "Redis is required in production for token revocation, lockout, and rate limiting. "
            "Set REDIS_URL (Railway) or REDIS_HOST + REDIS_PORT + REDIS_PASSWORD."
        ) from exc
