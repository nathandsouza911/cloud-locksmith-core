"""Keep OAuth secrets out of the HTTP access log.

uvicorn logs every request path with its query string. The Microsoft sign-in callback
carries the authorization code, ``state`` and ``session_state`` there, so without this
filter every sign-in wrote them to the log.
"""

from __future__ import annotations

import logging
import re

SENSITIVE_QUERY_PARAMS = (
    "code",
    "state",
    "session_state",
    "id_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "code_verifier",
)
REDACTED = "[REDACTED]"

# A parameter name must start the query or follow "&", so "error_code" and "postcode" are kept.
_SENSITIVE_PARAM = re.compile(r"(?P<prefix>[?&](?:%s)=)[^&#\s]*" % "|".join(SENSITIVE_QUERY_PARAMS))


def redact_query_secrets(text: str) -> str:
    if "?" not in text:
        return text
    return _SENSITIVE_PARAM.sub(lambda m: m.group("prefix") + REDACTED, text)


class AccessLogRedactionFilter(logging.Filter):
    """Redacts sensitive query parameters in the request path of uvicorn access records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(redact_query_secrets(a) if isinstance(a, str) else a for a in record.args)
        elif isinstance(record.msg, str):
            record.msg = redact_query_secrets(record.msg)
        return True


def install_access_log_redaction() -> None:
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, AccessLogRedactionFilter) for f in logger.filters):
        logger.addFilter(AccessLogRedactionFilter())
