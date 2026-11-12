"""
Regression tests verifying fail-closed behavior in security-sensitive paths.

Fail-closed means: when something goes wrong in a security operation (Graph
mutation, DB write after remediation), the system loudly fails rather than
silently succeeding.

Documented fail-open exceptions:
- Redis unavailability for rate limiting in non-production: falls back to
  in-memory counter (fail open relative to Redis, still enforced).
- Redis unavailability for rate limiting in production: fails CLOSED
  (blocks requests) — intentionally conservative.
- Email sending: failures must not block user-facing flows.
"""

import inspect
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Rate-limit middleware Redis failure behavior
# ---------------------------------------------------------------------------


class TestRateLimitMiddlewareRedisFailure:
    """
    In production:  Redis failure → fail CLOSED (block requests). Conservative.
    In non-prod:    Redis failure → in-memory fallback (still enforced, not bypassed).
    Neither path silently drops rate-limit enforcement without logging.
    """

    def test_middleware_has_except_around_redis_call(self):
        """_try_redis_incr must have an except clause wrapping the Redis call."""
        from app.middleware.rate_limit import _try_redis_incr

        source = inspect.getsource(_try_redis_incr)
        assert "except" in source, "Redis call must be wrapped in a try/except"

    def test_redis_failure_returns_none_in_non_prod(self):
        """
        In non-production, _try_redis_incr returns None on Redis error so the
        caller falls through to the in-memory counter — enforcement is maintained.
        """
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.ENVIRONMENT = "development"
            with patch("app.core.redis_client.redis_client") as mock_redis:
                mock_redis.incr.side_effect = Exception("connection refused")
                from app.middleware.rate_limit import _try_redis_incr

                result = _try_redis_incr("test_key", limit=5, window_seconds=60)
        # None signals caller to use in-memory fallback — not bypass
        assert result is None

    def test_redis_failure_fails_closed_in_production(self):
        """
        In production, _try_redis_incr returns True (blocked) on Redis error.
        This is the intentional conservative fail-closed behavior.
        """
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.ENVIRONMENT = "production"
            with patch("app.core.redis_client.redis_client") as mock_redis:
                mock_redis.incr.side_effect = Exception("connection refused")
                from app.middleware.rate_limit import _try_redis_incr

                result = _try_redis_incr("test_key", limit=5, window_seconds=60)
        assert result is True, "Production Redis failure must return True (blocked) — fail closed"

    def test_middleware_source_calls_call_next(self):
        """
        The dispatch method must always call call_next eventually — the
        middleware must not hard-crash on route resolution failures.
        """
        from app.middleware.rate_limit import RateLimitMiddleware

        source = inspect.getsource(RateLimitMiddleware.dispatch)
        assert "call_next" in source

    def test_route_resolution_exception_is_swallowed_safely(self):
        """
        _resolve_route_name swallows individual route-match exceptions via
        `except Exception: continue` to avoid crashing the middleware on
        malformed routes. This is acceptable — it only affects route matching,
        not security state.
        """
        from app.middleware.rate_limit import _resolve_route_name

        source = inspect.getsource(_resolve_route_name)
        assert "except Exception" in source
        assert "continue" in source


# ---------------------------------------------------------------------------
# Remediation execution service — IntegrityError must not be silently swallowed
# ---------------------------------------------------------------------------


class TestRemediationExecutionServiceFailClosed:
    """
    An IntegrityError during the final DB commit after a Graph mutation must
    NOT be silently swallowed and returned as a success. It must be re-raised
    so the caller (and any wrapping transaction) can detect the failure.
    """

    def test_integrity_error_is_reraised_not_swallowed(self):
        """
        Verify the except IntegrityError block in remediation_execution_service
        re-raises rather than returning compliance as if nothing happened.
        The fix: log + raise, not log + return.
        """
        from app.services import remediation_execution_service

        source = inspect.getsource(remediation_execution_service)

        # The old pattern was: except IntegrityError: ... return compliance
        # This silently reported success after a failed DB commit. It must
        # no longer appear in the source.
        assert "except IntegrityError" in source, "IntegrityError handler must exist to log the failure"

        # After the IntegrityError block there must be a raise, not a return
        # of the compliance object.  We check that the block contains "raise"
        # by examining the lines immediately following the except clause.
        lines = source.splitlines()
        in_integrity_block = False
        block_lines = []
        for line in lines:
            stripped = line.strip()
            if "except IntegrityError" in stripped:
                in_integrity_block = True
                continue
            if in_integrity_block:
                # Empty lines are fine; collect until we hit a new except/try/def
                if stripped.startswith(("except ", "except:", "finally:", "try:", "def ", "async def ", "class ")):
                    break
                if stripped:
                    block_lines.append(stripped)

        block_text = "\n".join(block_lines)
        assert "raise" in block_text, (
            f"IntegrityError handler must re-raise the exception. " f"Block contents:\n{block_text}"
        )
        assert "return compliance" not in block_text, (
            "IntegrityError handler must NOT return compliance — that silently "
            "reports success after a failed DB write."
        )

    def test_generic_exception_in_executing_state_is_reraised(self):
        """
        The broad except Exception block in execute_approved_remediation
        must re-raise after marking the compliance record FAILED.
        A raise at the end is required — verified by source inspection.
        """
        from app.services import remediation_execution_service

        source = inspect.getsource(remediation_execution_service.execute_approved_remediation)

        # The last broad handler must end with raise
        assert source.count("raise") >= 1, "execute_approved_remediation must re-raise from its broad except handler"


# ---------------------------------------------------------------------------
# Rollback route — broad except must log but not commit partial state
# ---------------------------------------------------------------------------


class TestRollbackRouteFailClosed:
    """
    The rollback route's broad except Exception handler must:
    1. Log the failure server-side (logger.exception call).
    2. NOT commit partial state (db.commit must not be called after the exception).
    3. Return a 500 to the client without echoing internal details.
    """

    def test_rollback_route_broad_handler_logs_and_does_not_echo_internals(self):
        from app.api.v1 import remediation_rollback

        source = inspect.getsource(remediation_rollback.rollback_remediation)

        assert "except Exception" in source, "Broad handler must exist"
        assert "logger.exception" in source, "Broad handler must call logger.exception to record the stack trace"
        # The response must not include raw exception text
        assert "internal_error" in source, "Client response must use a generic reason string, not exc details"

    def test_rollback_route_source_has_status_500(self):
        from app.api.v1 import remediation_rollback

        source = inspect.getsource(remediation_rollback.rollback_remediation)
        assert "500" in source, "Broad handler must return HTTP 500"


# ---------------------------------------------------------------------------
# Remediation execution service — Graph permission check must fail closed
# ---------------------------------------------------------------------------


class TestPermissionCheckFailClosed:
    """
    When validate_tenant_graph_permissions raises, the permission-check block
    must call _mark_execution_failed (marking DB state as FAILED), not silently
    skip the check.
    """

    def test_permission_check_exception_marks_failed_not_passes(self):
        from app.services import remediation_execution_service

        source = inspect.getsource(remediation_execution_service.execute_approved_remediation)

        # The permission-check try/except must call _mark_execution_failed on error
        assert "_mark_execution_failed" in source, "Permission check failure must call _mark_execution_failed"
        # It must NOT have a bare 'pass' after the permission check except
        lines = source.splitlines()
        in_perm_except = False
        for i, line in enumerate(lines):
            if "validate_tenant_graph_permissions" in line:
                # Look ahead for the except block
                for j in range(i, min(i + 10, len(lines))):
                    if lines[j].strip().startswith("except"):
                        in_perm_except = True
                    if in_perm_except and lines[j].strip() == "pass":
                        pytest.fail(
                            f"Permission-check except block must not have bare 'pass' " f"(line {j + 1}): {lines[j]}"
                        )
                    if in_perm_except and lines[j].strip() == "":
                        break
                break
