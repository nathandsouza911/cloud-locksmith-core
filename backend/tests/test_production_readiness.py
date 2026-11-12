"""
Production-readiness tests covering:
- JWT denylist backed by Redis (with in-memory fallback)
- Rate limiting via Redis (with in-memory fallback)
- CA policy engine returns verified=False on drift when auto-remediation is off
- get_valid_access_token reads exclusively from TenantOAuth
"""

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# JWT Denylist
# ---------------------------------------------------------------------------


class TestTokenDenylistRedis:
    def test_revoke_writes_to_redis(self):
        mock_redis = MagicMock()
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.services.auth import token_denylist

            exp = time.time() + 3600
            token_denylist.revoke("jti-abc", exp)
            mock_redis.setex.assert_called_once()
            key = mock_redis.setex.call_args[0][0]
            assert key == "denylist:jti-abc"

    def test_is_revoked_checks_redis(self):
        mock_redis = MagicMock()
        mock_redis.exists.return_value = 1
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.services.auth import token_denylist

            assert token_denylist.is_revoked("jti-abc") is True
            mock_redis.exists.assert_called_once_with("denylist:jti-abc")

    def test_not_revoked_when_redis_returns_zero(self):
        mock_redis = MagicMock()
        mock_redis.exists.return_value = 0
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.services.auth import token_denylist

            assert token_denylist.is_revoked("jti-xyz") is False

    def test_revoke_falls_back_to_memory_on_redis_error(self):
        mock_redis = MagicMock()
        mock_redis.setex.side_effect = ConnectionError("redis down")
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.services.auth import token_denylist

            # Clear any prior fallback state
            token_denylist._fallback.clear()
            exp = time.time() + 3600
            token_denylist.revoke("jti-fallback", exp)
            assert "jti-fallback" in token_denylist._fallback

    def test_is_revoked_falls_back_to_memory_on_redis_error(self):
        mock_redis = MagicMock()
        mock_redis.exists.side_effect = ConnectionError("redis down")
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.services.auth import token_denylist

            token_denylist._fallback.clear()
            token_denylist._fallback["jti-mem"] = time.time() + 3600
            assert token_denylist.is_revoked("jti-mem") is True

    def test_expired_token_not_revoked_in_memory(self):
        from app.services.auth import token_denylist

        token_denylist._fallback.clear()
        # Expired in the past
        token_denylist._fallback["jti-old"] = time.time() - 1

        mock_redis = MagicMock()
        mock_redis.exists.side_effect = ConnectionError("redis down")
        with patch("app.core.redis_client.redis_client", mock_redis):
            assert token_denylist.is_revoked("jti-old") is False

    def test_revoke_skipped_for_already_expired_token(self):
        mock_redis = MagicMock()
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.services.auth import token_denylist

            # exp already in the past — should be a no-op
            token_denylist.revoke("jti-past", time.time() - 10)
            mock_redis.setex.assert_not_called()

    def test_production_redis_read_failure_fails_closed(self):
        mock_redis = MagicMock()
        mock_redis.exists.side_effect = ConnectionError("redis down")
        with (
            patch("app.core.redis_client.redis_client", mock_redis),
            patch("app.services.auth.token_denylist.settings") as mock_settings,
        ):
            from app.services.auth import token_denylist

            mock_settings.ENVIRONMENT = "production"
            token_denylist._fallback.clear()
            token_denylist._fallback["jti-mem"] = time.time() + 3600

            assert token_denylist.is_revoked("jti-mem") is True


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------


class TestRateLimiterRedis:
    def test_redis_blocks_after_limit(self):
        mock_redis = MagicMock()
        # Simulate counter already at limit + 1
        mock_redis.incr.return_value = 61
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.middleware import rate_limit

            result = rate_limit._try_redis_incr("1.2.3.4", 60, 60)
            assert result is True

    def test_redis_allows_under_limit(self):
        mock_redis = MagicMock()
        mock_redis.incr.return_value = 1
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.middleware import rate_limit

            result = rate_limit._try_redis_incr("1.2.3.4", 60, 60)
            assert result is False
            # First hit must set the expiry window
            mock_redis.expire.assert_called_once()

    def test_redis_failure_returns_none(self):
        mock_redis = MagicMock()
        mock_redis.incr.side_effect = ConnectionError("redis down")
        with patch("app.core.redis_client.redis_client", mock_redis):
            from app.middleware import rate_limit

            result = rate_limit._try_redis_incr("1.2.3.4", 60, 60)
            assert result is None

    def test_memory_fallback_blocks_after_limit(self):
        from app.middleware import rate_limit

        rate_limit._counters.clear()
        ip = "10.0.0.1"
        # Fill the window
        now = time.time()
        rate_limit._counters[ip] = [now - 1] * 60
        assert rate_limit._check_memory(ip, 60, 60) is True

    def test_memory_fallback_allows_under_limit(self):
        from app.middleware import rate_limit

        rate_limit._counters.clear()
        assert rate_limit._check_memory("10.0.0.2", 60, 60) is False

    def test_production_redis_failure_blocks_request(self):
        mock_redis = MagicMock()
        mock_redis.incr.side_effect = ConnectionError("redis down")
        with (
            patch("app.core.redis_client.redis_client", mock_redis),
            patch("app.middleware.rate_limit.settings") as mock_settings,
        ):
            from app.middleware import rate_limit

            mock_settings.ENVIRONMENT = "production"
            assert rate_limit._try_redis_incr("1.2.3.4", 5, 60) is True


def test_production_startup_requires_redis():
    from app.core import redis_client as redis_module

    mock_redis = MagicMock()
    mock_redis.ping.side_effect = ConnectionError("redis down")
    with (
        patch("app.core.redis_client.settings") as mock_settings,
        patch("app.core.redis_client.redis_client", mock_redis),
    ):
        mock_settings.ENVIRONMENT = "production"
        with pytest.raises(RuntimeError) as exc_info:
            redis_module.verify_redis_available_in_production()

    assert "Redis is required in production" in str(exc_info.value)


# ---------------------------------------------------------------------------
# CA Policy Engine — drift returns verified=False
# ---------------------------------------------------------------------------


class TestCaDriftHandling:
    @pytest.mark.asyncio
    async def test_drift_returns_verified_false_when_auto_remediation_off(self):
        from app.services import ca_policy_engine

        mock_state = MagicMock()
        mock_state.mode = "audit"  # valid modes: audit / enforced; apply_control defaults to audit
        mock_state.rollout_phase = "full"
        mock_state.rollout_percentage = 100
        mock_state.target_group_id = None
        mock_state.policy_version = 1

        mock_tenant = MagicMock()
        mock_tenant.id = "tenant-123"
        mock_tenant.provider = "microsoft"

        MagicMock()

        async def fake_policy_matches(**_kwargs):
            return False  # drift detected

        with (
            patch.object(ca_policy_engine, "get_control_state", new=AsyncMock(return_value=mock_state)),
            patch.object(ca_policy_engine, "policy_matches_expected", new=fake_policy_matches),
            patch.object(ca_policy_engine, "list_break_glass_user_ids", return_value=["bg-1"]),
            patch.object(ca_policy_engine, "_validate_break_glass_accounts", new=AsyncMock()),
            patch.object(ca_policy_engine, "check_conditional_access_license", new=AsyncMock(return_value=True)),
            patch.object(ca_policy_engine, "build_policy", return_value={}),
            patch.object(ca_policy_engine, "_normalize_policy", return_value={}),
            patch("app.services.ca_policy_engine.settings") as mock_settings,
        ):
            mock_settings.ENABLE_AUTO_REMEDIATION = False
            result = await ca_policy_engine.apply_control(
                db=MagicMock(),
                tenant=mock_tenant,
                control_id="CA_MFA_ALL_USERS",
            )

        assert result["status"] == "drift_detected"
        assert result["verified"] is False
        assert result["control_id"] is not None

    @pytest.mark.asyncio
    async def test_no_drift_returns_verified_true(self):
        from app.services import ca_policy_engine

        mock_state = MagicMock()
        mock_state.mode = "audit"  # valid modes: audit / enforced; apply_control defaults to audit
        mock_state.rollout_phase = "full"
        mock_state.rollout_percentage = 100
        mock_state.target_group_id = None
        mock_state.policy_version = 1
        mock_state.status = "success"

        mock_tenant = MagicMock()
        mock_tenant.id = "tenant-456"
        mock_tenant.provider = "microsoft"

        async def fake_policy_matches(**_kwargs):
            return True  # no drift

        async def fake_calculate_affected(**_kwargs):
            return 5

        with (
            patch.object(ca_policy_engine, "get_control_state", new=AsyncMock(return_value=mock_state)),
            patch.object(ca_policy_engine, "policy_matches_expected", new=fake_policy_matches),
            patch.object(ca_policy_engine, "list_break_glass_user_ids", return_value=["bg-1"]),
            patch.object(ca_policy_engine, "_validate_break_glass_accounts", new=AsyncMock()),
            patch.object(ca_policy_engine, "check_conditional_access_license", new=AsyncMock(return_value=True)),
            patch.object(ca_policy_engine, "build_policy", return_value={}),
            patch.object(ca_policy_engine, "_normalize_policy", return_value={}),
            patch.object(ca_policy_engine, "calculate_affected_users", new=fake_calculate_affected),
            patch("app.services.ca_policy_engine.settings") as mock_settings,
        ):
            mock_settings.ENABLE_AUTO_REMEDIATION = False
            result = await ca_policy_engine.apply_control(
                db=MagicMock(),
                tenant=mock_tenant,
                control_id="CA_MFA_ALL_USERS",
            )

        assert result["status"] == "no-op"
        assert result["verified"] is True


# ---------------------------------------------------------------------------
# Token storage — get_valid_access_token reads from TenantOAuth only
# ---------------------------------------------------------------------------


class TestTokenStorageUnification:
    @pytest.mark.asyncio
    async def test_get_valid_access_token_reads_from_tenant_oauth(self):
        from app.services import token_manager

        mock_tenant = MagicMock()
        mock_tenant.id = "tenant-tok"

        expires_future = datetime.now(timezone.utc) + timedelta(hours=2)
        mock_oauth_record = MagicMock()
        mock_oauth_record.access_token = "encrypted-at"
        mock_oauth_record.refresh_token = None
        mock_oauth_record.expires_at = expires_future.replace(tzinfo=None)
        mock_oauth_record.scopes = ["User.Read"]

        with (
            patch.object(token_manager, "_get_tenant_record", new=AsyncMock(return_value=mock_tenant)),
            patch.object(token_manager, "_get_tenant_oauth_record", new=AsyncMock(return_value=mock_oauth_record)),
            patch.object(token_manager, "_validate_existing_token_binding", new=AsyncMock()),
            patch("app.services.token_manager.decrypt_str", return_value="plaintext-access-token"),
        ):
            result = await token_manager.get_valid_access_token("tenant-tok", db=MagicMock())

        assert result == "plaintext-access-token"

    @pytest.mark.asyncio
    async def test_get_valid_access_token_raises_when_tenant_oauth_missing(self):
        from fastapi import HTTPException
        from app.services import token_manager

        mock_tenant = MagicMock()
        mock_tenant.id = "tenant-no-oauth"

        with (
            patch.object(token_manager, "_get_tenant_record", new=AsyncMock(return_value=mock_tenant)),
            patch.object(token_manager, "_get_tenant_oauth_record", new=AsyncMock(return_value=None)),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await token_manager.get_valid_access_token("tenant-no-oauth", db=MagicMock())

        assert exc_info.value.status_code == 401
        assert "TENANT_REAUTH_REQUIRED" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_store_tenant_token_raises_when_oauth_record_missing(self):
        from fastapi import HTTPException
        from app.services import token_manager

        mock_tenant = MagicMock()
        mock_tenant.id = "tenant-no-record"

        token_payload = {
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "expires_at": datetime.now(timezone.utc).isoformat(),
            "scopes": ["User.Read"],
        }

        with patch.object(token_manager, "_get_tenant_oauth_record", new=AsyncMock(return_value=None)):
            with pytest.raises(HTTPException) as exc_info:
                await token_manager._store_tenant_token(db=MagicMock(), tenant=mock_tenant, token_payload=token_payload)

        assert exc_info.value.status_code == 401
