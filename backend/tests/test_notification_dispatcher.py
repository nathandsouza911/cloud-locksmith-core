import asyncio
from unittest.mock import AsyncMock, patch


from app.services.notification_dispatcher import (
    _send_via_resend,
    dispatch_alert,
    send_email,
)


def _mock_httpx_client(status_code: int = 200):
    mock_response = AsyncMock()
    mock_response.raise_for_status = lambda: None
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)
    return mock_client


class _Alert:
    def __init__(
        self,
        tenant_id="tenant-A",
        alert_type="control_regression",
        severity="critical",
        message="msg",
        details=None,
        alert_id=1,
    ):
        self.id = alert_id
        self.tenant_id = tenant_id
        self.alert_type = alert_type
        self.severity = severity
        self.message = message
        self.details = details or {}


class _Target:
    def __init__(self, channel, destination):
        self.channel = channel
        self.destination = destination


class _FakeExecuteResult:
    def __init__(self, targets):
        self._targets = targets

    def scalars(self):
        return self

    def all(self):
        return self._targets


class _FakeDb:
    def __init__(self, targets):
        self._targets = targets

    async def execute(self, statement):
        return _FakeExecuteResult(self._targets)


def test_send_via_resend_noop_when_api_key_not_configured():
    with patch("app.services.notification_dispatcher.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = None
        with patch("app.services.notification_dispatcher.httpx.AsyncClient") as mock_client_cls:
            asyncio.run(_send_via_resend(from_address="a@b.com", to="c@d.com", subject="s", text="t"))
            mock_client_cls.assert_not_called()


def test_send_via_resend_posts_to_resend_api_when_configured():
    mock_client = _mock_httpx_client()
    with patch("app.services.notification_dispatcher.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = "re_test_key"
        with patch("app.services.notification_dispatcher.httpx.AsyncClient", return_value=mock_client):
            asyncio.run(
                _send_via_resend(
                    from_address="Cloud Locksmith Alerts <alerts@example.com>",
                    to="ops@example.com",
                    subject="[Cloud Locksmith] CRITICAL alert",
                    text="body",
                )
            )

    mock_client.post.assert_called_once()
    call_args = mock_client.post.call_args
    assert call_args.args[0] == "https://api.resend.com/emails"
    assert call_args.kwargs["headers"]["Authorization"] == "Bearer re_test_key"
    payload = call_args.kwargs["json"]
    assert payload["from"] == "Cloud Locksmith Alerts <alerts@example.com>"
    assert payload["to"] == ["ops@example.com"]
    assert payload["subject"] == "[Cloud Locksmith] CRITICAL alert"
    assert payload["text"] == "body"


def test_send_email_delegates_to_resend_with_alert_content():
    mock_client = _mock_httpx_client()
    alert = _Alert(severity="critical", alert_type="control_regression", message="MFA regressed")
    with patch("app.services.notification_dispatcher.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = "re_test_key"
        with patch("app.services.notification_dispatcher.httpx.AsyncClient", return_value=mock_client):
            asyncio.run(send_email("ops@example.com", alert))

    payload = mock_client.post.call_args.kwargs["json"]
    assert payload["subject"] == "[Cloud Locksmith] CRITICAL alert"
    assert "MFA regressed" in payload["text"]


def test_dispatch_alert_continues_to_other_targets_when_one_fails():
    # First target (webhook) raises; second target (email) must still be attempted.
    mock_client = _mock_httpx_client()
    mock_client.post = AsyncMock(side_effect=[Exception("webhook down"), AsyncMock(raise_for_status=lambda: None)])

    targets = [_Target("webhook", "https://example.com/hook"), _Target("email", "ops@example.com")]
    db = _FakeDb(targets)
    alert = _Alert()

    with patch("app.services.notification_dispatcher.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = "re_test_key"
        with patch("app.services.notification_dispatcher.httpx.AsyncClient", return_value=mock_client):
            asyncio.run(dispatch_alert(db, alert))

    assert mock_client.post.call_count == 2
