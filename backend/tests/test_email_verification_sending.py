from unittest.mock import MagicMock, patch

from app.services.auth.email_verification import send_verification_email


def test_noop_prints_dev_url_when_resend_not_configured(capsys):
    with patch("app.services.auth.email_verification.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = None
        mock_settings.FRONTEND_URL = "http://localhost:3000"
        with patch("app.services.auth.email_verification.httpx.post") as mock_post:
            send_verification_email("user@example.com", "tok-123")
            mock_post.assert_not_called()

    captured = capsys.readouterr()
    assert "tok-123" in captured.out


def test_sends_via_resend_when_configured():
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    with patch("app.services.auth.email_verification.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = "re_test_key"
        mock_settings.FRONTEND_URL = "https://app.example.com"
        mock_settings.EMAIL_FROM_DOMAIN = "example.com"
        with patch("app.services.auth.email_verification.httpx.post", return_value=mock_response) as mock_post:
            send_verification_email("user@example.com", "tok-123")

    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args.args[0] == "https://api.resend.com/emails"
    assert call_args.kwargs["headers"]["Authorization"] == "Bearer re_test_key"
    payload = call_args.kwargs["json"]
    assert payload["to"] == ["user@example.com"]
    assert payload["from"] == "Cloud Locksmith <noreply@example.com>"
    assert "tok-123" in payload["text"]
    assert "https://app.example.com/verify-email?token=tok-123" in payload["text"]
    mock_response.raise_for_status.assert_called_once()


def test_never_raises_when_resend_call_fails():
    with patch("app.services.auth.email_verification.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = "re_test_key"
        mock_settings.FRONTEND_URL = "http://localhost:3000"
        with patch(
            "app.services.auth.email_verification.httpx.post",
            side_effect=Exception("resend down"),
        ):
            # Must not raise — signup already succeeded, a delivery failure
            # here must not turn into a 500 for the caller.
            send_verification_email("user@example.com", "tok-123")


def test_never_raises_when_resend_returns_error_status():
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = Exception("422 domain not verified")

    with patch("app.services.auth.email_verification.settings") as mock_settings:
        mock_settings.RESEND_API_KEY = "re_test_key"
        mock_settings.FRONTEND_URL = "http://localhost:3000"
        with patch("app.services.auth.email_verification.httpx.post", return_value=mock_response):
            send_verification_email("user@example.com", "tok-123")
