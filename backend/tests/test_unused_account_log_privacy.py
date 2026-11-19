"""Review R2-20: the full UPN was logged at INFO for every user on every scan."""

import logging
from datetime import datetime, timezone

from app.services.activity.unused_account_detector import evaluate_unused_account


def test_evaluation_log_carries_the_user_id_not_the_upn(caplog):
    user = {
        "id": "u1",
        "userPrincipalName": "alice@contoso.com",
        "displayName": "Alice",
        "accountEnabled": True,
        "createdDateTime": "2020-01-01T00:00:00Z",
    }
    with caplog.at_level(logging.INFO, logger="app.services.activity.unused_account_detector"):
        evaluate_unused_account(user, None, workload_available=False, now=datetime(2026, 5, 29, tzinfo=timezone.utc))

    assert "alice@contoso.com" not in caplog.text
    assert "user_id=u1" in caplog.text
