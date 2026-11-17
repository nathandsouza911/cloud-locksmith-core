"""The no-roles log line must not copy directory data from Graph into the logs.

Found in the 2026-11-17 live run: for every user without an admin role the scan logged the
user's full /memberOf response (group names, mail addresses, proxy addresses, SIDs).
"""

import logging

from app.services.detection.identity_overprivileged_admin import extract_directory_roles

LOGGER = "app.services.detection.identity_overprivileged_admin"
USER_ID = "4bba5943-8ab7-4d1e-b7f6-e6d9baa878ab"

MEMBER_OF = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryObjects",
    "value": [
        {
            "@odata.type": "#microsoft.graph.group",
            "id": "afcd2b09-c811-4b52-98e7-003fd7d6ec89",
            "displayName": "Fictional Sales Team",
            "description": "Fictional Company Ltd.",
            "mail": "sales-team@fictional.example",
            "proxyAddresses": ["SMTP:sales-team@fictional.example"],
            "securityIdentifier": "S-1-12-1-1111111111-2222222222-3333333333-4444444444",
        },
        {"@odata.type": "#microsoft.graph.group", "id": "b2", "displayName": "Second Group"},
    ],
}


def _log_text(caplog) -> str:
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        current, _ = extract_directory_roles(MEMBER_OF, user_id=USER_ID)
    assert current == []
    return "\n".join(r.getMessage() for r in caplog.records if r.name == LOGGER)


def test_no_roles_log_contains_no_directory_data(caplog):
    text = _log_text(caplog)
    for leaked in (
        "sales-team@fictional.example",
        "Fictional Sales Team",
        "Fictional Company Ltd.",
        "S-1-12-1-",
        "afcd2b09-c811-4b52-98e7-003fd7d6ec89",
        "Second Group",
    ):
        assert leaked not in text


def test_no_roles_log_keeps_user_id_and_object_counts(caplog):
    text = _log_text(caplog)
    assert "no_roles_returned" in text
    assert USER_ID in text
    assert "member_of_count=2" in text
    assert "group=2" in text
