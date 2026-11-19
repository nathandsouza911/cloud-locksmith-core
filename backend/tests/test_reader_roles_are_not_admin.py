"""Review R2-20: read-only directory roles do not make a user an admin.

Every directory role except "User" and "Guest" (neither is a directory role)
counted as privileged, so a Directory Readers member was scored as an admin:
IDENTITY_ADMIN_NO_MFA at CRITICAL, and one more role in the overprivileged count.
"""

import pytest

from app.services.detection.identity_overprivileged_admin import extract_directory_roles
from app.services.identity_scan_service import _build_user_context


@pytest.mark.parametrize("role", ["Directory Readers", "Message Center Reader", "Usage Summary Reports Reader"])
def test_reader_role_alone_is_not_admin(role):
    context = _build_user_context([{"id": "u1"}], {"u1": [{"role_id": "r1", "role_name": role}]})
    assert context["u1"]["is_admin"] is False


def test_reader_role_is_not_counted_as_an_admin_role():
    memberof = {
        "value": [
            {"@odata.type": "#microsoft.graph.directoryRole", "id": "r-ga", "displayName": "Global Administrator"},
            {"@odata.type": "#microsoft.graph.directoryRole", "id": "r-dr", "displayName": "Directory Readers"},
        ]
    }
    current, _ = extract_directory_roles(memberof)
    assert [r["role_name"] for r in current] == ["Global Administrator"]
