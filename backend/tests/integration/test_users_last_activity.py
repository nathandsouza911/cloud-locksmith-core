"""Users page shows each user's last sign-in (live run 2026-11-13, defect L2).

/api/v1/users and /api/v1/users/{id} took last_activity from the local
users.last_login column, which nothing fills for Microsoft tenants, so every user
showed "No recent activity". The Graph user objects the routes already fetch carry
signInActivity; last_activity is now the latest of its timestamps, falling back to
the local column.
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch

from app.api.v1 import users as users_api
from app.db.models import User
from app.db.models.tenant import Tenant

TENANT = "tenant-users-activity"


def _graph_user(user_id: str, sign_in: dict | None) -> dict:
    user = {
        "id": user_id,
        "displayName": user_id,
        "userPrincipalName": f"{user_id}@contoso.example",
        "mail": None,
        "accountEnabled": True,
    }
    if sign_in is not None:
        user["signInActivity"] = sign_in
    return user


GRAPH_USERS = [
    _graph_user(
        "interactive",
        {
            "lastSignInDateTime": "2026-11-12T09:50:38Z",
            "lastNonInteractiveSignInDateTime": "2026-11-10T08:00:00Z",
            "lastSuccessfulSignInDateTime": "2026-11-12T09:50:38Z",
        },
    ),
    _graph_user(
        "non-interactive-latest",
        {
            "lastSignInDateTime": "2025-03-05T09:08:57Z",
            "lastNonInteractiveSignInDateTime": "2026-11-01T12:00:00Z",
        },
    ),
    _graph_user("never", {"lastSignInDateTime": None, "lastNonInteractiveSignInDateTime": None}),
    _graph_user("no-premium", None),
]


def _seed(db) -> Tenant:
    tenant = Tenant(id=TENANT, tenant_name="activity")
    db.add(tenant)
    db.commit()
    db.add(
        User(
            tenant_id=TENANT,
            external_id="no-premium",
            email="no-premium@contoso.example",
            last_login=datetime(2026, 10, 1, 7, 30),
        )
    )
    db.commit()
    return tenant


def _patched():
    return (
        patch.object(users_api, "fetch_users", new=AsyncMock(return_value=GRAPH_USERS)),
        patch.object(users_api, "graph_get", new=AsyncMock(return_value={"value": []})),
    )


def test_user_list_shows_the_latest_graph_sign_in(db_session):
    tenant = _seed(db_session)
    fetch, roles = _patched()
    with fetch, roles:
        rows = asyncio.run(users_api.list_users(db=db_session, current_tenant=tenant))
    by_id = {row["id"]: row["last_activity"] for row in rows}

    assert by_id["interactive"].startswith("2026-11-12T09:50:38")
    assert by_id["non-interactive-latest"].startswith("2026-11-01T12:00:00")
    assert by_id["never"] is None
    assert by_id["no-premium"].startswith("2026-10-01T07:30:00"), "falls back to the local column"


def test_single_user_shows_the_latest_graph_sign_in(db_session):
    tenant = _seed(db_session)
    fetch, roles = _patched()
    with fetch, roles:
        row = asyncio.run(users_api.get_user(user_id="interactive", db=db_session, current_tenant=tenant))
    assert row["last_activity"].startswith("2026-11-12T09:50:38")
