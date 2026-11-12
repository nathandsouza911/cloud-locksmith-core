"""Recorded Microsoft Graph GET responses for the demo tenant.

``graph_get`` calls ``recorded_graph_get`` instead of the network when demo mode is on.
Only the read paths the demo pages use are recorded; anything else (and any other
tenant) raises, so a code path that would need live Graph fails closed.
"""

from app.demo import DEMO_TENANT_ID, DemoModeViolation
from app.demo.fixtures import recorded_directory_roles, recorded_subscribed_skus, recorded_users
from app.services.graph_user_service import USERS_SELECT_WITH_SIGNIN

_RECORDED = {
    "/directoryRoles?$expand=members": recorded_directory_roles,
    "/subscribedSkus": recorded_subscribed_skus,
    USERS_SELECT_WITH_SIGNIN: recorded_users,
}


def recorded_graph_get(tenant_id: str, path: str) -> dict:
    if tenant_id != DEMO_TENANT_ID:
        raise DemoModeViolation("Demo mode only serves the demo tenant")
    factory = _RECORDED.get(path)
    if factory is None:
        raise DemoModeViolation(f"Graph path not recorded for the demo: {path}")
    return factory()
