"""Recorded Microsoft Graph GET responses for the demo tenant.

``graph_get`` calls ``recorded_graph_get`` instead of the network when demo mode is on.
Only the read paths the demo pages use are recorded; anything else (and any other
tenant) raises, so a code path that would need live Graph fails closed.
"""

from app.demo import DEMO_TENANT_ID, DemoModeViolation
from functools import partial

from app.demo import fixtures as f
from app.services.graph_user_service import USERS_SELECT_WITH_SIGNIN
from app.simulation import tenant_reader as tr

_RECORDED = {
    "/directoryRoles?$expand=members": f.recorded_directory_roles,
    "/subscribedSkus": f.recorded_subscribed_skus,
    USERS_SELECT_WITH_SIGNIN: f.recorded_users,
    # CA coverage and Simulate Fix (app.simulation.tenant_reader).
    tr.CA_POLICIES_PATH: f.recorded_ca_policies,
    tr.SECURITY_DEFAULTS_PATH: f.recorded_security_defaults,
    tr.USERS_PATH: f.recorded_users,
    tr.DIRECTORY_ROLES_PATH: f.recorded_directory_roles_plain,
    tr.group_path(f.CA_EXCLUSIONS_GROUP_ID): f.recorded_ca_exclusions_group,
    tr.group_members_path(f.CA_EXCLUSIONS_GROUP_ID): f.recorded_ca_exclusions_members,
    **{tr.role_members_path(role_id): partial(f.recorded_role_members, role_id) for role_id in f._ROLE_MEMBERS},
}


def recorded_graph_get(tenant_id: str, path: str) -> dict:
    if tenant_id != DEMO_TENANT_ID:
        raise DemoModeViolation("Demo mode only serves the demo tenant")
    factory = _RECORDED.get(path)
    if factory is None:
        raise DemoModeViolation(f"Graph path not recorded for the demo: {path}")
    return factory()
