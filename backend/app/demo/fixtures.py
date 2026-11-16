"""The fictional demo tenant: people, licence and recorded scan results.

Every name, address and ID here is invented. Addresses use the reserved
``.example`` domain. Object IDs are fake GUIDs in the ``00000000-0000-4000-8000-...`` range.
"""

from app.demo import DEMO_OWNER_EMAIL, DEMO_OWNER_OID, DEMO_TENANT_DOMAIN

GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"  # public Entra role template
USER_ADMIN_ROLE_TEMPLATE_ID = "fe930be7-5e62-47db-91af-98c3a49a38b1"  # public Entra role template


def _oid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


# (external_id, display name, user principal name, is_admin, days since last sign-in or None)
DIRECTORY_USERS = [
    (DEMO_OWNER_OID, "Demo Owner (fictional)", DEMO_OWNER_EMAIL, True, 0),
    (_oid(101), "Avery Quill (fictional)", f"avery.quill@{DEMO_TENANT_DOMAIN}", True, 2),
    (_oid(102), "Bram Okafor (fictional)", f"bram.okafor@{DEMO_TENANT_DOMAIN}", False, 1),
    (_oid(103), "Cleo Marsh (fictional)", f"cleo.marsh@{DEMO_TENANT_DOMAIN}", False, 3),
    (_oid(104), "Dev Raman (fictional)", f"dev.raman@{DEMO_TENANT_DOMAIN}", False, 140),
    (_oid(105), "Elin Strand (fictional)", f"elin.strand@{DEMO_TENANT_DOMAIN}", False, 5),
    (_oid(106), "Farid Haddad (fictional)", f"farid.haddad@{DEMO_TENANT_DOMAIN}", False, 97),
    (_oid(107), "Gwen Ashby (fictional)", f"gwen.ashby@{DEMO_TENANT_DOMAIN}", False, 8),
    (_oid(108), "Hiro Tanaka (fictional)", f"hiro.tanaka@{DEMO_TENANT_DOMAIN}", False, None),
]

ADMIN_IDS = [u[0] for u in DIRECTORY_USERS if u[3]]
OVERPRIVILEGED_USER_ID = _oid(101)
UNUSED_USER_IDS = [_oid(104), _oid(106)]
NO_MFA_USER_ID = _oid(108)
# Member of the "CA exclusions" group: left out of the (report-only) all-users MFA policy.
EXCLUDED_USER_ID = _oid(107)
CA_EXCLUSIONS_GROUP_ID = _oid(701)
_ROLE_MEMBERS = {
    _oid(901): ("Global Administrator", GLOBAL_ADMIN_ROLE_TEMPLATE_ID, ADMIN_IDS),
    _oid(902): ("User Administrator", USER_ADMIN_ROLE_TEMPLATE_ID, [OVERPRIVILEGED_USER_ID]),
}
_USER_TYPE = "#microsoft.graph.user"


def recorded_users(now=None) -> dict:
    from datetime import datetime, timedelta, timezone

    now = now or datetime.now(timezone.utc)
    users = []
    for external_id, name, upn, _is_admin, days in DIRECTORY_USERS:
        last = None if days is None else (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        users.append(
            {
                "id": external_id,
                "displayName": name,
                "mail": upn,
                "userPrincipalName": upn,
                "accountEnabled": True,
                "userType": "Member",
                "createdDateTime": "2025-01-15T09:00:00Z",
                "signInActivity": {"lastSignInDateTime": last},
            }
        )
    return {"value": users}


def recorded_directory_roles() -> dict:
    """/directoryRoles?$expand=members (Users page)."""
    return {
        "value": [
            {
                "id": role_id,
                "displayName": name,
                "roleTemplateId": template_id,
                "members": [{"id": uid, "@odata.type": _USER_TYPE} for uid in member_ids],
            }
            for role_id, (name, template_id, member_ids) in _ROLE_MEMBERS.items()
        ]
    }


def recorded_directory_roles_plain() -> dict:
    """/directoryRoles (CA coverage reads members per role)."""
    return {
        "value": [
            {"id": role_id, "displayName": name, "roleTemplateId": template_id}
            for role_id, (name, template_id, _members) in _ROLE_MEMBERS.items()
        ]
    }


def recorded_role_members(role_id: str) -> dict:
    return {"value": [{"id": uid, "@odata.type": _USER_TYPE} for uid in _ROLE_MEMBERS[role_id][2]]}


def recorded_ca_policies() -> dict:
    """Consistent with the seeded findings: admin MFA enforced (CA_MFA_ADMINS passes),
    all-users MFA only report-only and excluding a group (CA_MFA_ALL_USERS fails), no
    legacy-authentication block (CA_LEGACY_AUTH_BLOCK fails)."""
    common = {"applications": {"includeApplications": ["All"], "excludeApplications": []}, "clientAppTypes": ["all"]}
    return {
        "value": [
            {
                "id": _oid(601),
                "displayName": "Require MFA for administrators (fictional)",
                "state": "enabled",
                "conditions": {
                    "users": {"includeRoles": [GLOBAL_ADMIN_ROLE_TEMPLATE_ID, USER_ADMIN_ROLE_TEMPLATE_ID]},
                    **common,
                },
                "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
            },
            {
                "id": _oid(602),
                "displayName": "Require MFA for all users (fictional)",
                "state": "enabledForReportingButNotEnforced",
                "conditions": {
                    "users": {"includeUsers": ["All"], "excludeGroups": [CA_EXCLUSIONS_GROUP_ID]},
                    **common,
                },
                "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
            },
        ]
    }


def recorded_security_defaults() -> dict:
    return {"id": "00000000-0000-0000-0000-000000000000", "isEnabled": False}


def recorded_ca_exclusions_group() -> dict:
    return {"id": CA_EXCLUSIONS_GROUP_ID, "displayName": "CA exclusions"}


def recorded_ca_exclusions_members() -> dict:
    return {"value": [{"id": EXCLUDED_USER_ID, "@odata.type": _USER_TYPE}]}


def recorded_subscribed_skus() -> dict:
    # One fictional SKU carrying the Entra ID P1 service plan, so Conditional Access
    # controls are evaluated (not NOT_EVALUATED) and the CA fix preview is offered.
    return {
        "value": [
            {
                "skuId": _oid(801),
                "skuPartNumber": "AAD_PREMIUM",
                "servicePlans": [{"servicePlanName": "AAD_PREMIUM"}],
                "prepaidUnits": {"enabled": len(DIRECTORY_USERS)},
                "consumedUnits": len(DIRECTORY_USERS),
            }
        ]
    }
