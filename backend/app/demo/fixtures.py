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
                "createdDateTime": "2025-01-15T09:00:00Z",
                "signInActivity": {"lastSignInDateTime": last},
            }
        )
    return {"value": users}


def recorded_directory_roles() -> dict:
    return {
        "value": [
            {
                "id": _oid(901),
                "displayName": "Global Administrator",
                "roleTemplateId": GLOBAL_ADMIN_ROLE_TEMPLATE_ID,
                "members": [{"id": uid, "@odata.type": "#microsoft.graph.user"} for uid in ADMIN_IDS],
            },
            {
                "id": _oid(902),
                "displayName": "User Administrator",
                "roleTemplateId": USER_ADMIN_ROLE_TEMPLATE_ID,
                "members": [{"id": OVERPRIVILEGED_USER_ID, "@odata.type": "#microsoft.graph.user"}],
            },
        ]
    }


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
