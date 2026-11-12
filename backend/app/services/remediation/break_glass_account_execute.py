from __future__ import annotations

import secrets
import string
from urllib.parse import quote

from sqlalchemy.orm import Session

from app.db.models.break_glass_account import BreakGlassAccount


GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
GLOBAL_ADMIN_ROLE_NAME = "Global Administrator"
BREAK_GLASS_PREFIX = "[BREAK-GLASS]"
BREAK_GLASS_ACCOUNT_SPECS = (
    {
        "display_name": f"{BREAK_GLASS_PREFIX} Break Glass Account 1",
        "mail_nickname": "bg-admin-1",
    },
    {
        "display_name": f"{BREAK_GLASS_PREFIX} Break Glass Account 2",
        "mail_nickname": "bg-admin-2",
    },
)


def generate_strong_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+" for c in password)
        ):
            return password


def _policy_targets_users(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    return any(
        bool(users.get(field))
        for field in (
            "includeUsers",
            "includeRoles",
            "includeGroups",
            "excludeUsers",
            "excludeRoles",
            "excludeGroups",
        )
    )


def _policy_with_excluded_users(policy: dict, excluded_user_ids: list[str]) -> tuple[dict, bool]:
    conditions = dict(policy.get("conditions") or {})
    users = dict(conditions.get("users") or {})
    existing_excluded = [
        user_id for user_id in (users.get("excludeUsers") or []) if isinstance(user_id, str) and user_id
    ]
    merged_excluded = list(dict.fromkeys([*existing_excluded, *excluded_user_ids]))
    changed = merged_excluded != existing_excluded
    users["excludeUsers"] = merged_excluded
    conditions["users"] = users
    payload = dict(policy)
    payload["conditions"] = conditions
    return payload, changed


def _find_initial_domain(domains_payload: dict, tenant_domain: str | None) -> str:
    if isinstance(tenant_domain, str) and tenant_domain.strip().endswith(".onmicrosoft.com"):
        return tenant_domain.strip()

    values = domains_payload.get("value", []) if isinstance(domains_payload, dict) else []
    initial = None
    fallback = None
    for item in values:
        if not isinstance(item, dict):
            continue
        domain_id = item.get("id")
        if not isinstance(domain_id, str) or not domain_id.endswith(".onmicrosoft.com"):
            continue
        fallback = fallback or domain_id
        if item.get("isInitial") is True:
            initial = domain_id
            break
    if initial:
        return initial
    if fallback:
        return fallback
    raise ValueError("Unable to determine tenant onmicrosoft.com domain")


async def _lookup_user_by_upn(graph_client, user_principal_name: str) -> dict | None:
    escaped_upn = user_principal_name.replace("'", "''")
    payload = await graph_client.get(
        "/users?$filter="
        + quote(f"userPrincipalName eq '{escaped_upn}'", safe="=$' ")
        + "&$select=id,displayName,userPrincipalName"
    )
    values = payload.get("value", []) if isinstance(payload, dict) else []
    for item in values:
        if isinstance(item, dict) and item.get("id"):
            return item
    return None


class BreakGlassAccountExecutor:
    async def _resolve_initial_domain(self, graph_client) -> str:
        domains_payload = await graph_client.get("/domains?$select=id,isInitial")
        return _find_initial_domain(domains_payload, getattr(graph_client.tenant, "domain", None))

    async def _resolve_global_admin_role(self, graph_client) -> dict:
        payload = await graph_client.get("/directoryRoles")
        roles = payload.get("value", []) if isinstance(payload, dict) else []
        for role in roles:
            if not isinstance(role, dict):
                continue
            if role.get("displayName") == GLOBAL_ADMIN_ROLE_NAME:
                return role
            if role.get("roleTemplateId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID:
                return role
        raise ValueError("Global Administrator directory role is unavailable")

    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        initial_domain = await self._resolve_initial_domain(graph_client)
        global_admin_role = await self._resolve_global_admin_role(graph_client)
        policies = await graph_client.list_conditional_access_policies()
        tenant = graph_client.tenant
        db: Session = graph_client.db
        existing_rows = db.query(BreakGlassAccount).filter(BreakGlassAccount.tenant_id == tenant.id).all()
        planned_accounts = [
            {
                **spec,
                "user_principal_name": f"{spec['mail_nickname']}@{initial_domain}",
            }
            for spec in BREAK_GLASS_ACCOUNT_SPECS
        ]
        restorable_policies = []
        for policy in policies:
            if not isinstance(policy, dict) or not policy.get("id") or not _policy_targets_users(policy):
                continue
            restorable_policies.append(policy)

        return {
            "tenant_id": tenant.id,
            "tenant_domain": initial_domain,
            "planned_accounts": planned_accounts,
            "global_admin_role_id": global_admin_role.get("id"),
            "conditional_access_policies": restorable_policies,
            "existing_break_glass_records": [
                {
                    "id": row.id,
                    "user_external_id": row.user_external_id,
                }
                for row in existing_rows
            ],
            "asset_flags": dict(getattr(tenant, "asset_flags", None) or {}),
            "created_accounts": [],
        }

    async def preview(self, graph_client, evidence: dict) -> dict:
        snapshot = await self.build_snapshot(graph_client, evidence)
        return {
            "control_id": "IDENTITY_BREAK_GLASS_ACCOUNT",
            "mode": "tenant_bootstrap",
            "dry_run_supported": True,
            "changes": [
                {
                    "action": "CREATE_USERS",
                    "accounts": [
                        {
                            "display_name": account["display_name"],
                            "user_principal_name": account["user_principal_name"],
                            "global_admin": True,
                            "marker": BREAK_GLASS_PREFIX,
                        }
                        for account in snapshot["planned_accounts"]
                    ],
                },
                {
                    "action": "EXCLUDE_FROM_CONDITIONAL_ACCESS",
                    "policy_ids": [policy.get("id") for policy in snapshot["conditional_access_policies"]],
                    "policy_count": len(snapshot["conditional_access_policies"]),
                },
                {
                    "action": "STORE_BREAK_GLASS_METADATA",
                    "storage": "break_glass_accounts_table_and_tenant_asset_flags",
                },
            ],
            "rollback": {
                "strategy": "not_supported",
            },
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        snapshot = dict(evidence.get("snapshot") or {})
        planned_accounts = snapshot.get("planned_accounts") or []
        role_id = snapshot.get("global_admin_role_id")
        if not planned_accounts or not role_id:
            raise ValueError("Break-glass snapshot is incomplete")

        created_accounts: list[dict] = []
        one_time_credentials: list[dict] = []
        for account in planned_accounts:
            upn = account["user_principal_name"]
            if await _lookup_user_by_upn(graph_client, upn):
                raise ValueError(f"User already exists: {upn}")

        for account in planned_accounts:
            upn = account["user_principal_name"]
            password = generate_strong_password()
            created_user = await graph_client.create_user(
                {
                    "accountEnabled": True,
                    "displayName": account["display_name"],
                    "mailNickname": account["mail_nickname"],
                    "userPrincipalName": upn,
                    "passwordProfile": {
                        "forceChangePasswordNextSignIn": False,
                        "password": password,
                    },
                }
            )
            user_id = created_user.get("id")
            if not isinstance(user_id, str) or not user_id:
                raise RuntimeError(f"Graph did not return a user id for {upn}")

            await graph_client.add_directory_role_member(role_id, user_id)
            created_accounts.append(
                {
                    "user_id": user_id,
                    "display_name": account["display_name"],
                    "user_principal_name": upn,
                }
            )
            one_time_credentials.append(
                {
                    "username": upn,
                    "user_principal_name": upn,
                    "display_name": account["display_name"],
                    "password": password,
                    "password_revealed": True,
                }
            )
            graph_client.db.add(
                BreakGlassAccount(
                    tenant_id=graph_client.tenant.id,
                    user_external_id=user_id,
                )
            )

        created_user_ids = [account["user_id"] for account in created_accounts]
        for policy in snapshot.get("conditional_access_policies") or []:
            policy_id = policy.get("id")
            if not isinstance(policy_id, str) or not policy_id:
                continue
            patched_policy, changed = _policy_with_excluded_users(policy, created_user_ids)
            if not changed:
                continue
            await graph_client.update_conditional_access_policy(policy_id, patched_policy)

        tenant_asset_flags = dict(getattr(graph_client.tenant, "asset_flags", None) or {})
        tenant_asset_flags["break_glass_accounts"] = [
            {
                "user_id": account["user_id"],
                "user_principal_name": account["user_principal_name"],
                "is_break_glass": True,
            }
            for account in created_accounts
        ]
        graph_client.tenant.asset_flags = tenant_asset_flags

        return {
            "status": "SUCCESS",
            "snapshot": {
                **snapshot,
                "created_accounts": created_accounts,
            },
            "response_payload": {
                "created_accounts": one_time_credentials,
                "credentials_delivery": "Passwords were generated but are not persisted by Cloud Locksmith.",
                "password_revealed": True,
            },
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        return None
