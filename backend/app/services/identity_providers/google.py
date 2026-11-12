from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from urllib.parse import quote

import httpx

from app.services.graph_client import GraphAPIError, GraphBlockedError
from app.services.identity_providers.base import (
    IdentityProviderAdapter,
    build_control_capability,
    default_control_capabilities,
)
from app.services.remediation.lifecycle import BlockReason

logger = logging.getLogger(__name__)


GOOGLE_DIRECTORY_BASE = "https://admin.googleapis.com/admin/directory/v1"
GOOGLE_DEFAULT_CUSTOMER = "my_customer"
GOOGLE_REQUEST_TIMEOUT_SECONDS = 30
GOOGLE_MAX_RETRIES = 3
GOOGLE_MAX_PAGES = 1000
GOOGLE_RETRY_BASE_DELAY_SECONDS = 0.5
GOOGLE_ADMIN_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement",
)
GOOGLE_REQUIRED_SERVICE_ACCOUNT_KEYS = ("client_email", "private_key")
GOOGLE_USER_FIELDS = "id,primaryEmail,name/fullName,isAdmin,suspended,lastLoginTime,isEnrolledIn2Sv"


def _google_error_category(status_code: int) -> str:
    if status_code == 404:
        return "not_found"
    if status_code == 403:
        return "permission_denied"
    if status_code == 429:
        return "rate_limited"
    if status_code == 400:
        return "invalid_payload"
    if status_code >= 500:
        return "server_error"
    return "unknown"


class GoogleAPIError(GraphAPIError):
    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        method: str = "GET",
        path: str = "",
        response_body: str | None = None,
        category: str | None = None,
    ) -> None:
        self.message = message
        super().__init__(
            method=method,
            path=path,
            status_code=status_code,
            response_body=response_body or message,
            category=category or _google_error_category(status_code),
            token_claims={},
        )


class GoogleWorkspaceAdapter(IdentityProviderAdapter):
    def get_control_capabilities(self) -> dict[str, dict[str, Any]]:
        capabilities = default_control_capabilities()
        capabilities.update(
            {
                "IDENTITY_USER_NO_MFA": build_control_capability(
                    detect=True,
                    remediate=False,
                    auto_remediate=False,
                    requires_approval=False,
                    notes=(
                        "Google Workspace can detect 2-Step Verification enrollment, but it does not support Conditional Access-style MFA enforcement via API. "
                        "Use advisory guidance; optional account disable is not the default action."
                    ),
                ),
                "IDENTITY_ADMIN_NO_MFA": build_control_capability(
                    detect=True,
                    remediate=False,
                    auto_remediate=False,
                    requires_approval=True,
                    notes=(
                        "Google Workspace can identify admins without 2-Step Verification, but this backend does not implement the provider-specific role-removal or disable-account remediation path for this control yet. TODO"
                    ),
                ),
                "IDENTITY_UNUSED_ACCOUNT": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=True,
                    requires_approval=False,
                    notes="Detects dormant accounts from lastLoginTime and disables accounts directly.",
                ),
                "IDENTITY_OVERPRIVILEGED_ADMIN": build_control_capability(
                    detect=True,
                    remediate=True,
                    auto_remediate=True,
                    requires_approval=False,
                    notes="Removes Google Workspace directory roles with a safeguard that blocks removing the last remaining super admin.",
                ),
                "IDENTITY_RISKY_OAUTH_APP": build_control_capability(
                    detect=True,
                    remediate=False,
                    auto_remediate=False,
                    requires_approval=True,
                    notes=(
                        "Google user-token revocation requires explicit approval, but this backend has not yet wired provider-neutral token inventory and revoke execution for this control. TODO"
                    ),
                ),
                "TENANT_CONDITIONAL_ACCESS_POLICY": build_control_capability(
                    detect=False,
                    remediate=False,
                    auto_remediate=False,
                    requires_approval=False,
                    notes="Google Workspace does not support Conditional Access policies",
                ),
            }
        )
        return capabilities

    async def ingest_tenant_data(self) -> None:
        users = await self.list_users()
        logger.info(
            "google_workspace_ingestion_seed tenant_id=%s users_fetched=%s",
            getattr(self.tenant, "id", None),
            len(users),
        )
        # TODO: Add Google Drive / Workspace asset ingestion once the broader
        # ingestion pipeline supports non-Microsoft providers.

    async def get(self, path: str) -> dict[str, Any]:
        return await self._request("GET", path)

    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", path, payload=payload)

    async def patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request("PATCH", path, payload=payload)

    async def delete(self, path: str) -> dict[str, Any]:
        return await self._request("DELETE", path)

    async def ensure_permissions(
        self,
        *,
        required_permissions: set[str],
        missing_permission_message: str,
    ) -> dict[str, Any]:
        try:
            await self.list_users()
            await self.list_directory_roles()
        except GoogleAPIError as exc:
            raise GraphBlockedError(
                status="blocked",
                reason=BlockReason.INSUFFICIENT_PERMISSIONS.value,
                message=missing_permission_message or exc.message,
                tenant_id=getattr(self.tenant, "id", None),
            ) from exc

        return {
            "status": "ok",
            "provider": "google",
            "delegated_admin": self._delegated_admin_email(),
            "required_permissions": sorted(required_permissions),
        }

    async def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        self._raise_unsupported(
            "conditional access policies",
            "TODO: Google has no direct Conditional Access equivalent in this adapter.",
        )

    async def create_conditional_access_policy(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        del payload
        self._raise_unsupported(
            "conditional access policy creation",
            "TODO: Advanced Google policy enforcement is not implemented.",
        )

    async def update_conditional_access_policy(
        self,
        policy_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        del policy_id, payload
        self._raise_unsupported(
            "conditional access policy updates",
            "TODO: Advanced Google policy enforcement is not implemented.",
        )

    async def delete_conditional_access_policy(self, policy_id: str) -> dict[str, Any]:
        del policy_id
        self._raise_unsupported(
            "conditional access policy deletion",
            "TODO: Advanced Google policy enforcement is not implemented.",
        )

    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        user = await self.post("/users", payload)
        return self._normalize_user(user)

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        await self.delete(f"/users/{quote(str(user_id), safe='')}")
        return {"id": user_id, "deleted": True}

    async def set_user_account_enabled(self, user_id: str, enabled: bool) -> dict[str, Any]:
        await self.patch(
            f"/users/{quote(str(user_id), safe='')}",
            {"suspended": not enabled},
        )
        # Google Directory API is eventually consistent; retry verification with
        # exponential backoff before warning rather than hard-failing.
        max_attempts = 3
        delay = GOOGLE_RETRY_BASE_DELAY_SECONDS
        state: dict[str, Any] = {}
        for attempt in range(1, max_attempts + 1):
            state = await self.get_user_account_state(user_id)
            if state.get("is_active") is enabled:
                return state
            if attempt < max_attempts:
                logger.warning(
                    "google_account_enabled_mismatch_retry tenant_id=%s user_id=%s attempt=%s",
                    getattr(self.tenant, "id", None),
                    user_id,
                    attempt,
                )
                await asyncio.sleep(delay)
                delay *= 2
        logger.warning(
            "google_account_enabled_mismatch_final tenant_id=%s user_id=%s expected=%s got=%s",
            getattr(self.tenant, "id", None),
            user_id,
            enabled,
            state.get("is_active"),
        )
        return state

    async def add_directory_role_member(self, role_id: str, user_id: str) -> dict[str, Any]:
        response = await self.post(
            f"/customer/{self._customer_id()}/roleassignments",
            {
                "roleId": role_id,
                "assignedTo": user_id,
                "scopeType": "CUSTOMER",
            },
        )
        role = await self._role_by_id(role_id)
        return {
            "id": role_id,
            "displayName": str(role.get("displayName") or "Unknown Role"),
            "type": str(role.get("type") or "unknown"),
            "roleAssignmentId": response.get("roleAssignmentId"),
            "scopeType": response.get("scopeType") or "CUSTOMER",
            "user_id": user_id,
        }

    async def create_role_eligibility_request(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        del payload
        self._raise_unsupported(
            "role eligibility requests",
            "TODO: Google Workspace has no PIM-style role eligibility flow in this adapter.",
        )

    async def create_role_assignment(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized_payload = dict(payload)
        normalized_payload.setdefault("scopeType", "CUSTOMER")
        response = await self.post(
            f"/customer/{self._customer_id()}/roleassignments",
            normalized_payload,
        )
        role_id = str(response.get("roleId") or normalized_payload.get("roleId") or "")
        assigned_to = str(response.get("assignedTo") or normalized_payload.get("assignedTo") or "")
        role = await self._role_by_id(role_id) if role_id else {}
        return {
            "id": role_id,
            "displayName": str(role.get("displayName") or "Unknown Role"),
            "type": str(role.get("type") or "unknown"),
            "roleAssignmentId": response.get("roleAssignmentId"),
            "scopeType": response.get("scopeType") or normalized_payload.get("scopeType"),
            "user_id": assigned_to,
        }

    async def fetch_user_memberof_directory_roles(self, user_id: str) -> list[dict[str, str]]:
        roles_by_id = await self._roles_by_id()
        assignments = await self._list_role_assignments(
            user_key=user_id,
            include_indirect=True,
        )

        normalized: list[dict[str, str]] = []
        seen_role_ids: set[str] = set()
        for assignment in assignments:
            role_id = assignment.get("roleId")
            if not isinstance(role_id, str) or not role_id or role_id in seen_role_ids:
                continue
            seen_role_ids.add(role_id)
            role = roles_by_id.get(role_id)
            if role is None:
                normalized.append(
                    {
                        "id": role_id,
                        "displayName": "Unknown Role",
                        "type": "unknown",
                    }
                )
                continue
            normalized.append(
                {
                    "id": role_id,
                    "displayName": str(role.get("displayName") or "Unknown Role"),
                    "type": str(role.get("type") or "directoryRole"),
                }
            )
        return normalized

    async def get_authorization_policy(self) -> dict[str, Any]:
        self._raise_unsupported(
            "authorization policy retrieval",
            "TODO: Microsoft authorizationPolicy has no Google Workspace equivalent.",
        )

    async def get_oauth2_permission_grant(self, grant_id: str) -> dict[str, Any]:
        del grant_id
        self._raise_unsupported(
            "OAuth grant retrieval",
            "TODO: Google OAuth grant management needs user-token mapping and is not implemented.",
        )

    async def list_oauth2_permission_grants(self) -> list[dict[str, Any]]:
        self._raise_unsupported(
            "OAuth grant listing",
            "TODO: Google OAuth grant management is limited and not implemented in phase 1.",
        )

    async def get_user_account_state(
        self,
        user_id: str,
        *,
        use_application_token: bool = False,
    ) -> dict[str, Any]:
        del use_application_token
        user = await self._request(
            "GET",
            f"/users/{quote(str(user_id), safe='')}",
            params={
                "projection": "full",
                "viewType": "admin_view",
                "fields": GOOGLE_USER_FIELDS,
            },
        )
        return self._normalize_user(user)

    async def remove_directory_role_member(self, role_id: str, user_id: str) -> dict[str, Any]:
        assignments = await self._list_role_assignments(
            user_key=user_id,
            role_id=role_id,
            include_indirect=False,
        )
        if not assignments:
            raise GoogleAPIError(
                404,
                f"Role assignment not found for user {user_id} and role {role_id}",
                method="DELETE",
                path=f"/customer/{self._customer_id()}/roleassignments",
            )

        # Last-admin guard runs after listing assignments so it executes as close
        # to the DELETE as possible, minimising the TOCTOU window.
        await self._ensure_not_last_remaining_super_admin(role_id=role_id, user_id=user_id)

        removed_assignment_ids: list[str] = []
        for assignment in assignments:
            assignment_id = assignment.get("roleAssignmentId")
            if not isinstance(assignment_id, str) or not assignment_id:
                continue
            await self.delete(f"/customer/{self._customer_id()}/roleassignments/{assignment_id}")
            removed_assignment_ids.append(assignment_id)

        role = await self._role_by_id(role_id)
        return {
            "id": role_id,
            "displayName": str(role.get("displayName") or "Unknown Role"),
            "type": str(role.get("type") or "unknown"),
            "removedAssignmentIds": removed_assignment_ids,
            "user_id": user_id,
        }

    async def delete_oauth2_permission_grant(self, grant_id: str) -> dict[str, Any]:
        del grant_id
        # TODO: Map grant deletion to Google user token revocation once consent
        # inventory and grant identifiers are modeled provider-neutrally.
        self._raise_unsupported(
            "OAuth grant deletion",
            "TODO: Google OAuth grant management is limited and not implemented in phase 1.",
        )

    async def create_oauth2_permission_grant(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        # TODO: Google consent rollback may require recreating app authorizations
        # through user re-consent rather than provider-side grant creation.
        self._raise_unsupported(
            "OAuth grant creation",
            "TODO: Google OAuth grant creation is not supported in phase 1.",
        )

    async def create_service_principal(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        self._raise_unsupported(
            "service principal creation",
            "TODO: Google does not expose a Microsoft-style servicePrincipal resource here.",
        )

    async def list_users(self) -> list[dict[str, Any]]:
        raw_users = await self._list_users()
        return [self._normalize_user(user) for user in raw_users]

    async def get_mfa_status(self, user_id: str) -> bool:
        user = await self._request(
            "GET",
            f"/users/{quote(str(user_id), safe='')}",
            params={
                "projection": "full",
                "viewType": "admin_view",
                "fields": "id,isEnrolledIn2Sv",
            },
        )
        return bool(user.get("isEnrolledIn2Sv", False))

    async def list_directory_roles(self) -> list[dict[str, Any]]:
        roles: list[dict[str, Any]] = []
        for item in await self._paged_items(
            path=f"/customer/{self._customer_id()}/roles",
            params={
                "maxResults": 200,
                "fields": ("items(roleId,roleName,roleDescription,isSystemRole,isSuperAdminRole)," "nextPageToken"),
            },
            items_key="items",
        ):
            if not isinstance(item, dict):
                continue
            role_id = item.get("roleId")
            if not isinstance(role_id, str) or not role_id:
                continue
            display_name = item.get("roleName")
            roles.append(
                {
                    "id": role_id,
                    "displayName": display_name if isinstance(display_name, str) else role_id,
                    "description": (
                        item.get("roleDescription") if isinstance(item.get("roleDescription"), str) else ""
                    ),
                    "isSystemRole": bool(item.get("isSystemRole", False)),
                    "isSuperAdminRole": bool(item.get("isSuperAdminRole", False)),
                    "type": "directoryRole",
                }
            )
        self._directory_roles_cache = {
            role["id"]: role for role in roles if isinstance(role.get("id"), str) and role.get("id")
        }
        return roles

    async def revoke_user_sessions(self, user_id: str) -> dict[str, Any]:
        await self.post(f"/users/{quote(str(user_id), safe='')}/signOut", {})
        return {"id": user_id, "sessions_revoked": True}

    def _get_access_token(self) -> str:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account
        except ImportError as exc:
            raise RuntimeError(
                "google-auth is required for Google Workspace adapters. " "Install the 'google-auth' package."
            ) from exc

        credentials = service_account.Credentials.from_service_account_info(
            self._service_account_info(),
            scopes=list(GOOGLE_ADMIN_SCOPES),
        ).with_subject(self._delegated_admin_email())
        credentials.refresh(Request())
        if not credentials.token:
            raise RuntimeError("Failed to acquire Google Workspace access token")
        return str(credentials.token)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_path = self._normalize_path(path)
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Accept": "application/json",
        }
        last_error: GoogleAPIError | None = None
        for attempt in range(1, GOOGLE_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=GOOGLE_REQUEST_TIMEOUT_SECONDS) as client:
                    response = await client.request(
                        method=method,
                        url=f"{GOOGLE_DIRECTORY_BASE}{normalized_path}",
                        headers=headers,
                        params=params,
                        json=payload,
                    )
            except httpx.HTTPError as exc:
                raise GoogleAPIError(
                    503,
                    str(exc) or "Google Workspace request failed",
                    method=method,
                    path=normalized_path,
                ) from exc

            if response.status_code == 204 or not response.content:
                return {}

            if response.status_code == 429 and attempt < GOOGLE_MAX_RETRIES:
                delay_seconds = self._retry_delay_seconds(response, attempt)
                logger.warning(
                    "google_workspace_rate_limited tenant_id=%s path=%s attempt=%s delay=%s",
                    getattr(self.tenant, "id", None),
                    normalized_path,
                    attempt,
                    delay_seconds,
                )
                await asyncio.sleep(delay_seconds)
                continue

            if response.status_code >= 400:
                last_error = self._build_google_api_error(method, normalized_path, response)
                break

            try:
                return response.json()
            except ValueError as exc:
                raise GoogleAPIError(
                    502,
                    "Google Workspace returned invalid JSON",
                    method=method,
                    path=normalized_path,
                    response_body=response.text,
                ) from exc

        if last_error is None:
            raise GoogleAPIError(
                500,
                "Google Workspace request failed",
                method=method,
                path=normalized_path,
            )
        raise last_error

    async def _list_users(self) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        for item in await self._paged_items(
            path="/users",
            params={
                "customer": self._customer_id(),
                "projection": "full",
                "viewType": "admin_view",
                "orderBy": "email",
                "sortOrder": "ASCENDING",
                "maxResults": 500,
                "fields": f"nextPageToken,users({GOOGLE_USER_FIELDS})",
            },
            items_key="users",
        ):
            if isinstance(item, dict):
                users.append(item)
        return users

    async def _list_role_assignments(
        self,
        *,
        user_key: str,
        role_id: str | None = None,
        include_indirect: bool = False,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "userKey": user_key,
            "includeIndirectRoleAssignments": str(include_indirect).lower(),
            "maxResults": 200,
            "fields": ("items(roleAssignmentId,roleId,assignedTo,scopeType,assigneeType)," "nextPageToken"),
        }
        if role_id:
            params["roleId"] = role_id

        assignments: list[dict[str, Any]] = []
        for item in await self._paged_items(
            path=f"/customer/{self._customer_id()}/roleassignments",
            params=params,
            items_key="items",
        ):
            if isinstance(item, dict):
                assignments.append(item)
        return assignments

    async def _paged_items(
        self,
        *,
        path: str,
        params: dict[str, Any],
        items_key: str,
    ) -> list[Any]:
        items: list[Any] = []
        next_page_token: str | None = None
        seen_tokens: set[str] = set()

        for _ in range(GOOGLE_MAX_PAGES):
            request_params = dict(params)
            if next_page_token:
                if next_page_token in seen_tokens:
                    raise RuntimeError("Google Workspace pagination loop detected")
                seen_tokens.add(next_page_token)
                request_params["pageToken"] = next_page_token

            payload = await self._request("GET", path, params=request_params)
            page_items = payload.get(items_key, []) if isinstance(payload, dict) else []
            if isinstance(page_items, list):
                items.extend(page_items)

            token = payload.get("nextPageToken") if isinstance(payload, dict) else None
            if not isinstance(token, str) or not token:
                return items
            next_page_token = token

        raise RuntimeError("Google Workspace pagination exceeded safe upper bound")

    async def _roles_by_id(self) -> dict[str, dict[str, Any]]:
        cached = getattr(self, "_directory_roles_cache", None)
        if isinstance(cached, dict) and cached:
            return cached
        roles = await self.list_directory_roles()
        return {role["id"]: role for role in roles if isinstance(role.get("id"), str) and role.get("id")}

    async def _role_by_id(self, role_id: str) -> dict[str, Any]:
        if not role_id:
            return {"displayName": "Unknown Role", "type": "unknown"}
        return (await self._roles_by_id()).get(
            role_id,
            {"displayName": "Unknown Role", "type": "unknown"},
        )

    async def _ensure_not_last_remaining_super_admin(self, *, role_id: str, user_id: str) -> None:
        role = await self._role_by_id(role_id)
        if not bool(role.get("isSuperAdminRole")):
            return

        user = await self.get_user_account_state(user_id)
        if not bool(user.get("is_admin")):
            return

        # Fetch the live admin list as late as possible to minimize the TOCTOU window.
        # We repeat this check; the window between this read and the DELETE call below
        # is still non-zero but cannot be fully eliminated without a provider-side lock.
        active_admins = [entry for entry in await self.list_users() if entry.get("is_admin") and entry.get("is_active")]
        if len(active_admins) > 1:
            return

        raise GraphBlockedError(
            status="blocked",
            reason=BlockReason.POLICY_RESTRICTION.value,
            message="Cannot remove the last remaining Google Workspace super admin",
            tenant_id=getattr(self.tenant, "id", None),
        )

    def _normalize_user(self, user: dict[str, Any]) -> dict[str, Any]:
        user_id = str(user.get("id") or "")
        email = str(user.get("primaryEmail") or "")
        last_login = user.get("lastLoginTime")
        full_name = ""
        name = user.get("name")
        if isinstance(name, dict):
            full_name = str(name.get("fullName") or "")

        normalized = {
            "id": user_id,
            "email": email,
            "is_active": not bool(user.get("suspended", False)),
            "is_admin": bool(user.get("isAdmin", False)),
            "mfa_enabled": bool(user.get("isEnrolledIn2Sv", False)),
            "last_login": last_login if isinstance(last_login, str) and last_login else None,
        }
        normalized.update(
            {
                "display_name": full_name or email,
                "displayName": full_name or email,
                "mail": email,
                "userPrincipalName": email,
                "accountEnabled": normalized["is_active"],
            }
        )
        return normalized

    def _normalize_path(self, path: str) -> str:
        candidate = str(path or "").strip()
        if not candidate:
            raise ValueError("Google Workspace API path is required")
        if candidate.startswith("http://") or candidate.startswith("https://"):
            if not candidate.startswith(GOOGLE_DIRECTORY_BASE):
                raise ValueError("Google Workspace adapter only supports Admin SDK Directory paths")
            return candidate[len(GOOGLE_DIRECTORY_BASE) :]
        return candidate if candidate.startswith("/") else f"/{candidate}"

    def _provider_credentials(self) -> dict[str, Any]:
        raw = getattr(self.tenant, "provider_credentials", None)
        if raw is None:
            raise RuntimeError("Tenant has no provider_credentials configured for Google Workspace")
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError("Tenant provider_credentials is not valid JSON") from exc
            if not isinstance(parsed, dict):
                raise RuntimeError("Tenant provider_credentials must decode to an object")
            return parsed
        if not isinstance(raw, dict):
            raise RuntimeError("Tenant provider_credentials must be a dict or JSON object string")
        return raw

    def _service_account_info(self) -> dict[str, Any]:
        provider_credentials = self._provider_credentials()
        candidates: list[dict[str, Any]] = []
        if isinstance(provider_credentials, dict):
            candidates.append(provider_credentials)
        for key in ("service_account", "service_account_info", "service_account_credentials"):
            candidate = provider_credentials.get(key)
            if isinstance(candidate, dict):
                candidates.append(candidate)

        for candidate in candidates:
            missing_keys = [
                key
                for key in GOOGLE_REQUIRED_SERVICE_ACCOUNT_KEYS
                if not isinstance(candidate.get(key), str) or not candidate.get(key)
            ]
            if not missing_keys:
                return candidate

        raise RuntimeError(
            "Google provider_credentials is missing required service account keys: "
            f"{', '.join(GOOGLE_REQUIRED_SERVICE_ACCOUNT_KEYS)}"
        )

    def _delegated_admin_email(self) -> str:
        provider_credentials = self._provider_credentials()
        for key in ("delegated_admin_email", "delegated_admin", "subject"):
            value = provider_credentials.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        raise ValueError("Delegated admin required")

    def _customer_id(self) -> str:
        provider_credentials = self._provider_credentials()
        for key in ("customer_id", "customer", "google_customer_id"):
            value = provider_credentials.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return GOOGLE_DEFAULT_CUSTOMER

    def _build_google_api_error(
        self,
        method: str,
        path: str,
        response: httpx.Response,
    ) -> GoogleAPIError:
        response_body = response.text
        message = self._extract_google_error_message(response_body)
        return GoogleAPIError(
            response.status_code,
            message,
            method=method,
            path=path,
            response_body=response_body,
        )

    def _extract_google_error_message(self, response_body: str) -> str:
        try:
            payload = json.loads(response_body or "{}")
        except json.JSONDecodeError:
            return response_body or "Google Workspace request failed"

        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message:
                return message
            details = error.get("errors")
            if isinstance(details, list) and details:
                first = details[0]
                if isinstance(first, dict):
                    first_message = first.get("message")
                    if isinstance(first_message, str) and first_message:
                        return first_message
        return response_body or "Google Workspace request failed"

    def _retry_delay_seconds(self, response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if isinstance(retry_after, str) and retry_after.strip().isdigit():
            return float(retry_after.strip())
        return GOOGLE_RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1))

    def _raise_unsupported(self, feature: str, todo: str) -> None:
        raise GraphBlockedError(
            status="blocked",
            reason=BlockReason.UNKNOWN.value,
            message=f"Google Workspace adapter does not yet support {feature}. {todo}",
            tenant_id=getattr(self.tenant, "id", None),
        )
