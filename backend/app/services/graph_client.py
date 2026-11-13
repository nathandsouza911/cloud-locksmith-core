import base64
import asyncio
import json
import logging
from typing import Any
from urllib.parse import quote

import httpx

from app.config import settings
from app.db.models.tenant import Tenant
from app.services.remediation.lifecycle import BlockReason
from app.services.graph_app_token import get_graph_app_token
from app.services.microsoft_oauth_scopes import REQUIRED_AUTHORIZATION_POLICY_SCOPE
from app.services.token_manager import get_valid_access_token, has_delegated_oauth_token

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
logger = logging.getLogger(__name__)


class TenantNotConnectedError(RuntimeError):
    """The tenant has no stored Microsoft token (e.g. a Preview-only sign-in).

    Subclasses RuntimeError so existing ``except RuntimeError`` handlers keep working;
    the API maps it to 409 FULL_CONNECT_REQUIRED instead of a 500.
    """

    def __init__(self) -> None:
        super().__init__("Tenant has no OAuth token stored")


class GraphAPIError(RuntimeError):
    def __init__(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        response_body: str,
        category: str,
        token_claims: dict[str, Any] | None = None,
    ):
        self.method = method
        self.path = path
        self.status_code = status_code
        self.response_body = response_body
        self.category = category
        self.token_claims = token_claims or {}
        super().__init__(f"Graph {method} {path} failed with {status_code}: {response_body}")


class GraphBlockedError(RuntimeError):
    def __init__(
        self,
        *,
        status: str,
        reason: str,
        message: str,
        tenant_id: str | None = None,
    ):
        self.status = status
        self.reason = reason
        self.message = message
        self.tenant_id = tenant_id
        super().__init__(message)


class GraphVerificationError(RuntimeError):
    def __init__(self, reason: str, message: str | None = None):
        self.reason = reason
        super().__init__(message or reason)


SIGNIN_ACTIVITY_NON_PREMIUM_CODE = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
REQUIRED_DISABLE_USER_PERMISSIONS = {
    "User.EnableDisableAccount.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
}
AUTHORIZATION_POLICY_WRITE_PERMISSIONS = {
    REQUIRED_AUTHORIZATION_POLICY_SCOPE,
}
OAUTH2_GRANT_WRITE_PERMISSIONS = {
    "DelegatedPermissionGrant.ReadWrite.All",
}


def decode_access_token_claims(access_token: str) -> dict[str, Any]:
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _validate_access_token_tenant(
    *,
    access_token: str,
    expected_tenant_id: str | None,
) -> dict[str, Any]:
    claims = decode_access_token_claims(access_token)
    token_tid = str(claims.get("tid") or "").strip()
    expected = str(expected_tenant_id or "").strip()
    if expected and token_tid and token_tid != expected:
        logger.warning(
            "graph_access_token_tenant_mismatch token_tid=%s expected_tenant_id=%s",
            token_tid,
            expected,
        )
        raise GraphVerificationError("TENANT_CONTEXT_MISMATCH")
    return claims


def _token_permissions(claims: dict[str, Any]) -> set[str]:
    scopes = (claims.get("scp") or "").split()
    roles = claims.get("roles") or []
    if not isinstance(roles, list):
        roles = []
    return {permission for permission in [*scopes, *roles] if isinstance(permission, str)}


def _token_mode(claims: dict[str, Any]) -> str:
    if claims.get("scp"):
        return "delegated"
    if claims.get("roles"):
        return "application"
    return "unknown"


def _extract_graph_error_code(response_body: str) -> str | None:
    try:
        payload = json.loads(response_body or "{}")
    except json.JSONDecodeError:
        return None
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        return code if isinstance(code, str) else None
    return None


def classify_graph_api_error(exc: "GraphAPIError") -> str:
    if exc.status_code == 403 and _extract_graph_error_code(exc.response_body) == "Authorization_RequestDenied":
        return BlockReason.INSUFFICIENT_PERMISSIONS.value
    if exc.status_code == 400:
        return "INVALID_PAYLOAD"
    if exc.status_code == 404:
        return "RESOURCE_NOT_FOUND"
    if exc.status_code == 403:
        return BlockReason.POLICY_RESTRICTION.value
    return BlockReason.UNKNOWN.value


def describe_graph_api_error(exc: "GraphAPIError") -> str:
    error_type = classify_graph_api_error(exc)
    if error_type == BlockReason.INSUFFICIENT_PERMISSIONS.value and exc.path == "/policies/authorizationPolicy":
        return "Missing required permission: " f"{REQUIRED_AUTHORIZATION_POLICY_SCOPE}. Please reconnect tenant."
    if error_type == "INVALID_PAYLOAD":
        try:
            body = json.loads(exc.response_body or "{}")
            graph_error = body.get("error") or {}
            code = graph_error.get("code")
            message = graph_error.get("message")
            if code and message:
                return f"Configuration error ({code}): {message}"
            if code:
                return f"Configuration error ({code})"
        except (json.JSONDecodeError, AttributeError):
            pass
        return "Configuration error"
    if error_type == "RESOURCE_NOT_FOUND":
        return "Resource not found"
    return str(exc)


def graph_error_ui_label(error_type: str | None) -> str | None:
    labels = {
        BlockReason.INSUFFICIENT_PERMISSIONS.value: "Permission required",
        BlockReason.INSUFFICIENT_SCOPE.value: "Permission required",
        "INVALID_PAYLOAD": "Configuration error",
        "RESOURCE_NOT_FOUND": "Resource not found",
        BlockReason.POLICY_RESTRICTION.value: "Policy restriction",
        BlockReason.UNKNOWN.value: "Execution failed",
    }
    if not error_type:
        return None
    return labels.get(error_type, error_type.replace("_", " ").title())


def validate_required_graph_permissions(
    *,
    access_token: str,
    required_permissions: set[str] | None = None,
    require_application_token: bool = False,
) -> dict[str, Any]:
    claims = decode_access_token_claims(access_token)
    token_mode = _token_mode(claims)
    permissions = _token_permissions(claims)
    required_permissions = required_permissions or REQUIRED_DISABLE_USER_PERMISSIONS

    if require_application_token and token_mode != "application":
        raise GraphBlockedError(
            status="blocked",
            reason=BlockReason.INSUFFICIENT_PERMISSIONS.value,
            message="Delegated tokens cannot be used for user disable operations",
            tenant_id=claims.get("tid"),
        )

    if not permissions.intersection(required_permissions):
        missing_permission = next(
            iter(settings.REQUIRED_GRAPH_REMEDIATION_PERMISSIONS), "User.EnableDisableAccount.All"
        )
        raise GraphBlockedError(
            status="blocked",
            reason=BlockReason.INSUFFICIENT_PERMISSIONS.value,
            message=f"Missing required permission: {missing_permission}",
            tenant_id=claims.get("tid"),
        )

    return claims


async def validate_tenant_graph_permissions(
    *,
    db,
    tenant: Tenant,
    required_permissions: set[str],
    missing_permission_message: str,
) -> dict[str, Any]:
    if not await has_delegated_oauth_token(tenant, db=db):
        raise TenantNotConnectedError()

    access_token = await get_valid_access_token(tenant.id, db=db)
    claims = decode_access_token_claims(access_token)
    permissions = _token_permissions(claims)
    if permissions.intersection(required_permissions):
        return claims

    raise GraphBlockedError(
        status="blocked",
        reason=BlockReason.INSUFFICIENT_SCOPE.value,
        message=missing_permission_message,
        tenant_id=claims.get("tid"),
    )


def is_non_premium_signin_activity_error(exc: Exception) -> bool:
    if not isinstance(exc, GraphAPIError):
        return False
    return exc.status_code == 403 and SIGNIN_ACTIVITY_NON_PREMIUM_CODE in (exc.response_body or "")


def _log_token_claims(access_token: str):
    claims = decode_access_token_claims(access_token)
    scopes = (claims.get("scp") or "").split()
    logger.debug(
        "graph_token_claims tid=%s aud=%s has_user_auth_method_scope=%s has_directory_read_all=%s",
        claims.get("tid"),
        claims.get("aud"),
        "UserAuthenticationMethod.Read.All" in scopes,
        "Directory.Read.All" in scopes,
    )
    return claims


async def _graph_request(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    payload: dict | None = None,
):
    endpoint = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    logger.debug("graph_call method=%s path=%s", method, path)

    response = None
    for attempt in range(3):
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.request(
                method=method,
                url=endpoint,
                headers=headers,
                json=payload,
            )

        if response.status_code != 429 or attempt == 2:
            break

        retry_after = response.headers.get("Retry-After")
        delay = float(retry_after) if retry_after else (2**attempt)
        logger.debug("graph_retry_backoff path=%s delay_seconds=%s", path, delay)
        await asyncio.sleep(delay)

    logger.debug("graph_response path=%s status=%s", path, response.status_code)
    return response


def _raise_graph_error(
    *,
    method: str,
    path: str,
    response: httpx.Response,
    access_token: str,
):
    claims = _log_token_claims(access_token)
    if "Authorization_IdentityDisabled" in response.text:
        tenant_id = claims.get("tid")
        logger.warning(
            "graph_blocked event=tenant_onboarding_failed reason=service_principal_disabled tenant_id=%s path=%s",
            tenant_id,
            path,
        )
        raise GraphBlockedError(
            status="blocked",
            reason=BlockReason.POLICY_RESTRICTION.value,
            message=(
                "The application is disabled in this tenant. Please enable it " "in Azure Enterprise Applications."
            ),
            tenant_id=tenant_id,
        )
    status_code = response.status_code
    error_code = _extract_graph_error_code(response.text)
    category = "unknown"
    if status_code == 400:
        category = "validation_issue"
    elif status_code == 403:
        category = "PERMISSION_ERROR" if error_code == "Authorization_RequestDenied" else "PRIVILEGE_BOUNDARY"
    elif status_code == 429:
        category = "rate_limited"
    elif status_code >= 500:
        category = "graph_server_error"
    if path.endswith("/authentication/methods"):
        scopes = (claims.get("scp") or "").split()
        logger.warning(
            "graph_auth_methods_failure status_code=%s has_user_auth_method_scope=%s has_directory_read_all=%s",
            status_code,
            "UserAuthenticationMethod.Read.All" in scopes,
            "Directory.Read.All" in scopes,
        )
    raise GraphAPIError(
        method=method,
        path=path,
        status_code=response.status_code,
        response_body=response.text,
        category=category,
        token_claims=claims,
    )


async def graph_get(db, tenant: Tenant, path: str):
    if settings.DEMO_MODE:
        # Demo mode never calls Microsoft: answer from the recorded demo tenant or fail closed.
        from app.demo.recorded_graph import recorded_graph_get

        return recorded_graph_get(tenant.id, path)
    if not await has_delegated_oauth_token(tenant, db=db):
        raise TenantNotConnectedError()

    access_token = await get_valid_access_token(tenant.id, db=db)
    _validate_access_token_tenant(
        access_token=access_token,
        expected_tenant_id=tenant.id,
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    response = await _graph_request(method="GET", path=path, headers=headers)

    if response.status_code == 401:
        access_token = await get_valid_access_token(tenant.id, db=db, force_refresh=True)
        _validate_access_token_tenant(
            access_token=access_token,
            expected_tenant_id=tenant.id,
        )
        headers["Authorization"] = f"Bearer {access_token}"
        response = await _graph_request(method="GET", path=path, headers=headers)

    if response.status_code >= 400:
        if response.status_code == 403 and "authentication/methods" in path:
            claims = _log_token_claims(access_token)
            return {
                "status": "error",
                "code": 403,
                "reason": "access_denied",
                "response_body": response.text,
                "token_claims": claims,
            }
        _raise_graph_error(
            method="GET",
            path=path,
            response=response,
            access_token=access_token,
        )

    return response.json() if response.text else {}


async def get_tenant_graph_token_claims(*, db, tenant: Tenant) -> dict[str, Any]:
    access_token = await get_valid_access_token(tenant.id, db=db)
    return _validate_access_token_tenant(
        access_token=access_token,
        expected_tenant_id=tenant.id,
    )


async def _graph_write_request(db, tenant: Tenant, method: str, path: str, payload: dict | None = None):
    if not await has_delegated_oauth_token(tenant, db=db):
        raise TenantNotConnectedError()

    access_token = await get_valid_access_token(tenant.id, db=db)
    _validate_access_token_tenant(
        access_token=access_token,
        expected_tenant_id=tenant.id,
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    response = await _graph_request(
        method=method,
        path=path,
        headers=headers,
        payload=payload,
    )

    if response.status_code == 401:
        access_token = await get_valid_access_token(tenant.id, db=db, force_refresh=True)
        _validate_access_token_tenant(
            access_token=access_token,
            expected_tenant_id=tenant.id,
        )
        headers["Authorization"] = f"Bearer {access_token}"
        response = await _graph_request(
            method=method,
            path=path,
            headers=headers,
            payload=payload,
        )

    if response.status_code >= 400:
        _raise_graph_error(
            method=method,
            path=path,
            response=response,
            access_token=access_token,
        )

    return response.json() if response.text else {}


async def _graph_write_request_with_token(
    *,
    method: str,
    path: str,
    access_token: str,
    payload: dict | None = None,
):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = await _graph_request(
        method=method,
        path=path,
        headers=headers,
        payload=payload,
    )
    if response.status_code >= 400:
        _raise_graph_error(
            method=method,
            path=path,
            response=response,
            access_token=access_token,
        )
    return response.json() if response.text else {}


async def graph_patch(db, tenant, path: str, payload: dict):
    return await _graph_write_request(db, tenant, "PATCH", path, payload)


async def graph_delete(db, tenant, path: str):
    return await _graph_write_request(db, tenant, "DELETE", path)


async def graph_post(db, tenant, path: str, payload: dict):
    return await _graph_write_request(db, tenant, "POST", path, payload)


def _normalize_memberof_directory_roles(payload: dict[str, Any] | None) -> list[dict[str, str]]:
    values = payload.get("value", []) if isinstance(payload, dict) else []
    normalized: list[dict[str, str]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        if item.get("@odata.type") != "#microsoft.graph.directoryRole":
            continue
        role_id = item.get("id")
        if not isinstance(role_id, str) or not role_id:
            continue
        display_name = item.get("displayName")
        normalized.append(
            {
                "id": role_id,
                "displayName": display_name if isinstance(display_name, str) else "",
                "type": "directoryRole",
            }
        )
    return normalized


async def fetch_user_memberof_directory_roles(db, tenant: Tenant, user_id: str) -> list[dict[str, str]]:
    path = f"/users/{user_id}/memberOf"
    try:
        payload = await graph_get(db, tenant, path)
        return _normalize_memberof_directory_roles(payload)
    except Exception as exc:
        logger.warning(
            "memberof_query_failed %s",
            {
                "event": "MEMBEROF_QUERY_FAILED",
                "used_select": False,
                "user_id": user_id,
                "error": str(exc),
            },
        )
        try:
            payload = await graph_get(db, tenant, path)
            return _normalize_memberof_directory_roles(payload)
        except Exception:
            return []


async def fetch_user_memberof_directory_roles_with_app_token(
    user_id: str,
) -> list[dict[str, str]]:
    path = f"/users/{user_id}/memberOf"
    try:
        payload = await graph_get_app(path)
        return _normalize_memberof_directory_roles(payload)
    except GraphAPIError as exc:
        logger.warning(
            "memberof_query_failed %s",
            {
                "event": "MEMBEROF_QUERY_FAILED",
                "used_select": False,
                "user_id": user_id,
                "status_code": exc.status_code,
            },
        )
        try:
            payload = await graph_get_app(path)
            return _normalize_memberof_directory_roles(payload)
        except Exception:
            return []
    except Exception as exc:
        logger.warning(
            "memberof_query_failed %s",
            {
                "event": "MEMBEROF_QUERY_FAILED",
                "used_select": False,
                "user_id": user_id,
                "error": str(exc),
            },
        )
        try:
            payload = await graph_get_app(path)
            return _normalize_memberof_directory_roles(payload)
        except Exception:
            return []


async def get_user_directory_roles_with_app_token(user_id: str) -> list[dict[str, Any]]:
    member_of = await fetch_user_memberof_directory_roles_with_app_token(user_id)
    return [
        {
            "id": item["id"],
            "displayName": item["displayName"],
            "@odata.type": "#microsoft.graph.directoryRole",
        }
        for item in member_of
    ]


async def get_user_directory_roles_with_token(
    *,
    access_token: str,
    user_id: str,
) -> list[dict[str, Any]]:
    payload = await graph_get_with_token(access_token, f"/users/{user_id}/memberOf")
    member_of = _normalize_memberof_directory_roles(payload)
    return [
        {
            "id": item["id"],
            "displayName": item["displayName"],
            "@odata.type": "#microsoft.graph.directoryRole",
        }
        for item in member_of
    ]


def _log_tenant_context(*, user_id: str, token_tid: str | None, expected_tenant_id: str | None) -> None:
    logger.info(
        "GRAPH_TENANT_CONTEXT %s",
        {
            "user_id": user_id,
            "token_tid": token_tid,
            "expected_tenant_id": expected_tenant_id,
        },
    )


def _ensure_tenant_context(*, claims: dict[str, Any], expected_tenant_id: str | None, user_id: str) -> None:
    token_tid = claims.get("tid")
    _log_tenant_context(
        user_id=user_id,
        token_tid=token_tid if isinstance(token_tid, str) else None,
        expected_tenant_id=expected_tenant_id,
    )
    if expected_tenant_id and token_tid and token_tid != expected_tenant_id:
        raise GraphVerificationError("TENANT_CONTEXT_MISMATCH")


async def _get_user_with_app_token(*, access_token: str, user_id: str) -> dict[str, Any] | None:
    try:
        return await graph_get_with_token(
            access_token,
            f"/users/{user_id}?$select=id,mail,userPrincipalName,accountEnabled",
        )
    except GraphAPIError as exc:
        if exc.status_code == 404:
            return None
        raise


async def _lookup_user_by_upn_with_app_token(
    *,
    access_token: str,
    user_email: str,
) -> dict[str, Any] | None:
    normalized_email = user_email.strip()
    if not normalized_email:
        return None
    escaped_email = normalized_email.replace("'", "''")
    path = (
        "/users?$filter="
        + quote(f"userPrincipalName eq '{escaped_email}'", safe="=$' ")
        + "&$select=id,mail,userPrincipalName,accountEnabled"
    )
    payload = await graph_get_with_token(access_token, path)
    values = payload.get("value", []) if isinstance(payload, dict) else []
    for item in values:
        if isinstance(item, dict) and item.get("id"):
            return item
    return None


def _update_session_references(
    *,
    steps: list[dict[str, Any]] | None,
    snapshot: dict[str, Any] | None,
    old_user_id: str,
    new_user_id: str,
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    updated_steps: list[dict[str, Any]] | None = None
    if isinstance(steps, list):
        updated_steps = []
        for step in steps:
            next_step = dict(step) if isinstance(step, dict) else step
            if isinstance(next_step, dict):
                automation = next_step.get("automation")
                if isinstance(automation, dict) and automation.get("user_id") == old_user_id:
                    next_step["automation"] = {**automation, "user_id": new_user_id}
            updated_steps.append(next_step)

    updated_snapshot = dict(snapshot) if isinstance(snapshot, dict) else snapshot
    if isinstance(updated_snapshot, dict):
        if updated_snapshot.get("user_id") == old_user_id:
            updated_snapshot["user_id"] = new_user_id
        if updated_snapshot.get("id") == old_user_id:
            updated_snapshot["id"] = new_user_id
    return updated_steps, updated_snapshot


def _sync_user_reference_in_db(
    *,
    db,
    tenant_id: str | None,
    old_user_id: str,
    new_user_id: str,
    user_email: str | None,
) -> None:
    if db is None or not tenant_id or old_user_id == new_user_id:
        return

    from app.db.models import User
    from app.db.models.compliance_result import ComplianceResult
    from app.db.models.offboarding_session import OffboardingSession

    normalized_email = (user_email or "").strip().lower()

    users = db.query(User).filter(User.tenant_id == tenant_id).all()
    for user in users:
        if user.external_id == old_user_id:
            user.external_id = new_user_id
            continue
        email = (getattr(user, "email", None) or "").strip().lower()
        if normalized_email and email == normalized_email:
            user.external_id = new_user_id

    (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.resource_id == old_user_id,
        )
        .update({ComplianceResult.resource_id: new_user_id}, synchronize_session=False)
    )

    sessions = (
        db.query(OffboardingSession)
        .filter(
            OffboardingSession.tenant_id == tenant_id,
            OffboardingSession.resource_id == old_user_id,
        )
        .all()
    )
    for session in sessions:
        updated_steps, updated_snapshot = _update_session_references(
            steps=session.steps,
            snapshot=session.snapshot,
            old_user_id=old_user_id,
            new_user_id=new_user_id,
        )
        session.resource_id = new_user_id
        if updated_steps is not None:
            session.steps = updated_steps
        if updated_snapshot is not None:
            session.snapshot = updated_snapshot

    db.commit()


async def _resolve_user_for_disable(
    *,
    access_token: str,
    db,
    tenant_id: str | None,
    user_id: str,
    user_email: str | None,
) -> tuple[str, dict[str, Any]]:
    user_payload = await _get_user_with_app_token(access_token=access_token, user_id=user_id)
    logger.info(
        "USER_DISABLE_ATTEMPT %s",
        {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "exists": bool(user_payload),
        },
    )
    if user_payload:
        return user_id, user_payload

    if user_email:
        fallback_user = await _lookup_user_by_upn_with_app_token(
            access_token=access_token,
            user_email=user_email,
        )
        if fallback_user and isinstance(fallback_user.get("id"), str):
            resolved_user_id = fallback_user["id"]
            _sync_user_reference_in_db(
                db=db,
                tenant_id=tenant_id,
                old_user_id=user_id,
                new_user_id=resolved_user_id,
                user_email=user_email,
            )
            logger.info(
                "USER_DISABLE_ATTEMPT %s",
                {
                    "user_id": resolved_user_id,
                    "tenant_id": tenant_id,
                    "exists": True,
                },
            )
            return resolved_user_id, fallback_user

    raise GraphVerificationError("USER_NOT_FOUND")


async def set_user_account_enabled_with_app_token(
    *,
    user_id: str,
    enabled: bool,
    tenant_id: str | None = None,
    db=None,
    user_email: str | None = None,
    tenant: Tenant | None = None,
):
    if tenant is not None:
        if tenant_id and tenant.id != tenant_id:
            raise GraphVerificationError("TENANT_CONTEXT_MISMATCH")
        access_token = await get_valid_access_token(tenant.id, db=db)
        claims = validate_required_graph_permissions(
            access_token=access_token,
            require_application_token=False,
        )
        expected_tenant_id = tenant.id
    else:
        access_token = await get_graph_app_token()
        claims = validate_required_graph_permissions(
            access_token=access_token,
            require_application_token=True,
        )
        expected_tenant_id = tenant_id
    _ensure_tenant_context(
        claims=claims,
        expected_tenant_id=expected_tenant_id,
        user_id=user_id,
    )

    resolved_user_id = user_id
    if enabled is False:
        resolved_user_id, _ = await _resolve_user_for_disable(
            access_token=access_token,
            db=db,
            tenant_id=expected_tenant_id,
            user_id=user_id,
            user_email=user_email,
        )

        roles = await get_user_directory_roles_with_token(
            access_token=access_token,
            user_id=resolved_user_id,
        )
        if roles and not settings.ALLOW_ADMIN_OFFBOARDING:
            raise GraphBlockedError(
                status="blocked",
                reason=BlockReason.PRIVILEGED_USER.value,
                message="Target user is privileged (admin role)",
                tenant_id=claims.get("tid"),
            )

    try:
        return await _graph_write_request_with_token(
            method="PATCH",
            path=f"/users/{resolved_user_id}",
            access_token=access_token,
            payload={"accountEnabled": enabled},
        )
    except GraphAPIError as exc:
        if exc.status_code == 403:
            logger.warning(
                "graph_remediation_failure control=IDENTITY_UNUSED_ACCOUNT failure_type=INSUFFICIENT_GRAPH_PRIVILEGE required_permission=User.EnableDisableAccount.All path=%s",
                exc.path,
            )
        raise


async def verify_graph_remediation_permissions_startup() -> None:
    access_token = await get_graph_app_token()
    validate_required_graph_permissions(
        access_token=access_token,
        required_permissions=set(settings.REQUIRED_GRAPH_REMEDIATION_PERMISSIONS),
        require_application_token=True,
    )


async def graph_get_app(path: str):
    """App-only Graph GET. WARNING: the app-only token is minted against the
    fixed publisher tenant (settings.MICROSOFT_TENANT), so this reads the
    PUBLISHER directory — never a customer tenant. Do NOT use it to read or
    decide anything about a customer's users/policies; use the delegated,
    tenant-scoped helpers (graph_get(db, tenant, ...)) for customer data.
    """
    access_token = await get_graph_app_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = await _graph_request(
        method="GET",
        path=path,
        headers=headers,
    )
    if response.status_code >= 400:
        _raise_graph_error(
            method="GET",
            path=path,
            response=response,
            access_token=access_token,
        )
    return response.json() if response.text else {}


async def graph_get_app_all(path: str):
    results = []
    response = await graph_get_app(path)
    results.extend(response.get("value", []))

    next_link = response.get("@odata.nextLink")
    while next_link:
        access_token = await get_graph_app_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        page = await _graph_request(method="GET", path=next_link, headers=headers)
        if page.status_code >= 400:
            _raise_graph_error(
                method="GET",
                path=next_link,
                response=page,
                access_token=access_token,
            )
        data = page.json()
        results.extend(data.get("value", []))
        next_link = data.get("@odata.nextLink")

    return results


async def graph_get_with_token(
    access_token: str,
    path: str,
    *,
    expected_tenant_id: str | None = None,
):
    _validate_access_token_tenant(
        access_token=access_token,
        expected_tenant_id=expected_tenant_id,
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = await _graph_request(method="GET", path=path, headers=headers)
    if response.status_code >= 400:
        _raise_graph_error(
            method="GET",
            path=path,
            response=response,
            access_token=access_token,
        )
    return response.json() if response.text else {}


async def graph_get_all(db, tenant, path: str):
    results = []
    response = await graph_get(db, tenant, path)
    results.extend(response.get("value", []))

    next_link = response.get("@odata.nextLink")
    while next_link:
        access_token = await get_valid_access_token(tenant.id, db=db)
        _validate_access_token_tenant(
            access_token=access_token,
            expected_tenant_id=tenant.id,
        )
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        page = await _graph_request(method="GET", path=next_link, headers=headers)
        if page.status_code >= 400:
            _raise_graph_error(
                method="GET",
                path=next_link,
                response=page,
                access_token=access_token,
            )
        data = page.json()
        results.extend(data.get("value", []))
        next_link = data.get("@odata.nextLink")

    return results
