import asyncio
from app.utils.datetime import to_naive_utc, utc_now
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import AsyncSessionLocal
from app.services.tenant_service import get_tenant
from app.services.ca_mfa_evaluator import is_mfa_policy, evaluate_tenant_wide_ca_mfa
from app.services.ca_user_coverage import users_covered_by_policy
from app.services.activity.unused_account_detector import evaluate_unused_account
from app.services.activity.workload_activity_source import fetch_workload_activity
from app.services.detection.identity_overprivileged_admin import (
    TENANT_CONTROL_ID as ADMIN_COUNT_EXCESS_CONTROL_ID,
    USER_CONTROL_ID as OVERPRIVILEGED_USER_CONTROL_ID,
    detect_overprivileged_controls,
    is_privileged_role,
)
from app.services.detection.identity_break_glass_account_detector import (
    detect_break_glass_accounts,
)
from app.services.detection.identity_risky_defaults_detector import (
    evaluate_identity_default_controls,
)
from app.services.detection.illicit_consent_grants_detector import (
    detect_illicit_consent_grants,
)
from app.services.detection.oauth_app_consent_discovery_detector import (
    detect_oauth_app_consent,
)
from app.services.graph_ca_service import (
    fetch_conditional_access_policies,
    build_ca_group_member_map,
)
from app.services.graph_client import graph_get, graph_get_all
from app.services.detection.password_never_expires_detector import evaluate_password_never_expires
from app.services.detection.app_secret_expiry_detector import evaluate_all_app_secret_expiry
from app.services.detection.stale_service_principal_detector import evaluate_stale_service_principals
from app.services.detection.service_account_interactive_login_detector import (
    evaluate_service_account_interactive_logins,
)
from app.services.detection.admin_phishing_resistant_mfa_detector import (
    evaluate_admin_phishing_resistant_mfa,
    TARGET_ADMIN_ROLE_NAMES as _PHISHING_RESISTANT_TARGET_ROLES,
)
from app.services.detection.permanent_role_assignment_detector import (
    evaluate_permanent_role_assignments,
    PRIVILEGED_ROLE_DEFINITION_IDS as _PERMANENT_ROLE_TARGET_IDS,
)
from app.services.detection.app_secret_expiry_detector import aggregate_app_secret_severity
from app.services.detection.mail_forwarding_rule_detector import evaluate_user_forwarding_rules
from app.services.graph_security_defaults_service import fetch_security_defaults_enabled
from app.services.graph_user_service import fetch_users
from app.services.identity_dedup import dedupe_directory_users, upsert_control_result
from app.services.posture_snapshot_service import (
    create_posture_snapshot_async,
    get_latest_posture_snapshot_async,
)
from app.services.alert_generator import generate_posture_alerts
from app.services.alert_service import create_alerts
from app.services.baseline.baseline_definition import (
    LICENSE_GATED_CA_CONTROLS,
    SECURITY_DEFAULTS_COVERED_CONTROLS,
)
from app.services.baseline_service import (
    get_msp_baseline,
    resolve_effective_scan_controls,
)
from app.services.break_glass_safeguards import (
    list_break_glass_user_ids_async,
    tag_break_glass_users,
)
from app.services.finding_cleanup import (
    resolve_findings_async,
    resolve_non_baseline_findings_async,
    resolve_stale_user_findings_async,
)
from app.services.remediation_decision_engine import generate_remediation_decisions
from app.services.token_manager import get_valid_access_token
from app.services.ca_policy_states import CA_STATE_REPORT_ONLY
from app.services.graph.graph_fetcher import GraphFetcher
from app.services.detection.conditional_access.ca_mfa_checks import (
    detect_ca_mfa_all_users,
    detect_ca_mfa_admins,
)
from app.services.detection.conditional_access.ca_auth_vector_checks import (
    detect_ca_authentication_transfer_blocked,
    detect_ca_legacy_auth_other_blocked,
    detect_ca_device_code_flow_blocked,
)
from app.services.detection.conditional_access.ca_guest_mfa import (
    detect_ca_guest_mfa,
)
from app.services.detection.conditional_access.ca_policy_checks import (
    detect_ca_break_glass_excluded,
)
from app.services.detection.conditional_access.ca_risk_checks import (
    detect_ca_high_risk_sign_in_block,
    detect_ca_risk_based_step_up_mfa,
)

_ACTIVE_SCAN_TENANTS: set[str] = set()
_SCAN_LOCK = asyncio.Lock()
logger = logging.getLogger(__name__)


async def is_scan_active(tenant_id: str) -> bool:
    async with _SCAN_LOCK:
        return tenant_id in _ACTIVE_SCAN_TENANTS


async def _scan_ca_license_available(db, tenant, *, tenant_id: str) -> bool:
    """Return True if the tenant has a CA-capable (Entra P1/P2) licence.

    Uses the non-mutative /subscribedSkus read (NOT the write-probe), per the
    V1 detection-gating design. Fails OPEN (treats as licensed) on any error so
    a transient Graph failure never silently hides CA findings for a licensed
    tenant — the authoritative write-probe still gates actual remediation.
    """
    try:
        from app.services.remediation_executor import RemediationGraphClient
        from app.services.license_check_service import check_ca_license_from_skus

        graph_client = RemediationGraphClient(db=db, tenant=tenant)
        return await check_ca_license_from_skus(graph_client)
    except Exception:
        logger.exception("identity_scan_ca_license_check_failed tenant_id=%s", tenant_id)
        return True


def _mfa_policy_state(policy: dict) -> str | None:
    if not is_mfa_policy(policy):
        return None
    state = str(policy.get("state") or "").strip()
    if state == "enabled":
        return "enabled"
    if state == CA_STATE_REPORT_ONLY:
        return "report_only"
    return None


def _evaluate_mfa_coverage(
    *,
    user_id: str,
    policies: list[dict],
    all_user_ids: set[str],
    group_member_map: dict[str, set[str]] | None = None,
) -> dict:
    enabled_policy_ids: list[str] = []
    report_only_policy_ids: list[str] = []

    for policy in policies:
        policy_state = _mfa_policy_state(policy)
        if policy_state is None:
            continue
        covered_users = users_covered_by_policy(policy, all_user_ids, group_member_map)
        if user_id not in covered_users:
            continue

        policy_id = policy.get("id")
        if not isinstance(policy_id, str) or not policy_id:
            policy_id = policy.get("displayName") or "<unnamed-policy>"

        if policy_state == "enabled":
            enabled_policy_ids.append(policy_id)
        elif policy_state == "report_only":
            report_only_policy_ids.append(policy_id)

    if enabled_policy_ids:
        return {
            "passed": True,
            "status": "pass",
            "enabled_policy_ids": enabled_policy_ids,
            "report_only_policy_ids": report_only_policy_ids,
        }

    if report_only_policy_ids:
        return {
            "passed": False,
            "status": "partial",
            "enabled_policy_ids": enabled_policy_ids,
            "report_only_policy_ids": report_only_policy_ids,
        }

    return {
        "passed": False,
        "status": "fail",
        "enabled_policy_ids": enabled_policy_ids,
        "report_only_policy_ids": report_only_policy_ids,
    }


async def _safe_upsert_control_result(db: AsyncSession, **kwargs):
    try:
        return await upsert_control_result(db=db, **kwargs)
    except Exception:
        await db.rollback()
        logger.exception(
            "identity_scan_upsert_failed tenant_id=%s control_id=%s resource_id=%s",
            kwargs.get("tenant_id"),
            kwargs.get("control_id"),
            kwargs.get("resource_id"),
        )
        return None


async def _build_role_map(db: AsyncSession, tenant) -> dict[str, list[dict[str, str]]]:
    roles_payload = await graph_get(db, tenant, "/directoryRoles")
    role_map: dict[str, list[dict[str, str]]] = {}

    for role in roles_payload.get("value", []):
        role_name = role.get("displayName")
        role_id = role.get("id")
        if not role_name or not role_id:
            continue

        members_payload = await graph_get(
            db,
            tenant,
            f"/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName",
        )
        members = members_payload.get("value", []) or []
        for member in members:
            if member.get("@odata.type") not in (None, "#microsoft.graph.user"):
                continue
            user_id = member.get("id")
            if not user_id:
                continue
            role_map.setdefault(user_id, []).append(
                {
                    "role_id": role_id,
                    "role_name": role_name,
                }
            )

    return role_map


def _build_user_context(users: list[dict], role_map: dict[str, list[dict[str, str]]]) -> dict[str, dict]:
    user_context: dict[str, dict] = {}

    for user in users:
        user_id = user.get("id")
        if not user_id:
            continue
        roles = role_map.get(user_id, [])
        privileged_role_names = {
            role.get("role_name") for role in roles if role.get("role_name") and is_privileged_role(role["role_name"])
        }
        user_context[user_id] = {
            "user": user,
            "roles": roles,
            "is_admin": len(privileged_role_names) > 0,
        }

    return user_context


async def run_user_controls(
    db: AsyncSession,
    tenant,
    tenant_id: str,
    users: list[dict],
    baseline_controls: set[str],
    workload_activity: dict | None = None,
    workload_available: bool = False,
    security_defaults_enabled: bool | None = None,
) -> None:
    break_glass_user_ids = set(await list_break_glass_user_ids_async(db=db, tenant_id=tenant_id))
    users = tag_break_glass_users(users, break_glass_user_ids=break_glass_user_ids)
    # Break-glass accounts are intentionally exempt from standard controls
    standard_users = [user for user in users if not user.get("is_break_glass")]
    role_map = await _build_role_map(db, tenant)
    user_context = _build_user_context(standard_users, role_map)
    workload_activity = workload_activity or {}
    unused_findings = 0
    if "IDENTITY_UNUSED_ACCOUNT" in baseline_controls:
        for user in standard_users:
            user_id = user.get("id")
            upn = (user.get("userPrincipalName") or "").lower()
            ctx = user_context.get(user_id) or {}
            is_admin = ctx.get("is_admin", False)
            result = evaluate_unused_account(
                user,
                workload_activity.get(upn),
                workload_available=workload_available,
            )
            # Inactive admin accounts carry elevated risk — severity raised to HIGH
            # so that the risk feed surfaces them above standard unused accounts.
            effective_severity = "HIGH" if is_admin and not result["passed"] else result["severity"]
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_type="USER",
                resource_id=user_id,
                passed=result["passed"],
                severity=effective_severity,
                evidence={
                    "user_id": user_id,
                    "user_principal_name": user.get("userPrincipalName"),
                    "display_name": user.get("displayName"),
                    "is_admin": is_admin,
                    **result["evidence"],
                },
                decision_status=result["decision_status"],
            )
            if not result["passed"]:
                unused_findings += 1

        await resolve_findings_async(
            db,
            tenant_id=tenant_id,
            control_ids=["IDENTITY_UNUSED_ACCOUNT"],
            resource_type="TENANT",
        )
    logger.info(
        "identity_scan_service_unused_summary tenant_id=%s unused_findings=%s",
        tenant_id,
        unused_findings,
    )

    if "IDENTITY_MAIL_FORWARDING_RULE" in baseline_controls:
        # Tenant's own domains, derived from its users' UPNs — avoids a separate
        # Graph call/scope just to look up verified domains.
        tenant_domains = {
            (user.get("userPrincipalName") or "").split("@")[-1].lower()
            for user in standard_users
            if "@" in (user.get("userPrincipalName") or "")
        }
        forwarding_findings = 0
        for user in standard_users:
            user_id = user.get("id")
            try:
                rules = await graph_get_all(db, tenant, f"/users/{user_id}/mailFolders/inbox/messageRules")
            except Exception:
                logger.exception(
                    "mail_forwarding_rule_fetch_failed tenant_id=%s user_id=%s — skipping user",
                    tenant_id,
                    user_id,
                )
                continue
            result = evaluate_user_forwarding_rules(user, rules, tenant_domains)
            if result is None:
                await _safe_upsert_control_result(
                    db=db,
                    tenant_id=tenant_id,
                    control_id="IDENTITY_MAIL_FORWARDING_RULE",
                    resource_type="USER",
                    resource_id=user_id,
                    passed=True,
                    severity="CRITICAL",
                    evidence={
                        "user_id": user_id,
                        "user_principal_name": user.get("userPrincipalName"),
                    },
                )
                continue
            forwarding_findings += 1
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id="IDENTITY_MAIL_FORWARDING_RULE",
                resource_type="USER",
                resource_id=user_id,
                passed=False,
                severity=result["severity"],
                evidence=result["evidence"],
            )

        await resolve_findings_async(
            db,
            tenant_id=tenant_id,
            control_ids=["IDENTITY_MAIL_FORWARDING_RULE"],
            resource_type="TENANT",
        )
        logger.info(
            "identity_scan_service_mail_forwarding_summary tenant_id=%s forwarding_findings=%s",
            tenant_id,
            forwarding_findings,
        )

    user_map = {u["id"]: u for u in standard_users}
    all_user_ids = set(user_map.keys())

    # ── MFA enforcement — 3-tier hierarchy ───────────────────────────────────
    #
    # Tier 1 – Security Defaults (tenant-wide, managed by Microsoft)
    #   If enabled, every sign-in requires MFA. Skip all CA evaluation.
    #
    # Tier 2 – Tenant-wide Conditional Access (MVP scope)
    #   Any single enabled CA policy whose includeUsers == "All" AND
    #   grantControls contains "mfa" makes every user protected.
    #   Skip per-user evaluation.
    #
    # Tier 3 – Per-user Conditional Access evaluation
    #   Fall back to checking whether each individual user is covered by an
    #   enabled or report-only CA policy.
    #
    # Fetch failure: ca_mfa_enforced = None → mark findings UNKNOWN (not FAIL)
    # to avoid false positives when Graph is temporarily unavailable.

    if security_defaults_enabled is None:
        security_defaults_enabled = await fetch_security_defaults_enabled(db, tenant)
    logger.info(
        "identity_scan_service_security_defaults tenant_id=%s enabled=%s",
        tenant_id,
        security_defaults_enabled,
    )

    # ca_mfa_enforced:
    #   True  – at least one tenant-wide CA policy enforces MFA
    #   False – policies fetched successfully, none qualify
    #   None  – Graph call failed; enforcement state is unknown
    ca_mfa_enforced: bool | None = False
    ca_mfa_policy_ids: list[str] = []
    mfa_fetch_error: str | None = None
    policies: list[dict] = []

    if security_defaults_enabled is False:
        try:
            policies = await fetch_conditional_access_policies(db, tenant)
            ca_mfa_enforced, ca_mfa_policy_ids = evaluate_tenant_wide_ca_mfa(policies)
            logger.info(
                "identity_scan_service_ca_mfa tenant_id=%s enforced=%s matching_policies=%s",
                tenant_id,
                ca_mfa_enforced,
                ca_mfa_policy_ids,
            )
        except Exception as exc:
            logger.exception(
                "identity_scan_service_mfa_policy_fetch_failed tenant_id=%s",
                tenant_id,
            )
            mfa_fetch_error = str(exc)
            ca_mfa_enforced = None  # unknown — do not assume unprotected

    # Pre-fetch CA group memberships for Tier 3 per-user evaluation.
    # Only needed when policies were fetched successfully AND no tenant-wide
    # policy was detected (ca_mfa_enforced is False).  Each group is queried
    # once here; the result is passed into every per-user coverage check to
    # avoid N+1 Graph calls inside the loop.
    group_member_map: dict[str, set[str]] = {}
    if policies and ca_mfa_enforced is False:
        group_member_map = await build_ca_group_member_map(db, tenant, policies)
        logger.info(
            "identity_scan_service_ca_group_map tenant_id=%s groups_resolved=%s",
            tenant_id,
            len(group_member_map),
        )

    user_mfa_failures = []
    admin_mfa_failures = []
    for uid in all_user_ids:
        user = user_map[uid]
        entry = user_context.get(uid) or {"roles": [], "is_admin": False}
        control_id = "IDENTITY_ADMIN_NO_MFA" if entry["is_admin"] else "IDENTITY_USER_NO_MFA"
        if control_id not in baseline_controls:
            continue

        # Tier 1: Security Defaults — explicitly True; None means unknown
        if security_defaults_enabled is True:
            mfa_eval: dict = {
                "passed": True,
                "status": "security_defaults",
                "enabled_policy_ids": [],
                "report_only_policy_ids": [],
                "ca_policy_detected": False,
            }
            detection_source = "security_defaults"

        # Security Defaults fetch failed — skip CA evaluation entirely;
        # marking UNKNOWN avoids false positives when Graph is temporarily
        # unavailable.  Do NOT fall through to CA tier.
        elif security_defaults_enabled is None:
            mfa_eval = {
                "passed": False,
                "status": "unknown",
                "enabled_policy_ids": [],
                "report_only_policy_ids": [],
                "ca_policy_detected": False,
            }
            detection_source = "unknown"

        # Tier 2: Tenant-wide CA
        elif ca_mfa_enforced is True:
            mfa_eval = {
                "passed": True,
                "status": "conditional_access",
                "enabled_policy_ids": ca_mfa_policy_ids,
                "report_only_policy_ids": [],
                "ca_policy_detected": True,
            }
            detection_source = "conditional_access"

        # Graph fetch failed — enforcement state unknown
        elif ca_mfa_enforced is None:
            mfa_eval = {
                "passed": False,
                "status": "unknown",
                "enabled_policy_ids": [],
                "report_only_policy_ids": [],
                "ca_policy_detected": False,
            }
            detection_source = "unknown"

        # Tier 3: Per-user CA evaluation (includes group-expanded coverage)
        else:
            mfa_eval = _evaluate_mfa_coverage(
                user_id=uid,
                policies=policies,
                all_user_ids=all_user_ids,
                group_member_map=group_member_map,
            )
            mfa_eval = {
                **mfa_eval,
                "ca_policy_detected": len(mfa_eval["enabled_policy_ids"]) > 0,
            }
            # Source reflects whether per-user CA coverage was found or not.
            detection_source = "conditional_access" if mfa_eval["passed"] else "per_user"

        evidence = {
            "user_id": uid,
            "user_principal_name": user.get("userPrincipalName"),
            "display_name": user.get("displayName"),
            "roles": entry["roles"],
            "is_admin": entry["is_admin"],
            "mfa_detection_source": detection_source,
            "mfa_coverage_status": mfa_eval["status"],
            "enabled_mfa_policy_ids": mfa_eval["enabled_policy_ids"],
            "report_only_mfa_policy_ids": mfa_eval["report_only_policy_ids"],
            "ca_policy_detected": mfa_eval["ca_policy_detected"],
            "security_defaults_enabled": security_defaults_enabled,
            "conditional_access_fetch_failed": mfa_fetch_error is not None,
        }
        if mfa_fetch_error:
            evidence["conditional_access_fetch_error"] = mfa_fetch_error

        if mfa_eval["passed"]:
            decision_status = "RESOLVED"
        elif mfa_eval["status"] == "unknown":
            decision_status = "UNKNOWN"
        elif entry["is_admin"]:
            decision_status = "MANUAL_ACTION_REQUIRED"
        else:
            decision_status = "PENDING"

        await _safe_upsert_control_result(
            db=db,
            tenant_id=tenant_id,
            control_id=control_id,
            resource_type="USER",
            resource_id=uid,
            passed=mfa_eval["passed"],
            severity=("LOW" if mfa_eval["passed"] else ("CRITICAL" if entry["is_admin"] else "HIGH")),
            evidence=evidence,
            decision_status=decision_status,
        )
        if mfa_eval["passed"]:
            continue
        if entry["is_admin"]:
            admin_mfa_failures.append(evidence)
        else:
            user_mfa_failures.append(evidence)

    overprivileged_user_findings = []
    if OVERPRIVILEGED_USER_CONTROL_ID in baseline_controls or ADMIN_COUNT_EXCESS_CONTROL_ID in baseline_controls:
        privileged_findings = await detect_overprivileged_controls(db=db, tenant=tenant)
        overprivileged_user_findings = privileged_findings["user_findings"]

        if OVERPRIVILEGED_USER_CONTROL_ID in baseline_controls:
            for finding in overprivileged_user_findings:
                evidence = finding.get("evidence") or {}
                logger.info(
                    "user_admin_eval %s",
                    {
                        "user_id": evidence.get("user_id"),
                        "admin_role_count": evidence.get("admin_role_count"),
                        "roles": [role.get("role_name") for role in evidence.get("roles", [])],
                        "final_passed": finding.get("passed", True),
                    },
                )
                await _safe_upsert_control_result(
                    db=db,
                    tenant_id=tenant_id,
                    control_id=OVERPRIVILEGED_USER_CONTROL_ID,
                    resource_type="USER",
                    resource_id=finding["resource_id"],
                    passed=finding.get("passed", True),
                    severity=finding.get("severity", "LOW"),
                    evidence=evidence,
                    decision_status=("RESOLVED" if finding.get("passed", True) else "PENDING"),
                )

        if ADMIN_COUNT_EXCESS_CONTROL_ID in baseline_controls:
            tenant_finding = privileged_findings["tenant_finding"]
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id=ADMIN_COUNT_EXCESS_CONTROL_ID,
                resource_type="TENANT",
                resource_id=tenant_id,
                passed=tenant_finding.get("passed", True),
                severity=tenant_finding.get("severity", "LOW"),
                evidence=tenant_finding.get("evidence") or {},
                decision_status=("RESOLVED" if tenant_finding.get("passed", True) else "PENDING"),
            )

    logger.info(
        "identity_scan_service_admin_summary tenant_id=%s overprivileged_user_findings=%s",
        tenant_id,
        len(overprivileged_user_findings),
    )

    if "IDENTITY_PASSWORD_NEVER_EXPIRES" in baseline_controls:
        try:
            pw_policy_users = await graph_get_all(db, tenant, "/users?$select=id,passwordPolicies")
            pw_policy_map = {u["id"]: u.get("passwordPolicies") for u in pw_policy_users if u.get("id")}
        except Exception:
            logger.exception("password_never_expires_policy_fetch_failed tenant_id=%s", tenant_id)
            pw_policy_map = {}

        pne_failures = 0
        for user in standard_users:
            user_id = user.get("id")
            if not user_id:
                continue
            result = evaluate_password_never_expires(user, pw_policy_map.get(user_id))
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id="IDENTITY_PASSWORD_NEVER_EXPIRES",
                resource_type="USER",
                resource_id=user_id,
                passed=result["passed"],
                severity=result["severity"],
                evidence=result["evidence"],
                decision_status="RESOLVED" if result["passed"] else "PENDING",
            )
            if not result["passed"]:
                pne_failures += 1

        logger.info(
            "identity_scan_service_pne_summary tenant_id=%s pne_failures=%s",
            tenant_id,
            pne_failures,
        )

    if "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN" in baseline_controls:
        svc_findings = evaluate_service_account_interactive_logins(standard_users)
        for finding in svc_findings:
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id=finding["control_id"],
                resource_type=finding.get("resource_type", "USER"),
                resource_id=finding.get("resource_id", tenant_id),
                passed=finding["passed"],
                severity=finding["severity"],
                evidence=finding.get("evidence") or {},
                decision_status="RESOLVED" if finding["passed"] else "PENDING",
            )

    # Phishing-resistant MFA check — only for target admin roles, per-user Graph call.
    if "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA" in baseline_controls:
        phish_failures = 0
        for uid, ctx in user_context.items():
            if not ctx.get("is_admin"):
                continue
            # Only target the specific high-risk admin roles
            user_role_names = {r.get("role_name") for r in ctx.get("roles", [])}
            if not (user_role_names & _PHISHING_RESISTANT_TARGET_ROLES):
                continue
            try:
                methods_resp = await graph_get(db, tenant, f"/users/{uid}/authentication/methods")
                auth_methods = methods_resp.get("value", []) if isinstance(methods_resp, dict) else []
            except Exception:
                logger.exception(
                    "phishing_resistant_mfa_methods_fetch_failed tenant_id=%s user_id=%s",
                    tenant_id,
                    uid,
                )
                auth_methods = []
            user = user_map.get(uid) or {}
            finding = evaluate_admin_phishing_resistant_mfa(
                user_id=uid,
                user_principal_name=user.get("userPrincipalName"),
                display_name=user.get("displayName"),
                roles=ctx.get("roles", []),
                auth_methods=auth_methods,
            )
            if finding is None:
                continue
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id=finding["control_id"],
                resource_type=finding["resource_type"],
                resource_id=finding["resource_id"],
                passed=finding["passed"],
                severity=finding["severity"],
                evidence=finding.get("evidence") or {},
                decision_status="RESOLVED" if finding["passed"] else "MANUAL_ACTION_REQUIRED",
            )
            if not finding["passed"]:
                phish_failures += 1
        logger.info(
            "identity_scan_phishing_resistant_mfa_summary tenant_id=%s failures=%s",
            tenant_id,
            phish_failures,
        )


_AUTHORIZATION_POLICY_CONTROLS = {
    "IDENTITY_USER_CONSENT_POLICY": "HIGH",
    "IDENTITY_GUEST_INVITES_OPEN": "MEDIUM",
}


async def _fetch_privileged_role_assignments(db: AsyncSession, tenant) -> list[dict]:
    """Active assignments to the privileged roles, one Graph query per role.

    Graph rejects ``roleDefinitionId in (...)`` on this endpoint ("Multiple
    roleDefinitionId in filter not supported"); ``roleDefinitionId eq '<id>'`` is the
    documented form. Any failed query raises, so a role is never silently skipped.
    """
    assignments: list[dict] = []
    for role_definition_id in sorted(_PERMANENT_ROLE_TARGET_IDS):
        assignments.extend(
            await graph_get_all(
                db,
                tenant,
                "/roleManagement/directory/roleAssignments"
                "?$select=id,principalId,roleDefinitionId,directoryScopeId"
                f"&$filter=roleDefinitionId eq '{role_definition_id}'",
            )
        )
    return assignments


async def run_tenant_controls(
    db: AsyncSession,
    tenant,
    tenant_id: str,
    baseline_controls: set[str],
) -> None:
    control_results: list[dict] = []
    try:
        authorization_policy = await graph_get(db, tenant, "/policies/authorizationPolicy")
        identity_snapshot = {
            "authorization_policy": authorization_policy,
        }
        control_results.extend(evaluate_identity_default_controls(identity_snapshot))
    except Exception:
        logger.exception(
            "authorization_policy_fetch_failed tenant_id=%s — marking controls NOT_EVALUATED",
            tenant_id,
        )
        for control_id, severity in _AUTHORIZATION_POLICY_CONTROLS.items():
            if control_id not in baseline_controls:
                continue
            control_results.append(
                {
                    "control_id": control_id,
                    "severity": severity,
                    "passed": None,
                    "evidence": {"reason": "authorization_policy_fetch_failed"},
                }
            )
    if "IDENTITY_ILLICIT_CONSENT_GRANTS" in baseline_controls:
        try:
            illicit_grants_result = await detect_illicit_consent_grants(
                db=db,
                tenant=tenant,
            )
        except Exception:
            logger.exception(
                "illicit_consent_grants_detection_failed tenant_id=%s",
                tenant_id,
            )
        else:
            control_results.append(illicit_grants_result)
    if "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in baseline_controls:
        try:
            oauth_consent_result = await detect_oauth_app_consent(
                db=db,
                tenant=tenant,
            )
        except Exception:
            logger.exception(
                "oauth_app_consent_discovery_failed tenant_id=%s",
                tenant_id,
            )
        else:
            control_results.append(oauth_consent_result)
    if "IDENTITY_APP_SECRET_EXPIRING_SOON" in baseline_controls:
        try:
            apps = await graph_get_all(
                db,
                tenant,
                "/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials",
            )
            app_findings = evaluate_all_app_secret_expiry(apps)
            affected_apps = [f["evidence"] for f in app_findings]
            overall_severity = aggregate_app_secret_severity(app_findings)
            expired_count = sum(1 for f in app_findings if f["evidence"].get("already_expired_count", 0) > 0)
            control_results.append(
                {
                    "control_id": "IDENTITY_APP_SECRET_EXPIRING_SOON",
                    "severity": overall_severity,
                    "passed": len(affected_apps) == 0,
                    "evidence": {
                        "affected_app_count": len(affected_apps),
                        "total_app_count": len(apps),
                        "expired_app_count": expired_count,
                        "worst_severity": overall_severity,
                        "affected_apps": affected_apps,
                    },
                }
            )
        except Exception:
            logger.exception("app_secret_expiry_detection_failed tenant_id=%s", tenant_id)
    if "IDENTITY_BREAK_GLASS_ACCOUNT" in baseline_controls:
        control_results.append(
            await detect_break_glass_accounts(
                db=db,
                tenant=tenant,
            )
        )
    if settings.CLX_INJECT_TEST_TENANT_CONTROL:
        control_results.append(
            {
                "control_id": "TEST_TENANT_CONTROL",
                "severity": "HIGH",
                "passed": False,
                "evidence": {"injected": True},
            }
        )

    for finding in control_results:
        if finding["control_id"] not in baseline_controls:
            continue
        logger.info(
            "TENANT_CONTROL_EVALUATED control_id=%s tenant_id=%s passed=%s",
            finding["control_id"],
            tenant_id,
            finding["passed"],
        )
        saved = await _safe_upsert_control_result(
            db=db,
            tenant_id=tenant_id,
            control_id=finding["control_id"],
            resource_type="TENANT",
            resource_id=tenant_id,
            passed=finding["passed"],
            severity=finding["severity"],
            evidence=finding["evidence"],
            decision_status="RESOLVED" if finding["passed"] else "PENDING",
        )
        logger.info(
            "TENANT_RESULT_SAVED control_id=%s tenant_id=%s compliance_result_id=%s",
            finding["control_id"],
            tenant_id,
            getattr(saved, "id", None),
        )

    # Permanent role assignment scan — fail-open; per-user findings.
    if "IDENTITY_PERMANENT_ROLE_ASSIGNMENT" in baseline_controls:
        try:
            role_assignments = await _fetch_privileged_role_assignments(db, tenant)
            try:
                eligible_schedules = await graph_get_all(
                    db,
                    tenant,
                    "/roleManagement/directory/roleEligibilitySchedules" "?$select=principalId,roleDefinitionId",
                )
                pim_check_available = True
            except Exception:
                logger.warning(
                    "pim_eligibility_check_unavailable tenant_id=%s — proceeding without PIM data",
                    tenant_id,
                )
                eligible_schedules = []
                pim_check_available = False

            pra_findings = evaluate_permanent_role_assignments(
                role_assignments=role_assignments,
                eligible_schedules=eligible_schedules,
                pim_check_available=pim_check_available,
            )
            for finding in pra_findings:
                await _safe_upsert_control_result(
                    db=db,
                    tenant_id=tenant_id,
                    control_id=finding["control_id"],
                    resource_type=finding.get("resource_type", "USER"),
                    resource_id=finding.get("resource_id", tenant_id),
                    passed=finding["passed"],
                    severity=finding["severity"],
                    evidence=finding.get("evidence") or {},
                    decision_status="RESOLVED" if finding["passed"] else "PENDING",
                )
            logger.info(
                "identity_scan_permanent_role_summary tenant_id=%s findings=%s",
                tenant_id,
                len(pra_findings),
            )
        except Exception:
            logger.exception("permanent_role_assignment_scan_failed tenant_id=%s", tenant_id)

    # Stale service principal scan — fail-open; uses per-SP resource_id.
    if "IDENTITY_STALE_SERVICE_PRINCIPAL" in baseline_controls:
        try:
            service_principals = await graph_get_all(
                db,
                tenant,
                "/servicePrincipals?$select=id,displayName,appId,appDisplayName,"
                "accountEnabled,signInActivity&$expand=owners($select=id,displayName,userPrincipalName)",
            )
            owners_map: dict[str, list[dict]] = {}
            for _sp in service_principals:
                _sp_id = _sp.get("id")
                if _sp_id:
                    owners_map[_sp_id] = [
                        {
                            "id": o.get("id"),
                            "displayName": o.get("displayName"),
                            "userPrincipalName": o.get("userPrincipalName"),
                        }
                        for o in (_sp.get("owners") or [])
                        if isinstance(o, dict) and o.get("id")
                    ]
            sp_findings = evaluate_stale_service_principals(service_principals, owners_map=owners_map)
            for finding in sp_findings:
                await _safe_upsert_control_result(
                    db=db,
                    tenant_id=tenant_id,
                    control_id=finding["control_id"],
                    resource_type=finding.get("resource_type", "SERVICE_PRINCIPAL"),
                    resource_id=finding.get("resource_id", tenant_id),
                    passed=finding["passed"],
                    severity=finding["severity"],
                    evidence=finding.get("evidence") or {},
                    decision_status="RESOLVED" if finding["passed"] else "PENDING",
                )
        except Exception:
            logger.exception("stale_service_principal_scan_failed tenant_id=%s", tenant_id)


async def run_extended_controls(
    *,
    ctx,
    db: AsyncSession,
    tenant_id: str,
    baseline_controls: set[str],
) -> None:
    _CA_CHECKS = [
        detect_ca_mfa_all_users,
        detect_ca_mfa_admins,
        detect_ca_legacy_auth_other_blocked,
        detect_ca_device_code_flow_blocked,
        detect_ca_authentication_transfer_blocked,
        detect_ca_guest_mfa,
        detect_ca_break_glass_excluded,
        detect_ca_high_risk_sign_in_block,
        detect_ca_risk_based_step_up_mfa,
    ]

    result_lists = await asyncio.gather(
        *[fn(ctx=ctx) for fn in _CA_CHECKS],
        return_exceptions=True,
    )

    for check_fn, result in zip(_CA_CHECKS, result_lists):
        check_name = check_fn.__name__
        if isinstance(result, Exception):
            logger.exception(
                "extended_control_check_crashed tenant_id=%s check=%s",
                tenant_id,
                check_name,
                exc_info=result,
            )
            continue
        for finding in result:
            control_id = finding.get("control_id")
            if control_id not in baseline_controls:
                continue
            await _safe_upsert_control_result(
                db=db,
                tenant_id=tenant_id,
                control_id=control_id,
                resource_type=finding.get("resource_type", "TENANT"),
                resource_id=finding.get("resource_id", tenant_id),
                passed=finding.get("passed", True),
                severity=finding.get("severity", "LOW"),
                evidence=finding.get("evidence") or {},
                decision_status="RESOLVED" if finding.get("passed", True) else "PENDING",
            )


async def _claim_scan_slot(tenant_id: str) -> bool:
    async with _SCAN_LOCK:
        if tenant_id in _ACTIVE_SCAN_TENANTS:
            return False
        _ACTIVE_SCAN_TENANTS.add(tenant_id)
        return True


async def _release_scan_slot(tenant_id: str) -> None:
    async with _SCAN_LOCK:
        _ACTIVE_SCAN_TENANTS.discard(tenant_id)


async def _run_scan_claimed(tenant_id: str):
    try:
        async with AsyncSessionLocal() as db:
            tenant = await get_tenant(tenant_id, db)
            await run_identity_scan(db=db, tenant=tenant, tenant_id=tenant_id)
    finally:
        await _release_scan_slot(tenant_id)


async def start_scan_task(tenant_id: str) -> bool:
    claimed = await _claim_scan_slot(tenant_id)
    if not claimed:
        return False

    asyncio.create_task(_run_scan_claimed(tenant_id))
    return True


async def run_identity_scan(db: AsyncSession, tenant, tenant_id: str | None = None):
    """
    Runs full identity posture scan with deterministic per-tenant results.
    """
    tenant_id = tenant_id or tenant.id
    if tenant.id != tenant_id:
        raise ValueError("Identity scan tenant mismatch")

    tenant.last_scheduler_run = to_naive_utc(utc_now())
    await db.commit()

    try:
        fetched_users = await fetch_users(db, tenant)
        logger.info(
            "identity_scan_service_user_fetch tenant_id=%s total_users_fetched=%s",
            tenant_id,
            len(fetched_users),
        )
        users = dedupe_directory_users(fetched_users, include_disabled=True)
        logger.info(
            "identity_scan_service_user_filter tenant_id=%s users_after_filtering=%s",
            tenant_id,
            len(users),
        )
        logger.info(
            "identity_scan_service_detector_input tenant_id=%s users_passed_to_detectors=%s",
            tenant_id,
            len(users),
        )
        baseline_controls = set(await get_msp_baseline(db, tenant.organization_id))
        # Always-monitored controls are evaluated regardless of baseline; gated
        # CA controls are dropped when the tenant has no Entra P1/P2 licence so
        # they never produce FAIL findings the tenant cannot remediate — unless
        # Entra Security Defaults is enabled, in which case CA_MFA_ALL_USERS and
        # CA_MFA_ADMINS stay evaluated (see SECURITY_DEFAULTS_COVERED_CONTROLS).
        # Fetched once here and threaded through to CA context below so it is
        # never re-fetched from Graph twice in the same scan.
        ca_licensed = await _scan_ca_license_available(db, tenant, tenant_id=tenant_id)
        security_defaults_enabled = await fetch_security_defaults_enabled(db, tenant)
        baseline_controls = resolve_effective_scan_controls(
            baseline_controls,
            ca_licensed=ca_licensed,
            security_defaults_enabled=security_defaults_enabled,
        )
        license_unavailable_controls = None
        if not ca_licensed:
            license_unavailable_controls = set(LICENSE_GATED_CA_CONTROLS)
            if security_defaults_enabled is True:
                license_unavailable_controls -= SECURITY_DEFAULTS_COVERED_CONTROLS
        await resolve_non_baseline_findings_async(
            db,
            tenant_id=tenant_id,
            baseline_controls=baseline_controls,
            # When the tenant lacks the required licence, CA controls are removed
            # from the effective baseline.  Pass the gated set so the cleanup
            # marks those findings NOT_EVALUATED (passed=None) rather than PASS.
            license_unavailable_controls=license_unavailable_controls,
        )
        workload_activity, workload_available = await fetch_workload_activity(db, tenant)
        logger.info(
            "identity_scan_service_workload_activity tenant_id=%s rows=%s available=%s",
            tenant_id,
            len(workload_activity),
            workload_available,
        )
        await run_user_controls(
            db=db,
            tenant=tenant,
            tenant_id=tenant_id,
            users=users,
            baseline_controls=baseline_controls,
            workload_activity=workload_activity,
            workload_available=workload_available,
            security_defaults_enabled=security_defaults_enabled,
        )

        # ── Stale user finding cleanup ────────────────────────────────────────
        # active_user_ids uses the Graph object GUID (user["id"]) — the same
        # value stored as resource_id on USER-scoped compliance findings.
        # Disabled accounts are included (include_disabled=True above) so only
        # truly deleted users are caught here.
        #
        # Safety guard: if the Graph fetch returned 0 users (error path in
        # fetch_users returns []), skip cleanup entirely — resolving against an
        # empty set would wipe every user finding for this tenant.
        #
        # Commit immediately after cleanup so the resolutions are durable even
        # if a later scan step (tenant controls, snapshot) rolls back.
        active_user_ids = {u["id"] for u in users if u.get("id")}
        logger.info(
            "identity_scan_service_stale_cleanup_start tenant_id=%s active_user_ids=%s",
            tenant_id,
            len(active_user_ids),
        )
        if not active_user_ids:
            logger.warning(
                "identity_scan_service_stale_cleanup_skipped "
                "tenant_id=%s reason=empty_active_user_set — Graph fetch likely failed",
                tenant_id,
            )
        else:
            stale_resolved = await resolve_stale_user_findings_async(
                db,
                tenant_id=tenant_id,
                active_user_ids=active_user_ids,
            )
            await db.commit()
            logger.info(
                "identity_scan_service_stale_user_cleanup tenant_id=%s resolved=%s",
                tenant_id,
                stale_resolved,
            )

        await run_tenant_controls(
            db=db,
            tenant=tenant,
            tenant_id=tenant_id,
            baseline_controls=baseline_controls,
        )

        # Extended controls (CA checks) — additive, never blocks existing scan.
        try:
            access_token = await get_valid_access_token(tenant_id, db=db)
            bg_ids = [str(x) for x in await list_break_glass_user_ids_async(db=db, tenant_id=tenant_id)]
            ctx = await GraphFetcher().build_context(
                tenant_id,
                access_token,
                break_glass_accounts=bg_ids,
                security_defaults_enabled=security_defaults_enabled,
            )
            await run_extended_controls(
                ctx=ctx,
                db=db,
                tenant_id=tenant_id,
                baseline_controls=baseline_controls,
            )
        except Exception:
            logger.exception("identity_scan_service_extended_controls_failed tenant_id=%s", tenant_id)

        await generate_remediation_decisions(
            db=db,
            tenant_id=tenant_id,
        )
        previous_snapshot = await get_latest_posture_snapshot_async(db, tenant_id)
        new_snapshot = await create_posture_snapshot_async(
            db,
            tenant_id=tenant_id,
            reason="scan",
        )
        try:
            posture_alerts = generate_posture_alerts(
                previous_snapshot.posture if previous_snapshot else None,
                new_snapshot.posture,
            )
            if posture_alerts:
                await create_alerts(db, tenant_id=tenant_id, alerts=posture_alerts)
        except Exception:
            logger.exception(
                "identity_scan_service_posture_alert_generation_failed tenant_id=%s",
                tenant_id,
            )

        tenant.last_scan_at = to_naive_utc(utc_now())
        tenant.scheduler_failures = 0
        await db.commit()

    except Exception:
        tenant.scheduler_failures = (tenant.scheduler_failures or 0) + 1
        await db.commit()
        raise


async def run_scan(tenant_id: str):
    claimed = await _claim_scan_slot(tenant_id)
    if not claimed:
        return False

    try:
        async with AsyncSessionLocal() as db:
            tenant = await get_tenant(tenant_id, db)
            await run_identity_scan(db=db, tenant=tenant, tenant_id=tenant_id)
        return True
    finally:
        await _release_scan_slot(tenant_id)
