import asyncio

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.services.attack_path_engine import summarize_attack_paths
from app.services.compliance_enrichment import get_framework_mappings
from app.services.graph_client import GraphAPIError, graph_get
from app.services.graph_client import graph_error_ui_label
from app.services.license_service import control_license_satisfied, control_requires_p1, get_tenant_license
from app.services.posture_snapshot_service import get_latest_posture_snapshot
from app.services.remediation.lifecycle import current_remediation_status
from app.services.scoring.identity_risk_score import build_risk_summary, calculate_fix_impact
from app.services.scoring.remediation_priority_model import (
    compute_priority_score,
    effective_severity_for_finding,
)


def _resource_type_label(resource_type: str | None) -> str:
    if not resource_type:
        return "Resource"
    return resource_type.replace("_", " ").title()


def _coerce_string(value) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


async def _fetch_user_identity_from_graph(
    *,
    db: Session,
    tenant: Tenant | None,
    user_id: str,
) -> dict[str, str | bool | None]:
    if tenant is None:
        return {"resource_name": None, "resource_email": None, "is_admin": None}

    try:
        payload = await graph_get(
            db,
            tenant,
            f"/users/{user_id}?$select=id,displayName,userPrincipalName",
        )
    except (GraphAPIError, RuntimeError):
        return {"resource_name": None, "resource_email": None, "is_admin": None}

    if not isinstance(payload, dict):
        return {"resource_name": None, "resource_email": None, "is_admin": None}

    return {
        "resource_name": _coerce_string(payload.get("displayName")),
        "resource_email": _coerce_string(payload.get("userPrincipalName")),
        "is_admin": None,
    }


async def _build_user_identity_map(
    *,
    db: Session,
    tenant: Tenant | None,
    rows: list[tuple[ComplianceResult, str]],
) -> dict[str, dict[str, str | bool | None]]:
    user_ids = {
        compliance.resource_id
        for compliance, _tenant_name in rows
        if compliance.resource_type == "USER" and compliance.resource_id
    }
    if not user_ids:
        return {}

    cached_users = (
        db.query(User)
        .filter(
            User.tenant_id == tenant.id if tenant is not None else False,
            User.external_id.in_(list(user_ids)),
        )
        .all()
        if tenant is not None
        else []
    )
    identity_map = {
        user.external_id: {
            "resource_name": _coerce_string(user.display_name),
            "resource_email": _coerce_string(user.email),
            "is_admin": bool(user.is_admin),
        }
        for user in cached_users
        if user.external_id
    }

    missing_user_ids = [
        user_id
        for user_id in user_ids
        if not identity_map.get(user_id, {}).get("resource_name")
        and not identity_map.get(user_id, {}).get("resource_email")
    ]
    if not missing_user_ids:
        return identity_map

    graph_results = await asyncio.gather(
        *[
            _fetch_user_identity_from_graph(
                db=db,
                tenant=tenant,
                user_id=user_id,
            )
            for user_id in missing_user_ids
        ]
    )
    for user_id, graph_identity in zip(missing_user_ids, graph_results):
        cached_identity = identity_map.get(user_id, {})
        identity_map[user_id] = {
            "resource_name": (cached_identity.get("resource_name") or graph_identity.get("resource_name")),
            "resource_email": (cached_identity.get("resource_email") or graph_identity.get("resource_email")),
            "is_admin": cached_identity.get("is_admin"),
        }

    return identity_map


async def get_risk_feed(
    db: Session,
    tenant_id: str,
    limit: int = 50,
    include_ignored: bool = True,
):
    query = (
        select(ComplianceResult, Tenant.tenant_name)
        .join(Tenant, Tenant.id == ComplianceResult.tenant_id)
        .where(
            or_(
                ComplianceResult.exposure_status == "ACTIVE",
                (
                    (ComplianceResult.control_id == "IDENTITY_UNUSED_ACCOUNT")
                    & (ComplianceResult.exposure_status == "RESOLVED")
                    & (ComplianceResult.remediation_status == "SUCCESS")
                    & (ComplianceResult.resolved_by != "OFFBOARDING")
                ),
            ),
            ComplianceResult.tenant_id == tenant_id,
        )
    )

    result = db.execute(query)

    rows = result.all()
    failed_controls = {
        compliance.control_id
        for compliance, _tenant_name in rows
        if isinstance(compliance.control_id, str)
        and compliance.control_id
        and compliance.passed is False
        and compliance.exposure_status == "ACTIVE"
    }
    attack_path_summary = summarize_attack_paths(failed_controls)
    attack_path_controls = attack_path_summary.get("affected_controls") or set()
    critical_attack_path_controls = attack_path_summary.get("critical_controls") or set()

    latest_snapshot = get_latest_posture_snapshot(db, tenant_id)
    latest_posture = latest_snapshot.posture if latest_snapshot and isinstance(latest_snapshot.posture, dict) else {}
    tenant_record = db.get(Tenant, tenant_id)
    current_results = [compliance for compliance, _tenant_name in rows]
    current_score = latest_posture.get("score")
    if current_score is None:
        current_score = build_risk_summary(current_results)["score"]

    try:
        tenant_license = await get_tenant_license(
            tenant_id=tenant_id,
            db=db,
            tenant=tenant_record,
        )
    except Exception:
        tenant_license = {"has_p1": False, "has_p2": False}

    user_identity_map = await _build_user_identity_map(
        db=db,
        tenant=tenant_record,
        rows=rows,
    )
    feed = []

    for compliance, tenant_name in rows:
        remediation_status = current_remediation_status(compliance)
        if remediation_status == "IGNORED" and not include_ignored:
            continue

        requires_license = control_requires_p1(compliance.control_id)
        license_available = control_license_satisfied(compliance.control_id, tenant_license)
        # Licence-unavailable CA controls are NOT_EVALUATED for this tenant —
        # they must never surface as actionable FAIL findings the tenant cannot
        # remediate. (Defence in depth: the scanner already skips writing these
        # rows for unlicensed tenants.)
        if requires_license and not license_available:
            continue
        approval_status = (
            "approved"
            if remediation_status
            in {
                "APPROVED",
                "EXECUTING",
                "SUCCESS",
                "IGNORED",
            }
            else "pending"
        )
        execution_status = (
            "executed"
            if remediation_status == "SUCCESS"
            else "ignored"
            if remediation_status == "IGNORED"
            else "pending"
        )
        evidence = compliance.evidence if isinstance(compliance.evidence, dict) else {}
        error_type = evidence.get("error_type")
        if not isinstance(error_type, str):
            error_type = None
        impact_score = calculate_fix_impact(
            current_results=current_results,
            current_score=current_score,
            target_result=compliance,
        )
        resource_name = None
        resource_email = None
        is_admin = False
        if compliance.resource_type == "USER":
            user_identity = user_identity_map.get(compliance.resource_id, {})
            evidence_roles = evidence.get("current_roles") or evidence.get("roles") or []
            is_admin = bool(
                user_identity.get("is_admin")
                or evidence.get("is_admin") is True
                or (isinstance(evidence_roles, list) and len(evidence_roles) > 0)
            )
            resource_name = (
                user_identity.get("resource_name")
                or _coerce_string(evidence.get("display_name"))
                or _coerce_string(evidence.get("user_display_name"))
                or compliance.resource_id
            )
            resource_email = (
                user_identity.get("resource_email")
                or _coerce_string(evidence.get("user_principal_name"))
                or _coerce_string(evidence.get("resource_email"))
            )
        else:
            if compliance.control_id == "IDENTITY_BREAK_GLASS_USAGE":
                resource_name = (
                    _coerce_string(evidence.get("display_name"))
                    or _coerce_string(evidence.get("user_principal_name"))
                    or "Break-glass account"
                )
                resource_email = _coerce_string(evidence.get("user_principal_name"))
            else:
                resource_name = _resource_type_label(compliance.resource_type)

        is_attack_path = compliance.control_id in attack_path_controls
        effective_severity = effective_severity_for_finding(
            compliance,
            critical_attack_path_controls=critical_attack_path_controls,
        )

        feed.append(
            {
                "compliance_result_id": compliance.id,
                "tenant_id": compliance.tenant_id,
                "tenant_name": tenant_name,
                "control_id": compliance.control_id,
                "resource_type": compliance.resource_type,
                "resource_id": compliance.resource_id,
                "resource_name": resource_name,
                "resource_email": resource_email,
                "is_admin": is_admin,
                "severity": effective_severity,
                "available_roles": evidence.get("available_roles", []),
                "current_roles": evidence.get("current_roles", []),
                "exposure_status": compliance.exposure_status,
                "remediation_status": remediation_status,
                "acknowledged": bool(getattr(compliance, "acknowledged", False)),
                "acknowledged_at": getattr(compliance, "acknowledged_at", None),
                "acknowledged_by": getattr(compliance, "acknowledged_by", None),
                "requires_acknowledgment": compliance.control_id == "IDENTITY_BREAK_GLASS_USAGE",
                "action": (
                    {
                        "action": "acknowledge",
                        "label": "Mark as Authorized",
                    }
                    if compliance.control_id == "IDENTITY_BREAK_GLASS_USAGE"
                    and not getattr(compliance, "acknowledged", False)
                    else None
                ),
                "error_type": error_type,
                "error_label": graph_error_ui_label(error_type),
                "resolved_at": compliance.resolved_at,
                "resolved_by": compliance.resolved_by,
                "first_seen_at": compliance.first_seen_at,
                "last_seen_at": compliance.last_seen_at,
                "drift_count": compliance.drift_count,
                "labels": [
                    *(["Reopened"] if (compliance.drift_count or 0) > 0 else []),
                    *(["Ignored"] if remediation_status == "IGNORED" else []),
                ],
                "requires_license": requires_license,
                "license_available": license_available,
                "approval_status": approval_status,
                "execution_status": execution_status,
                "evaluated_at": compliance.evaluated_at,
                "impact_score": impact_score,
                "priority_score": compute_priority_score(
                    compliance,
                    attack_path_controls=attack_path_controls,
                    critical_attack_path_controls=critical_attack_path_controls,
                ),
                "is_attack_path": is_attack_path,
                "framework_mappings": get_framework_mappings(compliance.control_id),
            }
        )

    feed.sort(
        key=lambda item: (
            -item["priority_score"],
            item["control_id"],
            item["resource_id"],
        )
    )
    return feed[:limit]
