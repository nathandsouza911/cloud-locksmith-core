from types import SimpleNamespace

from app.db.models.compliance_result import ComplianceResult
from app.services.graph_client import fetch_user_memberof_directory_roles, graph_get
from app.services.scoring.identity_posture_score import calculate_identity_posture_score

# Static, conservative monthly price estimates for preview-only savings.
# These are informational and do not drive any automated changes.
LICENSE_PRICE_ESTIMATES = {
    "ENTERPRISEPACK": 36.00,  # Microsoft 365 E3
    "SPE_E5": 57.00,  # Microsoft 365 E5
    "SPE_E3": 36.00,  # Microsoft 365 E3 (alt SKU)
    "SPE_F1": 2.25,  # Microsoft 365 F1
    "SPE_F3": 8.00,  # Microsoft 365 F3
    "BUSINESS_PREMIUM": 22.00,  # M365 Business Premium
    "O365_BUSINESS_PREMIUM": 12.50,  # Office 365 Business Premium (legacy)
    "STANDARDPACK": 12.50,  # Office 365 E1
    "M365EDU_A3_FACULTY": 2.50,  # EDU estimate
    "M365EDU_A5_FACULTY": 6.00,  # EDU estimate
}


async def _safe_graph_get(db, tenant, path: str):
    try:
        data = await graph_get(db, tenant, path)
    except Exception:
        return None

    if isinstance(data, dict) and data.get("_error"):
        return None

    return data


def _count_values(payload):
    if not payload or not isinstance(payload, dict):
        return None
    values = payload.get("value")
    if not isinstance(values, list):
        return None
    return len(values)


def _estimate_license_savings(license_details):
    if not license_details or not isinstance(license_details, dict):
        return None

    total = 0.0
    for item in license_details.get("value", []):
        sku = item.get("skuPartNumber")
        if sku in LICENSE_PRICE_ESTIMATES:
            total += LICENSE_PRICE_ESTIMATES[sku]

    return total


async def preview_offboarding(
    db,
    tenant,
    user_id: str,
    options: dict,
    force: bool = False,
):
    """
    Preview offboarding actions and score impact.
    Admin users are blocked unless force=True.
    """

    user = await graph_get(db, tenant, f"/users/{user_id}")
    if not user:
        raise ValueError("User not found")

    roles = await fetch_user_memberof_directory_roles(db, tenant, user_id)
    member_of = await _safe_graph_get(db, tenant, f"/users/{user_id}/memberOf")
    member_values = member_of.get("value", []) if isinstance(member_of, dict) else None
    groups = (
        [g for g in (member_values or []) if g.get("@odata.type") == "#microsoft.graph.group"]
        if member_values is not None
        else None
    )

    is_admin = len(roles) > 0
    is_global_admin = any(r.get("displayName") == "Global Administrator" for r in roles)

    shared_resources = await _safe_graph_get(
        db,
        tenant,
        f"/users/{user_id}/drive/sharedWithMe",
    )
    guest_relationships = await _safe_graph_get(
        db,
        tenant,
        f"/users/{user_id}/transitiveMemberOf/microsoft.graph.user" "?$filter=userType%20eq%20'Guest'",
    )
    license_details = await _safe_graph_get(
        db,
        tenant,
        f"/users/{user_id}/licenseDetails",
    )

    exposure_counts = {
        "group_memberships": len(groups) if isinstance(groups, list) else None,
        "shared_resources": _count_values(shared_resources),
        "guest_relationships": _count_values(guest_relationships),
    }
    estimated_license_savings = _estimate_license_savings(license_details)

    user_info = {
        "id": user.get("id"),
        "upn": user.get("userPrincipalName"),
        "display_name": user.get("displayName"),
    }

    actions = {
        "revoke_sessions": True,
        "disable_account": True,
        "remove_admin_roles": True,
        "capture_identity_snapshot": True,
    }

    guardrails = {
        "snapshot_confirmation_required": True,
        "continuous_monitoring_notice": (
            "Post-offboarding monitoring remains active to detect unexpected " "identity changes."
        ),
    }

    if is_admin and not force:
        return {
            "eligible": False,
            "blocked": True,
            "reason": (
                "This user holds administrative roles. "
                "Offboarding is blocked by default to prevent tenant lockout. "
                "Re-run preview with force=true to override."
            ),
            "is_global_admin": is_global_admin,
            "user": user_info,
            "admin_roles": [r.get("displayName") for r in roles],
            "exposure_counts": exposure_counts,
            "estimated_license_savings": estimated_license_savings,
            "actions": actions,
            "guardrails": guardrails,
        }

    results = db.query(ComplianceResult).filter(ComplianceResult.tenant_id == tenant.id).all()

    current_score = calculate_identity_posture_score(results)["score"]

    simulated_results = []
    for r in results:
        if r.control_id in (
            "IDENTITY_UNUSED_ACCOUNT",
            "IDENTITY_OVERPRIVILEGED_USER",
        ):
            simulated_results.append(
                SimpleNamespace(
                    passed=True,
                    severity=r.severity,
                    control_id=r.control_id,
                )
            )
        else:
            simulated_results.append(r)

    new_score = calculate_identity_posture_score(simulated_results)["score"]

    return {
        "eligible": True,
        "blocked": False,
        "reason": None,
        "user": {
            "id": user["id"],
            "upn": user["userPrincipalName"],
            "display_name": user["displayName"],
        },
        "admin_roles": [r.get("displayName") for r in roles],
        "exposure_counts": exposure_counts,
        "estimated_license_savings": estimated_license_savings,
        "actions": actions,
        "guardrails": guardrails,
        "current_score": current_score,
        "estimated_score_after": new_score,
        "estimated_improvement": new_score - current_score,
        "informational_only": ["exposure_counts", "estimated_license_savings"],
    }
