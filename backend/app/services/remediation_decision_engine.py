from datetime import timezone

from sqlalchemy import select

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.services.remediation.control_registry import get_control_capabilities


def ensure_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def decide_for_compliance_result(finding) -> dict:
    capabilities = get_control_capabilities(finding.control_id)
    if not capabilities["is_executable"]:
        return {
            "decision": "MANUAL_ACTION_REQUIRED",
            "confidence": "HIGH",
            "explanation": {
                "summary": "Control does not support automated remediation",
                "key_factors": [
                    "automation_not_supported",
                    f"control_{finding.control_id.lower()}",
                ],
                "risk_note": "Manual remediation is required",
            },
        }

    if finding.control_id == "IDENTITY_UNUSED_ACCOUNT":
        is_admin = finding.evidence.get("is_admin", False)

        if not is_admin:
            return {
                "decision": "AUTO_REMEDIATE",
                "confidence": "HIGH",
                "explanation": {
                    "summary": "Dormant non-admin account eligible for auto-disable",
                    "key_factors": [
                        "account_age_exceeded_threshold",
                        "non_admin_user",
                    ],
                    "risk_note": "Rollback available",
                },
            }

        return {
            "decision": "REQUIRE_APPROVAL",
            "confidence": "MEDIUM",
            "explanation": {
                "summary": "Dormant high-risk account requires approval",
                "key_factors": ["admin_or_high_severity"],
                "risk_note": "Manual review required",
            },
        }

    if finding.control_id == "IDENTITY_OVERPRIVILEGED_USER":
        role_count = int((finding.evidence or {}).get("admin_role_count") or 0)
        severity = str(getattr(finding, "severity", "") or "").upper()
        return {
            "decision": "REQUIRE_APPROVAL",
            "confidence": "HIGH" if severity == "HIGH" or role_count >= 3 else "MEDIUM",
            "explanation": {
                "summary": "User has multiple admin roles and needs explicit role selection before remediation",
                "key_factors": [
                    "multiple_admin_roles_assigned",
                    f"admin_role_count_{role_count}",
                ],
                "risk_note": "Preview and rollback are available for selected role removals",
            },
        }

    if finding.control_id == "IDENTITY_ADMIN_COUNT_EXCESS":
        global_admin_count = int((finding.evidence or {}).get("global_admin_count") or 0)
        return {
            "decision": "REQUIRE_APPROVAL",
            "confidence": "MEDIUM",
            "explanation": {
                "summary": "Tenant has more Global Administrators than policy allows",
                "key_factors": [
                    "tenant_level_privileged_access_excess",
                    f"global_admin_count_{global_admin_count}",
                ],
                "risk_note": "Review affected accounts and remediate through the related user findings",
            },
        }

    return {
        "decision": "REQUIRE_APPROVAL",
        "confidence": "LOW",
        "explanation": {
            "summary": "Control requires manual approval",
            "key_factors": [],
            "risk_note": "",
        },
    }


async def generate_remediation_decisions(*, db, tenant_id: str) -> int:
    result = await db.execute(
        select(ComplianceResult)
        .where(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.exposure_status == "ACTIVE",
            ComplianceResult.passed.is_(False),
        )
        .order_by(ComplianceResult.evaluated_at.asc(), ComplianceResult.id.asc())
    )
    findings = result.scalars().all()

    generated = 0
    for finding in findings:
        anchor_at = finding.drift_detected_at or finding.first_seen_at or finding.evaluated_at

        latest_result = await db.execute(
            select(RemediationAuditLog)
            .where(
                RemediationAuditLog.tenant_id == tenant_id,
                RemediationAuditLog.compliance_result_id == finding.id,
                RemediationAuditLog.explanation_summary != "Event recorded",
                RemediationAuditLog.explanation_summary != "Rollback executed",
            )
            .order_by(RemediationAuditLog.created_at.desc())
            .limit(1)
        )
        latest_decision = latest_result.scalars().first()

        latest_created = ensure_utc(latest_decision.created_at) if latest_decision else None
        anchor = ensure_utc(anchor_at)

        if latest_decision and anchor and latest_created and latest_created >= anchor:
            continue

        decision = decide_for_compliance_result(finding)
        explanation = decision.get("explanation") or {}
        confidence_map = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
        finding.decision_status = decision["decision"]

        log = RemediationAuditLog(
            tenant_id=tenant_id,
            compliance_result_id=finding.id,
            control_id=finding.control_id,
            resource_type=finding.resource_type,
            resource_id=finding.resource_id,
            decision=decision["decision"],
            confidence=confidence_map.get(decision.get("confidence"), 0.0),
            explanation_summary=explanation.get("summary", "No explanation recorded"),
            explanation_factors=explanation.get("key_factors", []),
            explanation_risk_note=explanation.get("risk_note", ""),
        )
        db.add(log)
        generated += 1

    if generated:
        await db.commit()

    return generated
