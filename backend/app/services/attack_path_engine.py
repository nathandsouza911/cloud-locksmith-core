import logging
from collections.abc import Iterable, Mapping

from sqlalchemy import select

from app.db.models.compliance_result import ComplianceResult, ExposureStatus

logger = logging.getLogger(__name__)


ATTACK_PATHS = [
    {
        "id": "ACCOUNT_TAKEOVER",
        "name": "Account Takeover via OAuth Abuse",
        "controls": [
            "IDENTITY_USER_NO_MFA",
            "IDENTITY_USER_CONSENT_POLICY",
        ],
        "severity": "HIGH",
        "description": "Attacker can take over user accounts and grant malicious app access",
    },
    {
        "id": "PRIVILEGE_ESCALATION",
        "name": "Privilege Escalation to Admin",
        "controls": [
            "IDENTITY_USER_NO_MFA",
            "IDENTITY_OVERPRIVILEGED_USER",
        ],
        "severity": "CRITICAL",
        "description": "Compromised account can escalate to admin privileges",
    },
    {
        "id": "EXTERNAL_ACCESS",
        "name": "External Guest Abuse",
        "controls": [
            "IDENTITY_GUEST_INVITES_OPEN",
            "IDENTITY_USER_NO_MFA",
        ],
        "severity": "HIGH",
        "description": "External users can gain access and move laterally",
    },
    {
        "id": "DORMANT_ACCOUNT_TAKEOVER",
        "name": "Dormant Account Exploitation",
        "controls": [
            "IDENTITY_UNUSED_ACCOUNT",
            "IDENTITY_USER_NO_MFA",
        ],
        "severity": "HIGH",
        "description": "Inactive accounts can be hijacked without detection",
    },
]


def summarize_attack_paths(failed_controls: Iterable[str] | None) -> dict:
    normalized_failed_controls = {
        control_id for control_id in (failed_controls or []) if isinstance(control_id, str) and control_id
    }

    logger.debug(
        "attack_path_engine_failed_controls failed_control_count=%s failed_controls=%s",
        len(normalized_failed_controls),
        sorted(normalized_failed_controls),
    )

    paths: list[dict] = []
    affected_controls: set[str] = set()
    critical_controls: set[str] = set()

    for path in ATTACK_PATHS:
        if not isinstance(path, Mapping):
            continue

        controls = path.get("controls")
        if not isinstance(controls, list) or not all(isinstance(control, str) and control for control in controls):
            logger.debug(
                "attack_path_engine_skipped_invalid_definition path_id=%s",
                path.get("id"),
            )
            continue

        if all(control in normalized_failed_controls for control in controls):
            paths.append(
                {
                    "id": path.get("id"),
                    "name": path.get("name"),
                    "severity": path.get("severity"),
                    "description": path.get("description"),
                    "controls_triggered": controls,
                    "status": "ACTIVE",
                }
            )
            affected_controls.update(controls)
            if path.get("severity") == "CRITICAL":
                critical_controls.update(controls)

    logger.debug(
        "attack_path_engine_paths triggered_path_count=%s triggered_paths=%s affected_controls=%s critical_controls=%s",
        len(paths),
        [path["id"] for path in paths],
        sorted(affected_controls),
        sorted(critical_controls),
    )

    return {
        "total_paths": len(paths),
        "critical_paths": sum(1 for path in paths if path.get("severity") == "CRITICAL"),
        "high_paths": sum(1 for path in paths if path.get("severity") == "HIGH"),
        "affected_controls": affected_controls,
        "critical_controls": critical_controls,
        "paths": paths,
    }


async def evaluate_attack_paths(db, tenant_id: str) -> dict:
    result = await db.execute(
        select(ComplianceResult.control_id)
        .where(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.passed.is_(False),
            ComplianceResult.exposure_status == ExposureStatus.ACTIVE.value,
        )
        .distinct()
    )

    summary = summarize_attack_paths(result.scalars().all())
    logger.debug(
        "attack_path_engine_summary tenant_id=%s total_paths=%s",
        tenant_id,
        summary["total_paths"],
    )
    return summary
