from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.license_optimizer import (
    LicenseFinding,
    LicenseFindingType,
    LicenseSnapshot,
)
from app.db.models.tenant import Tenant
from app.services.graph_client import (
    GraphAPIError,
    graph_get,
    graph_get_all,
)
from app.services.activity.workload_activity_source import (
    build_activity_map as _build_activity_map,
    first_present as _first_present,
    parse_csv_rows as _parse_csv_rows,
    parse_datetime as _parse_datetime,
    fetch_report_csv,
)

logger = logging.getLogger(__name__)

INACTIVE_DAYS = 30
LICENSE_PRICING = {
    "BUSINESS_BASIC": 7,
    "BUSINESS_STANDARD": 14,
    "BUSINESS_PREMIUM": 22,
    "OFFICE_365_E1": 10,
    "OFFICE_365_E3": 26,
    "M365_E3": 39,
    "M365_E5": 60,
    "M365_F1": 3,
    "M365_F3": 10,
}
# Microsoft 365 commercial SKU GUIDs — sourced from Microsoft's published product GUID reference.
# Used as the primary resolution path; skuPartNumber is the fallback.
SKU_ID_TO_PRICING_KEY: dict[str, str] = {
    # Microsoft 365 E-series
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06": "M365_E5",  # SPE_E5
    "05e9a617-0261-4cee-bb44-138d3ef5d965": "M365_E3",  # SPE_E3
    # Office 365 E-series
    "6fd2c87f-b296-42f0-b197-1e91e994b900": "OFFICE_365_E3",  # ENTERPRISEPACK
    "18181a46-0d4e-45cd-891e-60aabd171b4e": "OFFICE_365_E1",  # STANDARDPACK
    # Microsoft 365 Business
    "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46": "BUSINESS_PREMIUM",  # M365_BUSINESS_PREMIUM / SPB
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3": "BUSINESS_STANDARD",  # O365_BUSINESS_PREMIUM
    "3b555118-da6a-4418-894f-7df1e2096870": "BUSINESS_BASIC",  # O365_BUSINESS_ESSENTIALS
    # Microsoft 365 Frontline
    "50f60901-3181-4b75-8a2c-4c8e4c1d5a72": "M365_F1",  # SPE_F1
    "66b55226-6b4f-492c-910c-a3b7a3c9d993": "M365_F3",  # SPE_F3
    "4b9405b0-7788-4568-add1-99614e613b69": "M365_F1",  # DESKLESSPACK
}
SKU_PART_NUMBER_TO_PRICING_KEY = {
    "O365_BUSINESS_ESSENTIALS": "BUSINESS_BASIC",
    "SMB_BUSINESS_ESSENTIALS": "BUSINESS_BASIC",
    "O365_BUSINESS_PREMIUM": "BUSINESS_STANDARD",
    "SMB_BUSINESS": "BUSINESS_STANDARD",
    "SPB": "BUSINESS_PREMIUM",
    "M365_BUSINESS_PREMIUM": "BUSINESS_PREMIUM",
    "STANDARDPACK": "OFFICE_365_E1",
    "STANDARDWOFFPACK": "OFFICE_365_E1",
    "ENTERPRISEPACK": "OFFICE_365_E3",
    "SPE_E3": "M365_E3",
    "SPE_E5": "M365_E5",
    "DESKLESSPACK": "M365_F1",
    "SPE_F1": "M365_F1",
    "SPE_F3": "M365_F3",
}
OVERLICENSED_PRICING_KEYS = {"OFFICE_365_E3", "M365_E3", "M365_E5"}


@dataclass
class LicenseScanResult:
    summary: dict[str, int]
    findings: list[dict[str, Any]]
    snapshot_id: str
    scanned_at: str


def _utcnow() -> datetime:
    return datetime.utcnow()


def _coerce_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _resolve_license_type_from_sku_part_number(sku_part_number: str | None) -> str | None:
    if not sku_part_number:
        return None
    return SKU_PART_NUMBER_TO_PRICING_KEY.get(str(sku_part_number).strip().upper())


def _resolve_pricing_key(sku: dict[str, Any]) -> str | None:
    sku_id = str(sku.get("skuId") or "").strip()
    if sku_id and sku_id in SKU_ID_TO_PRICING_KEY:
        return SKU_ID_TO_PRICING_KEY[sku_id]
    return _resolve_license_type_from_sku_part_number(sku.get("skuPartNumber"))


def _build_sku_catalog(
    subscribed_skus: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_part_number: dict[str, dict[str, Any]] = {}
    for sku in subscribed_skus:
        sku_id = str(sku.get("skuId") or "").strip()
        sku_part_number = str(sku.get("skuPartNumber") or "").strip()
        pricing_key = _resolve_pricing_key(sku)
        if pricing_key is None:
            logger.warning(
                "[LicenseOptimizer] Unresolved SKU — skuId=%r skuPartNumber=%r: "
                "no pricing key found; this SKU will be excluded from waste analysis",
                sku_id,
                sku_part_number,
            )
        else:
            logger.debug(
                "[LicenseOptimizer] SKU resolved — skuId=%r skuPartNumber=%r pricing_key=%r",
                sku_id,
                sku_part_number,
                pricing_key,
            )
        normalized = {
            "sku_id": sku_id,
            "sku_part_number": sku_part_number,
            "pricing_key": pricing_key,
            "license_type": pricing_key,
            "enabled": _coerce_int((sku.get("prepaidUnits") or {}).get("enabled")),
            "assigned": _coerce_int(sku.get("consumedUnits")),
        }
        if sku_id:
            by_id[sku_id] = normalized
        if sku_part_number:
            by_part_number[sku_part_number.upper()] = normalized
    return by_id, by_part_number


def _serialize_finding(finding: LicenseFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "type": finding.finding_type,
        "tenant_id": finding.tenant_id,
        "user_id": finding.user_id,
        "license_type": finding.license_type,
        "currency": "USD",
        "estimated_monthly_cost": finding.estimated_monthly_cost,
        "metadata": finding.finding_metadata or {},
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }


async def fetch_license_optimizer_inputs(db: Session, tenant: Tenant) -> dict[str, Any]:
    users = await graph_get_all(
        db,
        tenant,
        "/users?$select=id,displayName,mail,userPrincipalName,accountEnabled,createdDateTime,assignedLicenses",
    )
    subscribed_skus_payload = await graph_get(db, tenant, "/subscribedSkus")
    try:
        office_activity_rows = _parse_csv_rows(
            await fetch_report_csv(
                db,
                tenant,
                "/reports/getOffice365ActiveUserDetail(period='D180')",
            )
        )
        office365_active_user_detail_available = True
    except GraphAPIError as e:
        logger.warning(
            "[LicenseOptimizer] Reports API failed for tenant %s: %s",
            tenant.id,
            str(e),
        )
        office_activity_rows = []
        office365_active_user_detail_available = False

    try:
        app_user_count_rows = _parse_csv_rows(
            await fetch_report_csv(
                db,
                tenant,
                "/reports/getM365AppUserCounts(period='D180')",
            )
        )
        m365_app_user_counts_available = True
    except GraphAPIError as e:
        logger.warning(
            "[LicenseOptimizer] Reports API failed for tenant %s: %s",
            tenant.id,
            str(e),
        )
        app_user_count_rows = []
        m365_app_user_counts_available = False

    return {
        "users": users,
        "subscribed_skus": list((subscribed_skus_payload or {}).get("value", [])),
        "office365_active_user_detail": office_activity_rows,
        "office365_active_user_detail_available": office365_active_user_detail_available,
        "m365_app_user_counts": app_user_count_rows,
        "m365_app_user_counts_available": m365_app_user_counts_available,
    }


def analyze_license_data(
    *, tenant_id: str, raw_data: dict[str, Any], now: datetime | None = None
) -> list[dict[str, Any]]:
    now = now or _utcnow()
    users = list(raw_data.get("users") or [])
    subscribed_skus = list(raw_data.get("subscribed_skus") or [])
    activity_rows = list(raw_data.get("office365_active_user_detail") or [])
    activity_available = bool(raw_data.get("office365_active_user_detail_available", True))

    if not activity_available:
        logger.warning(
            "[LicenseOptimizer] Activity reports unavailable for tenant %s — "
            "OVERLICENSED_USER detection is disabled; INACTIVE_USER detection "
            "falls back to account creation date only",
            tenant_id,
        )

    activity_map = _build_activity_map(activity_rows)
    sku_catalog_by_id, _sku_catalog_by_part_number = _build_sku_catalog(subscribed_skus)

    logger.info(
        "[LicenseOptimizer] Scan inputs — tenant=%s users=%d subscribed_skus=%d "
        "activity_rows=%d activity_available=%s",
        tenant_id,
        len(users),
        len(subscribed_skus),
        len(activity_rows),
        activity_available,
    )

    findings: list[dict[str, Any]] = []
    inactive_user_ids: set[str] = set()
    inactivity_cutoff = now - timedelta(days=INACTIVE_DAYS)

    for user in users:
        assigned_licenses = list(user.get("assignedLicenses") or [])
        if not assigned_licenses:
            continue

        user_id = str(user.get("id") or "").strip() or None
        principal_name = _first_present(user, "userPrincipalName", "mail")
        activity = activity_map.get((principal_name or "").lower(), {})

        licensed_skus = [sku_catalog_by_id.get(str(item.get("skuId") or "").strip()) for item in assigned_licenses]
        licensed_skus = [item for item in licensed_skus if item]
        priced_skus = [item for item in licensed_skus if item.get("pricing_key") in LICENSE_PRICING]
        if not priced_skus:
            continue
        primary_priced = max(priced_skus, key=lambda item: LICENSE_PRICING.get(item["pricing_key"], 0))
        premium_skus = [item for item in priced_skus if item.get("pricing_key") in OVERLICENSED_PRICING_KEYS]
        primary_premium = max(
            premium_skus,
            key=lambda item: LICENSE_PRICING.get(item["pricing_key"], 0),
            default=None,
        )

        last_activity = activity.get("last_activity")
        created_at = _parse_datetime(_first_present(user, "createdDateTime"))
        is_inactive = bool(
            (last_activity is not None and last_activity <= inactivity_cutoff)
            or (last_activity is None and created_at is not None and created_at <= inactivity_cutoff)
        )

        base_metadata = {
            "display_name": user.get("displayName"),
            "email": user.get("mail") or user.get("userPrincipalName"),
            "user_principal_name": user.get("userPrincipalName"),
            "last_activity_at": last_activity.isoformat() if last_activity else None,
            "created_at": created_at.isoformat() if created_at else None,
            "recommended_action": "Downgrade or remove the assigned license",
            "assigned_license_types": sorted(
                {item.get("pricing_key") for item in priced_skus if item.get("pricing_key")}
            ),
            "activity_data_available": activity_available,
        }

        if is_inactive:
            inactive_user_ids.add(user_id or "")
            findings.append(
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "type": LicenseFindingType.INACTIVE_USER,
                    "user_id": user_id,
                    "license_type": primary_priced["pricing_key"],
                    "estimated_monthly_cost": LICENSE_PRICING[primary_priced["pricing_key"]],
                    "metadata": {
                        **base_metadata,
                        "reason": "Licensed user has been inactive for more than 30 days",
                        "recommended_action": "Remove or reassign this license from the inactive user",
                    },
                }
            )

        if (
            user_id
            and user_id not in inactive_user_ids
            and primary_premium is not None
            and activity.get("exchange_activity")
            and not activity.get("non_email_activity")
        ):
            findings.append(
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "type": LicenseFindingType.OVERLICENSED_USER,
                    "user_id": user_id,
                    "license_type": primary_premium["pricing_key"],
                    "estimated_monthly_cost": LICENSE_PRICING[primary_premium["pricing_key"]],
                    "metadata": {
                        **base_metadata,
                        "reason": "Premium user shows email-only usage with no other Microsoft 365 workload activity",
                        "recommended_action": "Downgrade this user to a lower-cost license tier",
                    },
                }
            )

    for sku in subscribed_skus:
        sku_part_number = str(sku.get("skuPartNumber") or "").strip()
        pricing_key = _resolve_pricing_key(sku)
        if pricing_key not in LICENSE_PRICING:
            continue

        enabled = _coerce_int((sku.get("prepaidUnits") or {}).get("enabled"))
        assigned = _coerce_int(sku.get("consumedUnits"))
        unused_count = max(enabled - assigned, 0)
        if unused_count <= 0:
            continue

        findings.append(
            {
                "id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "type": LicenseFindingType.UNUSED_LICENSE,
                "user_id": None,
                "license_type": pricing_key,
                "estimated_monthly_cost": unused_count * LICENSE_PRICING[pricing_key],
                "metadata": {
                    "sku_part_number": sku_part_number,
                    "enabled": enabled,
                    "assigned": assigned,
                    "unused_count": unused_count,
                    "reason": "Purchased licenses exceed assigned licenses",
                    "recommended_action": "Reduce purchased seats or reassign the unused licenses",
                },
            }
        )

    logger.info(
        "[LicenseOptimizer] Analysis complete — tenant=%s findings=%d " "(inactive=%d overlicensed=%d unused=%d)",
        tenant_id,
        len(findings),
        sum(1 for f in findings if f["type"] == LicenseFindingType.INACTIVE_USER),
        sum(1 for f in findings if f["type"] == LicenseFindingType.OVERLICENSED_USER),
        sum(1 for f in findings if f["type"] == LicenseFindingType.UNUSED_LICENSE),
    )
    return findings


def _replace_license_findings(db: Session, tenant_id: str, findings: list[dict[str, Any]]) -> list[LicenseFinding]:
    db.query(LicenseFinding).filter(LicenseFinding.tenant_id == tenant_id).delete(synchronize_session=False)
    db.flush()

    stored_findings: list[LicenseFinding] = []
    for item in findings:
        finding = LicenseFinding(
            id=item["id"],
            tenant_id=tenant_id,
            finding_type=item["type"],
            user_id=item.get("user_id"),
            license_type=item["license_type"],
            estimated_monthly_cost=_coerce_int(item.get("estimated_monthly_cost")),
            finding_metadata=item.get("metadata") or {},
        )
        db.add(finding)
        stored_findings.append(finding)

    db.flush()
    return stored_findings


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    inactive_cost = sum(
        item["estimated_monthly_cost"] for item in findings if item["type"] == LicenseFindingType.INACTIVE_USER
    )
    overlicensed_cost = sum(
        item["estimated_monthly_cost"] for item in findings if item["type"] == LicenseFindingType.OVERLICENSED_USER
    )
    unused_license_cost = sum(
        item["estimated_monthly_cost"] for item in findings if item["type"] == LicenseFindingType.UNUSED_LICENSE
    )
    return {
        "currency": "USD",
        "total_waste": inactive_cost + overlicensed_cost + unused_license_cost,
        "inactive_users_cost": inactive_cost,
        "overlicensed_cost": overlicensed_cost,
        "unused_license_cost": unused_license_cost,
    }


async def run_license_scan(*, db: Session, tenant: Tenant) -> LicenseScanResult:
    raw_data = await fetch_license_optimizer_inputs(db, tenant)
    findings = analyze_license_data(tenant_id=tenant.id, raw_data=raw_data)
    snapshot = LicenseSnapshot(
        id=str(uuid.uuid4()),
        tenant_id=tenant.id,
        raw_data=raw_data,
    )
    db.add(snapshot)
    db.flush()

    stored_findings = _replace_license_findings(db, tenant.id, findings)
    db.commit()

    return LicenseScanResult(
        summary=_build_summary(findings),
        findings=[_serialize_finding(item) for item in stored_findings],
        snapshot_id=snapshot.id,
        scanned_at=snapshot.captured_at.isoformat() if snapshot.captured_at else _utcnow().isoformat(),
    )


def get_license_summary(db: Session, tenant_id: str) -> dict[str, int]:
    rows = (
        db.query(
            LicenseFinding.finding_type,
            func.coalesce(func.sum(LicenseFinding.estimated_monthly_cost), 0),
        )
        .filter(LicenseFinding.tenant_id == tenant_id)
        .group_by(LicenseFinding.finding_type)
        .all()
    )
    costs = {finding_type: int(total_cost or 0) for finding_type, total_cost in rows}
    return {
        "currency": "USD",
        "total_waste": sum(costs.values()),
        "inactive_users_cost": costs.get(LicenseFindingType.INACTIVE_USER, 0),
        "overlicensed_cost": costs.get(LicenseFindingType.OVERLICENSED_USER, 0),
        "unused_license_cost": costs.get(LicenseFindingType.UNUSED_LICENSE, 0),
    }


def list_license_findings(db: Session, tenant_id: str) -> list[dict[str, Any]]:
    findings = (
        db.query(LicenseFinding)
        .filter(LicenseFinding.tenant_id == tenant_id)
        .order_by(LicenseFinding.created_at.desc(), LicenseFinding.estimated_monthly_cost.desc())
        .all()
    )
    return [_serialize_finding(item) for item in findings]


def build_license_report(db: Session, tenant: Tenant) -> dict[str, Any]:
    findings = list_license_findings(db, tenant.id)
    summary = get_license_summary(db, tenant.id)
    return {
        "tenant_id": tenant.id,
        "tenant_name": tenant.tenant_name,
        "generated_at": _utcnow().isoformat(),
        "currency": "USD",
        "pricing_reference": "Microsoft 365 pricing baseline configured for July 2026",
        "summary": summary,
        "findings": findings,
    }


def export_license_report_json(db: Session, tenant: Tenant) -> bytes:
    report = build_license_report(db, tenant)
    return json.dumps(report, indent=2).encode("utf-8")
