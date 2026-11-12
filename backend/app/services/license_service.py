from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.db.models.tenant import Tenant
from app.services.graph_client import graph_get


LICENSE_CACHE_TTL = timedelta(minutes=15)
_LICENSE_CACHE: dict[str, tuple[datetime, dict[str, bool]]] = {}
# Controls that require an Entra ID P1/P2 licence to evaluate AND remediate.
# These are the Conditional Access enforcement controls. Per-user MFA detection
# (IDENTITY_*_NO_MFA) reads Graph state and needs no licence — it was previously
# (incorrectly) listed here, which mislabelled those findings in the risk feed.
CONTROL_LICENSE_REQUIREMENTS = {
    "CA_MFA_ALL_USERS": "P1",
    "CA_MFA_ADMINS": "P1",
    "CA_LEGACY_AUTH_BLOCK": "P1",
    "CA_DEVICE_CODE_FLOW_BLOCK": "P1",
    "CA_AUTHENTICATION_TRANSFER_BLOCK": "P1",
    "CA_GUEST_MFA": "P1",
    # Risk-based policies need Entra ID P2 (Identity Protection).
    "CA_HIGH_RISK_SIGN_IN_BLOCK": "P2",
    "CA_RISK_BASED_STEP_UP_MFA": "P2",
}

P1_MARKERS = {
    "AAD_PREMIUM",
    "EMS",
    "ENTERPRISEPREMIUM",
    "SPE_E3",
    "SPB",
}
P2_MARKERS = {
    "AAD_PREMIUM_P2",
    "EMS_PREMIUM",
    "SPE_E5",
}
P1_SERVICE_PLANS = {
    "AAD_PREMIUM",
}
P2_SERVICE_PLANS = {
    "AAD_PREMIUM_P2",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_license_payload(payload: dict | None) -> dict[str, bool]:
    values = payload.get("value", []) if isinstance(payload, dict) else []
    markers = set()
    service_plans = set()

    for sku in values:
        if not isinstance(sku, dict):
            continue
        sku_part_number = sku.get("skuPartNumber")
        if isinstance(sku_part_number, str) and sku_part_number:
            markers.add(sku_part_number.upper())

        for plan in sku.get("servicePlans", []) or []:
            if not isinstance(plan, dict):
                continue
            service_plan_name = plan.get("servicePlanName")
            if isinstance(service_plan_name, str) and service_plan_name:
                service_plans.add(service_plan_name.upper())

    has_p2 = bool(markers & P2_MARKERS or service_plans & P2_SERVICE_PLANS)
    has_p1 = has_p2 or bool(markers & P1_MARKERS or service_plans & P1_SERVICE_PLANS)
    return {
        "has_p1": has_p1,
        "has_p2": has_p2,
    }


async def get_tenant_license(
    *, tenant_id: str, db, tenant: Tenant | None = None, force_refresh: bool = False
) -> dict[str, bool]:
    cached = _LICENSE_CACHE.get(tenant_id)
    if cached and not force_refresh:
        cached_at, cached_value = cached
        if _now() - cached_at < LICENSE_CACHE_TTL:
            return dict(cached_value)

    tenant_record = tenant
    if tenant_record is None:
        tenant_record = db.get(Tenant, tenant_id)
    if tenant_record is None:
        raise ValueError("Tenant not found")

    payload = await graph_get(db, tenant_record, "/subscribedSkus")
    normalized = _normalize_license_payload(payload)
    _LICENSE_CACHE[tenant_id] = (_now(), normalized)
    return dict(normalized)


def control_requires_p1(control_id: str) -> bool:
    """True when the control needs at least an Entra ID P1 licence (P1 or P2)."""
    return CONTROL_LICENSE_REQUIREMENTS.get(control_id) in {"P1", "P2"}


def required_license_tier(control_id: str) -> str | None:
    return CONTROL_LICENSE_REQUIREMENTS.get(control_id)


def control_license_satisfied(control_id: str, tenant_license: dict | None) -> bool:
    """Whether the tenant's licence covers the control (P2 controls need has_p2)."""
    tier = CONTROL_LICENSE_REQUIREMENTS.get(control_id)
    if tier is None:
        return True
    tenant_license = tenant_license or {}
    if tier == "P2":
        return bool(tenant_license.get("has_p2"))
    return bool(tenant_license.get("has_p1"))
