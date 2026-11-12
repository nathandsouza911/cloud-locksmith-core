import uuid

from app.db.models.tenant import Tenant
from app.services.posture_snapshot_service import create_posture_snapshot
from app.services.baseline_service import (
    normalize_organization_id,
    save_baseline_config_sync,
)


def apply_baseline_configuration(
    db,
    *,
    organization_id: str,
    baseline_name: str,
    controls: list[str],
):
    organization_key = normalize_organization_id(organization_id)
    baseline = save_baseline_config_sync(
        db,
        organization_id=organization_key,
        baseline_name=baseline_name,
        controls=controls,
    )
    tenant_organization_id = organization_id
    try:
        tenant_organization_id = uuid.UUID(str(organization_id))
    except (TypeError, ValueError, AttributeError):
        tenant_organization_id = organization_id

    tenants = db.query(Tenant).filter(Tenant.organization_id == tenant_organization_id).all()

    tenant_ids = [tenant.id for tenant in tenants]
    for tenant_id in tenant_ids:
        create_posture_snapshot(
            db,
            tenant_id=tenant_id,
            reason="baseline_updated",
        )

    return {
        "status": "baseline_applied",
        "organization_id": organization_key,
        "baseline_name": baseline.baseline_name,
        "controls": baseline.controls or [],
        "tenant_count": len(tenant_ids),
        "tenant_ids": tenant_ids,
        "message": (f"Baseline saved for {len(tenant_ids)} tenant(s). " "Findings will update on the next scan."),
    }
