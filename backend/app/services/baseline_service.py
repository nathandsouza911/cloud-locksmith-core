from app.utils.datetime import to_naive_utc, utc_now

from sqlalchemy import select, update

from app.db.models.msp_security_baseline import BaselineConfig
from app.services.baseline.baseline_definition import (
    ALWAYS_MONITORED_CONTROLS,
    CUSTOMER_SELECTABLE_CONTROLS,
    LICENSE_GATED_CA_CONTROLS,
    MSP_SECURITY_BASELINE,
    SECURITY_DEFAULTS_COVERED_CONTROLS,
)

DEFAULT_BASELINE_TEMPLATE_NAME = "Default Secure Baseline"


def resolve_effective_scan_controls(
    baseline_controls,
    *,
    ca_licensed: bool,
    security_defaults_enabled: bool | None = None,
) -> set[str]:
    """Resolve the set of controls the scanner should actually evaluate.

    Combines the customer-selected baseline with always-monitored controls
    (which are enforced unconditionally), then removes licence-gated CA
    controls when the tenant lacks an Entra P1/P2 licence so they are never
    evaluated, scored, or surfaced as FAIL findings.

    Exception: when Entra Security Defaults is enabled, CA_MFA_ALL_USERS and
    CA_MFA_ADMINS stay in the effective set even without a P1/P2 licence —
    Security Defaults is a free, tenant-wide MFA toggle this scanner already
    treats as equivalent to CA-enforced MFA (see SECURITY_DEFAULTS_COVERED_CONTROLS).
    Without this, the smallest, unlicensed tenants — the ones most likely to be
    relying on Security Defaults instead of paid Conditional Access — would have
    these controls go permanently dark as NOT_EVALUATED despite being protected.
    """
    effective = set(baseline_controls) | set(ALWAYS_MONITORED_CONTROLS)
    if not ca_licensed:
        gated = set(LICENSE_GATED_CA_CONTROLS)
        if security_defaults_enabled is True:
            gated -= SECURITY_DEFAULTS_COVERED_CONTROLS
        effective -= gated
    return effective


def resolve_scoring_controls(baseline_controls) -> list[str]:
    """Controls included in the posture score: customer baseline plus
    always-monitored controls, in canonical order with no duplicates.

    Licence-gated CA controls that were not evaluated have no result rows and
    are excluded from the score by the three-way NOT_EVALUATED rule, so no
    licence lookup is needed here.
    """
    wanted = set(baseline_controls) | set(ALWAYS_MONITORED_CONTROLS)
    return [control_id for control_id in MSP_SECURITY_BASELINE if control_id in wanted]


def normalize_baseline_controls(controls: list[str] | None) -> list[str]:
    # Customer baselines may only contain customer-selectable controls. Unknown
    # control ids and always-monitored controls (which are enforced regardless
    # of baseline) are stripped so the stored baseline stays consistent with the
    # selectable set shown in the UI.
    allowed_controls = set(MSP_SECURITY_BASELINE) - set(ALWAYS_MONITORED_CONTROLS)
    normalized: list[str] = []
    for control_id in controls or []:
        if control_id not in allowed_controls:
            continue
        if control_id in normalized:
            continue
        normalized.append(control_id)
    return normalized


def normalize_organization_id(organization_id) -> str | None:
    if organization_id is None:
        return None
    return str(organization_id)


def resolve_baseline_controls(controls: list[str] | None) -> list[str]:
    normalized = normalize_baseline_controls(controls)
    if normalized:
        return normalized
    return list(CUSTOMER_SELECTABLE_CONTROLS)


async def list_baseline_templates(db, organization_id):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        return []

    result = await db.execute(
        select(BaselineConfig)
        .where(BaselineConfig.organization_id == organization_key)
        .order_by(BaselineConfig.is_active.desc(), BaselineConfig.created_at.desc())
    )
    return list(result.scalars().all())


def list_baseline_templates_sync(db, organization_id):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        return []

    return (
        db.query(BaselineConfig)
        .filter(BaselineConfig.organization_id == organization_key)
        .order_by(BaselineConfig.is_active.desc(), BaselineConfig.created_at.desc())
        .all()
    )


async def get_baseline_config(db, organization_id):
    templates = await list_baseline_templates(db, organization_id)
    return templates[0] if templates else None


def get_baseline_config_sync(db, organization_id):
    templates = list_baseline_templates_sync(db, organization_id)
    return templates[0] if templates else None


async def get_active_baseline_template(db, organization_id):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        return None

    result = await db.execute(
        select(BaselineConfig)
        .where(
            BaselineConfig.organization_id == organization_key,
            BaselineConfig.is_active.is_(True),
        )
        .order_by(BaselineConfig.created_at.desc())
    )
    return result.scalars().first()


def get_active_baseline_template_sync(db, organization_id):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        return None

    return (
        db.query(BaselineConfig)
        .filter(
            BaselineConfig.organization_id == organization_key,
            BaselineConfig.is_active.is_(True),
        )
        .order_by(BaselineConfig.created_at.desc())
        .first()
    )


async def ensure_default_baseline_template(db, organization_id):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        return None

    existing_templates = await list_baseline_templates(db, organization_key)
    if existing_templates:
        return existing_templates[0]

    return await save_baseline_template(
        db,
        organization_id=organization_key,
        baseline_name=DEFAULT_BASELINE_TEMPLATE_NAME,
        controls=list(CUSTOMER_SELECTABLE_CONTROLS),
        activate=True,
    )


def ensure_default_baseline_template_sync(db, organization_id):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        return None

    existing_templates = list_baseline_templates_sync(db, organization_key)
    if existing_templates:
        return existing_templates[0]

    return save_baseline_template_sync(
        db,
        organization_id=organization_key,
        baseline_name=DEFAULT_BASELINE_TEMPLATE_NAME,
        controls=list(CUSTOMER_SELECTABLE_CONTROLS),
        activate=True,
    )


async def save_baseline_template(
    db,
    *,
    organization_id,
    baseline_name: str,
    controls: list[str] | None,
    activate: bool = False,
):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        raise ValueError("Organization context is unavailable")

    normalized_name = (baseline_name or "").strip() or DEFAULT_BASELINE_TEMPLATE_NAME
    result = await db.execute(
        select(BaselineConfig).where(
            BaselineConfig.organization_id == organization_key,
            BaselineConfig.baseline_name == normalized_name,
        )
    )
    baseline = result.scalars().first()
    if baseline is None:
        baseline = BaselineConfig(
            organization_id=organization_key,
            baseline_name=normalized_name,
        )
        db.add(baseline)

    if activate:
        await db.execute(
            update(BaselineConfig).where(BaselineConfig.organization_id == organization_key).values(is_active=False)
        )

    baseline.baseline_name = normalized_name
    baseline.controls = resolve_baseline_controls(controls)
    baseline.is_active = activate or baseline.is_active
    if activate or baseline.created_at is None:
        baseline.created_at = to_naive_utc(utc_now())
    await db.commit()
    await db.refresh(baseline)
    return baseline


def save_baseline_template_sync(
    db,
    *,
    organization_id,
    baseline_name: str,
    controls: list[str] | None,
    activate: bool = False,
):
    organization_key = normalize_organization_id(organization_id)
    if not organization_key:
        raise ValueError("Organization context is unavailable")

    normalized_name = (baseline_name or "").strip() or DEFAULT_BASELINE_TEMPLATE_NAME
    baseline = (
        db.query(BaselineConfig)
        .filter(
            BaselineConfig.organization_id == organization_key,
            BaselineConfig.baseline_name == normalized_name,
        )
        .first()
    )
    if baseline is None:
        baseline = BaselineConfig(
            organization_id=organization_key,
            baseline_name=normalized_name,
        )
        db.add(baseline)

    if activate:
        (
            db.query(BaselineConfig)
            .filter(BaselineConfig.organization_id == organization_key)
            .update({"is_active": False})
        )

    baseline.baseline_name = normalized_name
    baseline.controls = resolve_baseline_controls(controls)
    baseline.is_active = activate or baseline.is_active
    if activate or baseline.created_at is None:
        baseline.created_at = to_naive_utc(utc_now())
    db.commit()
    db.refresh(baseline)
    return baseline


async def save_baseline_config(
    db,
    *,
    organization_id,
    baseline_name: str,
    controls: list[str] | None,
):
    return await save_baseline_template(
        db,
        organization_id=organization_id,
        baseline_name=baseline_name,
        controls=controls,
        activate=True,
    )


def save_baseline_config_sync(
    db,
    *,
    organization_id,
    baseline_name: str,
    controls: list[str] | None,
):
    return save_baseline_template_sync(
        db,
        organization_id=organization_id,
        baseline_name=baseline_name,
        controls=controls,
        activate=True,
    )


async def get_msp_baseline(db, organization_id):
    baseline = await get_active_baseline_template(db, organization_id)
    if not baseline:
        baseline = await ensure_default_baseline_template(db, organization_id)
    if not baseline:
        return list(CUSTOMER_SELECTABLE_CONTROLS)
    return resolve_baseline_controls(baseline.controls)


def get_msp_baseline_sync(db, organization_id):
    baseline = get_active_baseline_template_sync(db, organization_id)
    if not baseline:
        baseline = ensure_default_baseline_template_sync(db, organization_id)
    if not baseline:
        return list(CUSTOMER_SELECTABLE_CONTROLS)
    return resolve_baseline_controls(baseline.controls)
