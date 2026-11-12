from sqlalchemy.orm import Session

from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.compliance_result import EnforcementMode


def assert_breakglass_present_for_enforcement(
    *,
    db: Session,
    tenant_id: str,
    target_mode: EnforcementMode,
):
    if target_mode != EnforcementMode.ENFORCED:
        return

    count = db.query(BreakGlassAccount).filter(BreakGlassAccount.tenant_id == tenant_id).count()

    if count == 0:
        raise ValueError("Cannot move to ENFORCED mode without at least one break-glass account configured.")
