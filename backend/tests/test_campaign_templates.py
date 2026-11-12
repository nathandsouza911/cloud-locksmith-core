"""Phase 3 TDD — Campaign Templates.

Tests: TM-C1 (create), TM-L1 (list), TM-U1 (update), TM-D1 (delete),
TM-X1 (execute → AWAITING_APPROVAL), TM-I1 (cross-org isolation),
TM-S1 (execute never bypasses approval).

IMPORTANT: model import at module level so Base.metadata sees the table.
"""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.db.models.campaign_template import CampaignTemplate  # noqa: F401 — registers table
from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.api.v1.fleet_campaigns import (
    create_template_endpoint,
    list_templates_endpoint,
    get_template_endpoint,
    update_template_endpoint,
    delete_template_endpoint,
    execute_template_endpoint,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _user(org_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=org_id or uuid.uuid4(),
    )


def _seed(db, user, tenant_ids=("t1",)):
    for t in tenant_ids:
        db.add(UserTenantAccess(user_id=user.id, tenant_id=t, role="ADMIN"))
        db.add(
            ComplianceResult(
                tenant_id=t,
                control_id=SAFE_CONTROL,
                resource_id="user-1",
                resource_type="USER",
                passed=False,
                exposure_status=ExposureStatus.ACTIVE,
            )
        )
    db.commit()


# ---------------------------------------------------------------------------
# TM-C1 — Create template
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_template_returns_template(db_session):
    """TM-C1: Creating a template returns the template dict with expected fields."""
    user = _user()
    result = await create_template_endpoint(
        body={
            "name": "Guest Control Bundle",
            "control_ids": [SAFE_CONTROL],
            "target_tenant_ids": ["t1"],
            "dry_run": False,
        },
        db=db_session,
        current_user=user,
    )
    assert result["name"] == "Guest Control Bundle"
    assert result["control_ids"] == [SAFE_CONTROL]
    assert result["target_tenant_ids"] == ["t1"]
    assert result["dry_run"] is False
    assert "id" in result


# ---------------------------------------------------------------------------
# TM-L1 — List templates (org-scoped)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_templates_returns_org_scoped(db_session):
    """TM-L1: List templates returns only templates belonging to the operator's org."""
    user_a = _user()
    user_b = _user()

    await create_template_endpoint(
        body={"name": "A-template", "control_ids": [SAFE_CONTROL], "target_tenant_ids": [], "dry_run": False},
        db=db_session,
        current_user=user_a,
    )
    await create_template_endpoint(
        body={"name": "B-template", "control_ids": [SAFE_CONTROL], "target_tenant_ids": [], "dry_run": False},
        db=db_session,
        current_user=user_b,
    )

    result_a = await list_templates_endpoint(db=db_session, current_user=user_a)
    result_b = await list_templates_endpoint(db=db_session, current_user=user_b)

    assert len(result_a) == 1
    assert result_a[0]["name"] == "A-template"
    assert len(result_b) == 1
    assert result_b[0]["name"] == "B-template"


# ---------------------------------------------------------------------------
# TM-U1 — Update template
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_template_changes_fields(db_session):
    """TM-U1: Updating a template changes the specified fields."""
    user = _user()
    created = await create_template_endpoint(
        body={"name": "Old Name", "control_ids": [SAFE_CONTROL], "target_tenant_ids": [], "dry_run": False},
        db=db_session,
        current_user=user,
    )
    template_id = created["id"]

    updated = await update_template_endpoint(
        template_id=template_id,
        body={"name": "New Name", "dry_run": True},
        db=db_session,
        current_user=user,
    )
    assert updated["name"] == "New Name"
    assert updated["dry_run"] is True
    assert updated["control_ids"] == [SAFE_CONTROL]  # unchanged


# ---------------------------------------------------------------------------
# TM-D1 — Delete template
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_template_removes_it(db_session):
    """TM-D1: Deleting a template removes it from the list."""
    user = _user()
    created = await create_template_endpoint(
        body={"name": "To Delete", "control_ids": [SAFE_CONTROL], "target_tenant_ids": [], "dry_run": False},
        db=db_session,
        current_user=user,
    )
    template_id = created["id"]

    await delete_template_endpoint(template_id=template_id, db=db_session, current_user=user)

    templates = await list_templates_endpoint(db=db_session, current_user=user)
    assert all(t["id"] != template_id for t in templates)


# ---------------------------------------------------------------------------
# TM-X1 — Execute template creates AWAITING_APPROVAL campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_template_creates_awaiting_approval_campaign(db_session):
    """TM-X1: Executing a template creates a new AWAITING_APPROVAL campaign."""
    user = _user()
    _seed(db_session, user)

    created = await create_template_endpoint(
        body={"name": "Fleet Cleanup", "control_ids": [SAFE_CONTROL], "target_tenant_ids": ["t1"], "dry_run": False},
        db=db_session,
        current_user=user,
    )
    template_id = created["id"]

    campaign = await execute_template_endpoint(template_id=template_id, db=db_session, current_user=user)
    assert campaign["status"] == "AWAITING_APPROVAL"
    assert campaign["control_ids"] == [SAFE_CONTROL]


# ---------------------------------------------------------------------------
# TM-I1 — Cross-org user cannot access another org's template
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_template_cross_org_returns_404(db_session):
    """TM-I1: Cross-org user cannot read or execute another org's template."""
    owner = _user()
    created = await create_template_endpoint(
        body={"name": "Owner Template", "control_ids": [SAFE_CONTROL], "target_tenant_ids": [], "dry_run": False},
        db=db_session,
        current_user=owner,
    )
    template_id = created["id"]

    attacker = _user()
    with pytest.raises(HTTPException) as exc:
        await get_template_endpoint(template_id=template_id, db=db_session, current_user=attacker)
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# TM-S1 — Execute template never bypasses approval (approval NOT set)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_template_never_sets_approved_hash(db_session):
    """TM-S1: Campaign created from template has no approved_plan_hash (unapproved)."""
    user = _user()
    _seed(db_session, user)

    created = await create_template_endpoint(
        body={"name": "Fleet Cleanup", "control_ids": [SAFE_CONTROL], "target_tenant_ids": ["t1"], "dry_run": False},
        db=db_session,
        current_user=user,
    )
    campaign = await execute_template_endpoint(template_id=created["id"], db=db_session, current_user=user)
    assert campaign["approved_plan_hash"] is None
    assert campaign["approved_by"] is None
