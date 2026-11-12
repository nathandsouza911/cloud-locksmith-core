import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.db.base import Base
from app.services.offboarding.offboarding_rollback import rollback_offboarding
from app.services import offboarding_service


@pytest.fixture(autouse=True)
def _offline_graph_reads(monkeypatch):
    """Offboarding now reads the user's directory roles from Graph before acting.

    Default to "no admin roles, account enabled"; tests that need roles patch
    fetch_user_memberof_directory_roles themselves (a later setattr wins).
    """

    async def no_roles(*args, **kwargs):
        return []

    async def enabled_user_snapshot(db, tenant, user_id):
        return {"roles": [], "account_enabled": True}

    monkeypatch.setattr(offboarding_service, "fetch_user_memberof_directory_roles", no_roles)
    monkeypatch.setattr(offboarding_service, "snapshot_user_state", enabled_user_snapshot)

    async def no_context_log(**kwargs):
        return None

    # Reads the user's roles from Graph purely for the audit log line.
    monkeypatch.setattr(offboarding_service, "_log_offboarding_step_context", no_context_log)


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def seed_tenant(db: Session) -> Tenant:
    tenant = Tenant(id="tenant-123", tenant_name="Test Tenant")
    db.add(tenant)
    db.commit()
    return tenant


def seed_compliance(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    resource_id: str,
    evidence: dict | None = None,
    decision_status: str | None = "PENDING",
    resource_type: str = "USER",
) -> ComplianceResult:
    compliance = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type=resource_type,
        resource_id=resource_id,
        severity="HIGH",
        passed=False,
        evidence=evidence or {},
        decision_status=decision_status,
    )
    db.add(compliance)
    db.commit()
    db.refresh(compliance)
    return compliance


def seed_user(
    db: Session,
    *,
    tenant_id: str,
    external_id: str,
    email: str,
    is_admin: bool = False,
) -> User:
    user = User(
        tenant_id=tenant_id,
        external_id=external_id,
        email=email,
        display_name=email,
        is_admin=is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_create_session_success(db_session):
    tenant = seed_tenant(db_session)
    seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_OVERPRIVILEGED_USER",
        resource_id="user-1",
        evidence={"current_roles": [{"id": "role-1", "displayName": "Global Administrator"}]},
    )
    seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_ADMIN_NO_MFA",
        resource_id="user-1",
    )

    session = offboarding_service.create_session(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_ADMIN_OVERPRIVILEGED",
        resource_id="user-1",
    )

    assert session["status"] == "PENDING"
    assert len(session["steps"]) == 3
    assert session["steps"][0]["type"] == "manual"
    assert session["steps"][1]["type"] == "automated"
    assert session["steps"][2]["type"] == "automated"


def test_execute_steps_updates_state(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    compliance = seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-2",
        evidence={"user_id": "user-2"},
    )
    session = offboarding_service.create_session(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-2",
    )

    calls: list[tuple[int, dict]] = []

    async def fake_execute_approved_remediation(
        *, db, compliance_result_id, tenant, tenant_id, execution_payload=None, **_kwargs
    ):
        calls.append((compliance_result_id, execution_payload or {}))
        return {"status": "EXECUTED"}

    monkeypatch.setattr(
        offboarding_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    first_step = session["steps"][0]["id"]
    second_step = session["steps"][1]["id"]

    in_progress = asyncio.run(offboarding_service.execute_step(db_session, tenant, session["session_id"], first_step))
    assert in_progress["status"] == "IN_PROGRESS"
    assert in_progress["steps"][0]["status"] == "completed"

    completed = asyncio.run(offboarding_service.execute_step(db_session, tenant, session["session_id"], second_step))
    assert calls == [(compliance.id, {})]
    assert completed["steps"][1]["status"] == "completed"


def test_complete_flow_sets_completed_status(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-3",
        evidence={"user_id": "user-3"},
    )
    session = offboarding_service.create_session(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-3",
    )

    async def fake_execute_approved_remediation(
        *, db, compliance_result_id, tenant, tenant_id, execution_payload=None, **_kwargs
    ):
        return {"status": "EXECUTED"}

    monkeypatch.setattr(
        offboarding_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    for step in session["steps"]:
        session = asyncio.run(offboarding_service.execute_step(db_session, tenant, session["session_id"], step["id"]))

    assert session["status"] == "COMPLETED"
    assert all(step["status"] == "completed" for step in session["steps"])


def test_failed_automated_step_returns_retryable_error(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-4",
        evidence={"user_id": "user-4", "manual_action_required": True},
    )
    session = offboarding_service.create_session(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-4",
    )

    automated_step = session["steps"][1]["id"]

    async def fake_execute_approved_remediation(
        *, db, compliance_result_id, tenant, tenant_id, execution_payload=None, **_kwargs
    ):
        raise RuntimeError("temporary remediation failure")

    monkeypatch.setattr(
        offboarding_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    failed = asyncio.run(offboarding_service.execute_step(db_session, tenant, session["session_id"], automated_step))

    assert failed["status"] == "IN_PROGRESS"
    assert failed["steps"][1]["status"] == "failed"
    assert failed["steps"][1]["error"] == "temporary remediation failure"
    assert failed["error"] == "temporary remediation failure"
    assert failed["retryable"] is True


def test_manual_action_required_finding_executes_anyway(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    compliance = seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-5",
        evidence={"user_id": "user-5", "manual_action_required": True},
        decision_status="MANUAL_ACTION_REQUIRED",
    )
    session = offboarding_service.create_session(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-5",
    )

    calls: list[int] = []

    async def fake_execute_approved_remediation(
        *, db, compliance_result_id, tenant, tenant_id, execution_payload=None, **_kwargs
    ):
        calls.append(compliance_result_id)
        return {"status": "EXECUTED"}

    monkeypatch.setattr(
        offboarding_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    automated_step = session["steps"][1]["id"]
    result = asyncio.run(offboarding_service.execute_step(db_session, tenant, session["session_id"], automated_step))

    db_session.refresh(compliance)
    assert calls == [compliance.id]
    assert compliance.decision_status == "APPROVED"
    assert result["steps"][1]["status"] == "completed"


def test_user_offboarding_flow_completes(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-6",
        email="user6@example.com",
        is_admin=True,
    )

    session = offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-6",
    )

    calls: list[str] = []

    async def fake_execute_user_action(*, db, tenant, action, user_id):
        calls.append(f"{action}:{user_id}")
        return {"status": "SUCCESS"}

    monkeypatch.setattr(
        offboarding_service,
        "_execute_user_action",
        fake_execute_user_action,
    )

    for step in session["steps"]:
        session = asyncio.run(
            offboarding_service.execute_user_offboarding_step(
                db_session,
                tenant,
                "user-6",
                step["id"],
            )
        )

    assert calls == [
        "remove_admin_roles:user-6",
        "revoke_sessions:user-6",
        "disable_account:user-6",
    ]
    assert session["status"] == "COMPLETED"
    assert all(step["status"] == "completed" for step in session["steps"])


def test_user_offboarding_start_always_creates_fresh_session(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-7",
        email="user7@example.com",
        is_admin=False,
    )

    first_session = offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-7",
    )

    async def fake_execute_user_action(*, db, tenant, action, user_id):
        return {"status": "SUCCESS"}

    monkeypatch.setattr(
        offboarding_service,
        "_execute_user_action",
        fake_execute_user_action,
    )

    first_step_id = first_session["steps"][0]["id"]
    completed_session = asyncio.run(
        offboarding_service.execute_user_offboarding_step(
            db_session,
            tenant,
            "user-7",
            first_step_id,
        )
    )
    assert completed_session["steps"][0]["status"] == "completed"

    second_session = offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-7",
    )

    assert second_session["session_id"] != first_session["session_id"]
    assert all(step["status"] == "pending" for step in second_session["steps"])
    assert second_session["steps"][0]["id"] != first_step_id


def test_create_session_for_tenant_rejects_dormant_account_control(db_session):
    tenant = seed_tenant(db_session)

    with pytest.raises(ValueError, match="Dormant account findings use remediation execution, not offboarding"):
        asyncio.run(
            offboarding_service.create_session_for_tenant(
                db_session,
                tenant=tenant,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_id="user-admin",
            )
        )


def test_user_offboarding_completion_resolves_user_findings(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-11",
        email="user11@example.com",
        is_admin=False,
    )
    finding = seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-11",
        evidence={"user_id": "user-11"},
    )

    session = offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-11",
    )

    async def fake_execute_user_action(*, db, tenant, action, user_id):
        return {"status": "SUCCESS"}

    monkeypatch.setattr(
        offboarding_service,
        "_execute_user_action",
        fake_execute_user_action,
    )

    for step in session["steps"]:
        session = asyncio.run(
            offboarding_service.execute_user_offboarding_step(
                db_session,
                tenant,
                "user-11",
                step["id"],
            )
        )

    db_session.refresh(finding)
    assert session["status"] == "COMPLETED"
    assert finding.passed is True
    assert finding.exposure_status == "RESOLVED"
    assert finding.resolved_by == "OFFBOARDING"
    assert finding.resolved_at is not None


def test_rollback_user_offboarding_reopens_user_findings(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-12",
        email="user12@example.com",
        is_admin=False,
    )
    finding = seed_compliance(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-12",
        evidence={"user_id": "user-12"},
    )
    finding.passed = True
    finding.exposure_status = "RESOLVED"
    finding.resolved_by = "OFFBOARDING"
    db_session.commit()

    offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-12",
    )
    stored_session = offboarding_service.get_user_offboarding_session(
        db_session,
        tenant.id,
        "user-12",
    )
    stored_session.status = offboarding_service.OffboardingSessionStatus.COMPLETED
    db_session.commit()

    async def fake_enable_user(**kwargs):
        return {"status": "SUCCESS"}

    async def fake_fetch_roles(db, tenant, user_id):
        return []

    monkeypatch.setattr(
        "app.services.offboarding.offboarding_rollback.set_user_account_enabled_with_app_token",
        fake_enable_user,
    )
    monkeypatch.setattr(
        "app.services.offboarding.offboarding_rollback.fetch_user_memberof_directory_roles",
        fake_fetch_roles,
    )

    asyncio.run(
        rollback_offboarding(
            db=db_session,
            tenant=tenant,
            session=stored_session,
        )
    )

    db_session.refresh(finding)
    assert finding.passed is False
    assert finding.exposure_status == "ACTIVE"
    assert finding.resolved_by is None
    assert finding.resolved_at is None


def test_user_offboarding_role_removal_requires_verification(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-8",
        email="user8@example.com",
        is_admin=True,
    )
    session = offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-8",
    )

    remove_roles_step = session["steps"][0]["id"]

    async def fake_fetch_roles(db, tenant, user_id):
        return [{"id": "role-1", "displayName": "Global Administrator"}]

    async def fake_execute(self, graph_client, evidence):
        return {"status": "SUCCESS"}

    async def fake_verify_with_retries(self, *, attempts=3, delay_seconds=0.75):
        return SimpleNamespace(
            verified=False,
            reason="ROLE_REMOVAL_NOT_EFFECTIVE",
            evidence={"remaining_roles": ["Global Administrator"]},
        )

    monkeypatch.setattr(offboarding_service, "fetch_user_memberof_directory_roles", fake_fetch_roles)
    monkeypatch.setattr(offboarding_service.AdminRoleExecutor, "execute", fake_execute)
    monkeypatch.setattr(offboarding_service.AdminRoleVerifier, "verify_with_retries", fake_verify_with_retries)

    failed = asyncio.run(
        offboarding_service.execute_user_offboarding_step(
            db_session,
            tenant,
            "user-8",
            remove_roles_step,
        )
    )

    assert failed["status"] == "IN_PROGRESS"
    assert failed["steps"][0]["status"] == "failed"
    assert failed["steps"][0]["error"] == "ROLE_REMOVAL_NOT_EFFECTIVE"
    assert failed["retryable"] is True


def test_disable_account_is_blocked_when_admin_roles_still_present(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-9",
        email="user9@example.com",
        is_admin=True,
    )
    session = offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-9",
    )

    disable_step = session["steps"][2]["id"]

    async def fake_fetch_roles(db, tenant, user_id):
        return [{"id": "role-1", "displayName": "Global Administrator"}]

    monkeypatch.setattr(offboarding_service, "fetch_user_memberof_directory_roles", fake_fetch_roles)

    failed = asyncio.run(
        offboarding_service.execute_user_offboarding_step(
            db_session,
            tenant,
            "user-9",
            disable_step,
        )
    )

    assert failed["status"] == "IN_PROGRESS"
    assert failed["steps"][2]["status"] == "failed"
    assert failed["steps"][2]["error"] == "User still has admin roles"
    assert failed["retryable"] is True


def test_restart_user_offboarding_resets_failed_steps_from_current_state(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-10",
        email="user10@example.com",
        is_admin=False,
    )
    offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-10",
    )

    stored_session = offboarding_service.get_user_offboarding_session(
        db_session,
        tenant.id,
        "user-10",
    )
    stored_session.status = offboarding_service.OffboardingSessionStatus.IN_PROGRESS
    stored_session.steps = [
        {**dict(stored_session.steps[0]), "status": "completed", "error": None},
        {**dict(stored_session.steps[1]), "status": "failed", "error": "temporary remediation failure"},
        {**dict(stored_session.steps[2]), "status": "pending", "error": None},
        {**dict(stored_session.steps[3]), "status": "pending", "error": None},
    ]
    db_session.add(stored_session)
    db_session.commit()

    async def fake_snapshot_user_state(db, tenant, user_id):
        return {
            "user_id": user_id,
            "account_enabled": True,
            "roles": [],
            "is_global_admin": False,
        }

    monkeypatch.setattr(offboarding_service, "snapshot_user_state", fake_snapshot_user_state)

    restarted = asyncio.run(
        offboarding_service.restart_user_offboarding_session(
            db_session,
            tenant=tenant,
            user_id="user-10",
        )
    )

    assert restarted["status"] == "PENDING"
    assert restarted["steps"][0]["status"] == "completed"
    assert restarted["steps"][1]["status"] == "pending"
    assert restarted["steps"][2]["status"] == "pending"
    assert restarted["current_step"] == 1
    assert restarted["step_states"] == ["COMPLETED", "PENDING", "PENDING", "PENDING"]


def test_restart_user_offboarding_marks_partial_real_state_as_completed(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_user(
        db_session,
        tenant_id=tenant.id,
        external_id="user-11",
        email="user11@example.com",
        is_admin=False,
    )
    offboarding_service.create_user_offboarding_session(
        db_session,
        tenant_id=tenant.id,
        user_id="user-11",
    )

    async def fake_snapshot_user_state(db, tenant, user_id):
        return {
            "user_id": user_id,
            "account_enabled": False,
            "roles": [],
            "is_global_admin": False,
        }

    monkeypatch.setattr(offboarding_service, "snapshot_user_state", fake_snapshot_user_state)

    restarted = asyncio.run(
        offboarding_service.restart_user_offboarding_session(
            db_session,
            tenant=tenant,
            user_id="user-11",
        )
    )

    assert restarted["status"] == "PENDING"
    assert restarted["steps"][0]["status"] == "completed"
    assert restarted["steps"][2]["status"] == "completed"
    assert restarted["steps"][1]["status"] == "pending"
    assert restarted["steps"][3]["status"] == "pending"
    assert restarted["step_states"] == ["COMPLETED", "PENDING", "COMPLETED", "PENDING"]
