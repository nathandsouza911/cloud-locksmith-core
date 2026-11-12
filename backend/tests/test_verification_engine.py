"""Tests for VerificationEngine — dispatch, None for unsupported controls,
and parity with direct verifier calls for all 12 verifiable controls."""

import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.services.remediation.verification.engine import VerificationEngine, verification_engine
from app.services.remediation.verification.adapter import VerificationResult


# ---------------------------------------------------------------------------
# Engine dispatch
# ---------------------------------------------------------------------------


def test_engine_returns_none_for_non_verifiable_control():
    result = asyncio.run(
        verification_engine.run(
            "IDENTITY_USER_NO_MFA",
            db=None,
            tenant=SimpleNamespace(id="t-1"),
            compliance_result=SimpleNamespace(evidence={}),
        )
    )
    assert result is None


def test_engine_returns_verification_result_for_verifiable_control():
    """IDENTITY_UNUSED_ACCOUNT is verifiable — engine must return a VerificationResult."""
    import app.services.remediation.verification.dormant_account_verifier as mod
    from types import SimpleNamespace

    class _FakeAdapter:
        async def get_user_account_state(self, user_id, *, use_application_token=False):
            return {"accountEnabled": False}

    def _fake_identity(*, db, tenant):
        return _FakeAdapter()

    import unittest.mock as mock

    with mock.patch.object(mod, "get_identity_provider_adapter", _fake_identity):
        result = asyncio.run(
            verification_engine.run(
                "IDENTITY_UNUSED_ACCOUNT",
                db=None,
                tenant=SimpleNamespace(id="t-1"),
                compliance_result=SimpleNamespace(
                    evidence={"user_id": "u-123"},
                    id=1,
                ),
            )
        )

    assert isinstance(result, VerificationResult)
    assert result.control_id == "IDENTITY_UNUSED_ACCOUNT"
    assert result.success is True


def test_engine_returns_none_for_unknown_control():
    result = asyncio.run(
        verification_engine.run(
            "CONTROL_THAT_DOES_NOT_EXIST",
            db=None,
            tenant=None,
            compliance_result=None,
        )
    )
    assert result is None


def test_engine_singleton_is_verification_engine_instance():
    assert isinstance(verification_engine, VerificationEngine)


def test_engine_result_to_legacy_dict_matches_expected_shape():
    """to_legacy_dict() must produce the shape existing callers expect."""
    import app.services.remediation.verification.dormant_account_verifier as mod
    import unittest.mock as mock

    class _FakeAdapter:
        async def get_user_account_state(self, user_id, *, use_application_token=False):
            return {"accountEnabled": True}

    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        result = asyncio.run(
            verification_engine.run(
                "IDENTITY_UNUSED_ACCOUNT",
                db=None,
                tenant=SimpleNamespace(id="t-1"),
                compliance_result=SimpleNamespace(
                    evidence={"user_id": "u-456"},
                    id=1,
                ),
            )
        )

    legacy = result.to_legacy_dict()
    assert "success" in legacy
    assert "details" in legacy
    assert "reason" in legacy["details"]
    assert "evidence" in legacy["details"]


# ---------------------------------------------------------------------------
# Parity tests — engine result must match direct verifier result
# ---------------------------------------------------------------------------
# For each verifiable control: call the raw verifier AND the engine with the
# same mocked state. Assert success values are identical.
# ---------------------------------------------------------------------------


async def _direct_verifier(control_id: str, **kwargs):
    """Call the registered verifier directly (bypassing the engine)."""
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    verifier = CONTROL_REGISTRY[control_id]["verifier"]
    return await verifier(**kwargs)


async def _engine_result(control_id: str, **kwargs):
    """Call through the engine."""
    return await verification_engine.run(control_id, **kwargs)


# --- IDENTITY_GUEST_INVITES_OPEN ---


def test_parity_guest_invites_restricted():
    import unittest.mock as mock
    import app.services.remediation.verification.tenant_identity_verifier as mod

    class _FakeAdapter:
        async def get_authorization_policy(self):
            return {"allowInvitesFrom": "adminsAndGuestInviters"}

    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=None)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_GUEST_INVITES_OPEN", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_GUEST_INVITES_OPEN", **kwargs))
    assert raw["success"] == eng.success


def test_parity_guest_invites_not_restricted():
    import unittest.mock as mock
    import app.services.remediation.verification.tenant_identity_verifier as mod

    class _FakeAdapter:
        async def get_authorization_policy(self):
            return {"allowInvitesFrom": "everyone"}

    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=None)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_GUEST_INVITES_OPEN", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_GUEST_INVITES_OPEN", **kwargs))
    assert raw["success"] == eng.success


# --- IDENTITY_USER_CONSENT_POLICY ---


def test_parity_user_consent_restricted():
    import unittest.mock as mock
    import app.services.remediation.verification.tenant_identity_verifier as mod

    class _FakeAdapter:
        async def get_authorization_policy(self):
            return {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}}

    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=None)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_USER_CONSENT_POLICY", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_USER_CONSENT_POLICY", **kwargs))
    assert raw["success"] == eng.success


def test_parity_user_consent_not_restricted():
    import unittest.mock as mock
    import app.services.remediation.verification.tenant_identity_verifier as mod

    class _FakeAdapter:
        async def get_authorization_policy(self):
            return {
                "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.any"]}
            }

    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=None)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_USER_CONSENT_POLICY", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_USER_CONSENT_POLICY", **kwargs))
    assert raw["success"] == eng.success


# --- IDENTITY_UNUSED_ACCOUNT ---


def test_parity_dormant_account_disabled():
    import unittest.mock as mock
    import app.services.remediation.verification.dormant_account_verifier as mod

    class _FakeAdapter:
        async def get_user_account_state(self, uid, *, use_application_token=False):
            return {"accountEnabled": False}

    cr = SimpleNamespace(evidence={"user_id": "u-1"}, id=1)
    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=cr)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_UNUSED_ACCOUNT", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_UNUSED_ACCOUNT", **kwargs))
    assert raw["success"] == eng.success


def test_parity_dormant_account_still_enabled():
    import unittest.mock as mock
    import app.services.remediation.verification.dormant_account_verifier as mod

    class _FakeAdapter:
        async def get_user_account_state(self, uid, *, use_application_token=False):
            return {"accountEnabled": True}

    cr = SimpleNamespace(evidence={"user_id": "u-2"}, id=1)
    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=cr)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_UNUSED_ACCOUNT", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_UNUSED_ACCOUNT", **kwargs))
    assert raw["success"] == eng.success


# --- IDENTITY_ILLICIT_CONSENT_GRANTS ---


def test_parity_illicit_grants_all_removed():
    import unittest.mock as mock
    import app.services.remediation.verification.illicit_consent_grants_verifier as mod
    from app.services.graph_client import GraphAPIError

    class _FakeAdapter:
        async def get_oauth2_permission_grant(self, grant_id):
            raise GraphAPIError(
                method="GET", path=f"/grants/{grant_id}", status_code=404, response_body="", category="not_found"
            )

    cr = SimpleNamespace(evidence={"snapshot": {"grants": [{"id": "g-1"}]}}, id=1)
    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=cr)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_ILLICIT_CONSENT_GRANTS", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_ILLICIT_CONSENT_GRANTS", **kwargs))
    assert raw["success"] == eng.success


def test_parity_illicit_grants_still_present():
    import unittest.mock as mock
    import app.services.remediation.verification.illicit_consent_grants_verifier as mod

    class _FakeAdapter:
        async def get_oauth2_permission_grant(self, grant_id):
            return {"id": grant_id}

    cr = SimpleNamespace(evidence={"snapshot": {"grants": [{"id": "g-2"}]}}, id=1)
    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=cr)
    with mock.patch.object(mod, "get_identity_provider_adapter", lambda **kw: _FakeAdapter()):
        raw = asyncio.run(_direct_verifier("IDENTITY_ILLICIT_CONSENT_GRANTS", **kwargs))
        eng = asyncio.run(_engine_result("IDENTITY_ILLICIT_CONSENT_GRANTS", **kwargs))
    assert raw["success"] == eng.success


# --- IDENTITY_OVERPRIVILEGED_USER ---


@pytest.mark.asyncio
async def test_parity_overprivileged_user_roles_removed():
    """IDENTITY_OVERPRIVILEGED_USER: roles removed → success=True, engine matches verifier."""
    import unittest.mock as mock
    from app.services.remediation.admin_roles.admin_role_verifier import verify_admin_role_removal
    from app.services.remediation.verification.engine import verification_engine

    fake_snapshot = mock.Mock()
    fake_snapshot.state = {"roles": [{"role_id": "r1", "role_name": "Global Administrator"}]}

    fake_db = mock.Mock()
    fake_db.query.return_value.filter.return_value.order_by.return_value.first.return_value = fake_snapshot

    fake_tenant = mock.Mock()
    fake_cr = mock.Mock()
    fake_cr.id = 1
    fake_cr.evidence = {"user_id": "u1"}
    fake_cr.resource_id = "u1"

    fake_adapter = mock.AsyncMock()
    fake_adapter.fetch_user_memberof_directory_roles.return_value = []  # roles gone

    with mock.patch(
        "app.services.remediation.admin_roles.admin_role_verifier.get_identity_provider_adapter",
        return_value=fake_adapter,
    ):
        raw = await verify_admin_role_removal(db=fake_db, tenant=fake_tenant, compliance_result=fake_cr)
        eng = await verification_engine.run(
            "IDENTITY_OVERPRIVILEGED_USER",
            db=fake_db,
            tenant=fake_tenant,
            compliance_result=fake_cr,
        )

    assert raw["success"] is True
    assert eng.success is True
    assert raw["success"] == eng.success


@pytest.mark.asyncio
async def test_parity_overprivileged_user_roles_still_present():
    """IDENTITY_OVERPRIVILEGED_USER: roles still present → success=False, engine matches verifier."""
    import unittest.mock as mock
    from app.services.remediation.admin_roles.admin_role_verifier import verify_admin_role_removal
    from app.services.remediation.verification.engine import verification_engine

    fake_snapshot = mock.Mock()
    fake_snapshot.state = {"roles": [{"role_id": "r1", "role_name": "Global Administrator"}]}

    fake_db = mock.Mock()
    fake_db.query.return_value.filter.return_value.order_by.return_value.first.return_value = fake_snapshot

    fake_tenant = mock.Mock()
    fake_cr = mock.Mock()
    fake_cr.id = 1
    fake_cr.evidence = {"user_id": "u1"}
    fake_cr.resource_id = "u1"

    fake_adapter = mock.AsyncMock()
    fake_adapter.fetch_user_memberof_directory_roles.return_value = [
        {"id": "r1", "displayName": "Global Administrator"}
    ]  # role still present

    with mock.patch(
        "app.services.remediation.admin_roles.admin_role_verifier.get_identity_provider_adapter",
        return_value=fake_adapter,
    ):
        raw = await verify_admin_role_removal(db=fake_db, tenant=fake_tenant, compliance_result=fake_cr)
        eng = await verification_engine.run(
            "IDENTITY_OVERPRIVILEGED_USER",
            db=fake_db,
            tenant=fake_tenant,
            compliance_result=fake_cr,
        )

    assert raw["success"] is False
    assert eng.success is False
    assert raw["success"] == eng.success


# --- CA controls (all 7, success path) ---

CA_CONTROL_IDS = [
    "CA_MFA_ALL_USERS",
    "CA_MFA_ADMINS",
    "CA_LEGACY_AUTH_BLOCK",
    "CA_DEVICE_CODE_FLOW_BLOCK",
    "CA_AUTHENTICATION_TRANSFER_BLOCK",
    "CA_GUEST_MFA",
    "CA_BREAK_GLASS_EXCLUSION",
]


@pytest.mark.parametrize("control_id", CA_CONTROL_IDS)
def test_parity_ca_control_passes(control_id):
    """CA adapter passes when the underlying CA verifier returns True."""
    from app.services.remediation.verification.ca_verifier_adapter import make_ca_verifier_adapter

    async def _pass_verifier(*, graph_client):
        return True

    # Use a no-op client_factory so db=None doesn't cause RemediationGraphClient to fail.
    patched_adapter = make_ca_verifier_adapter(
        _pass_verifier,
        control_id=control_id,
        client_factory=lambda **kw: None,
    )
    cr = SimpleNamespace(evidence={}, id=1)
    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=cr)

    # Build a temporary engine that uses the patched adapter
    from app.services.remediation.verification.adapter import LegacyFunctionAdapter
    from app.services.remediation.verification import adapter_registry as reg_mod

    original_registry = dict(reg_mod.ADAPTER_REGISTRY)
    reg_mod.ADAPTER_REGISTRY[control_id] = LegacyFunctionAdapter(patched_adapter, control_id=control_id)
    try:
        raw = asyncio.run(patched_adapter(**kwargs))
        eng = asyncio.run(verification_engine.run(control_id, **kwargs))
    finally:
        reg_mod.ADAPTER_REGISTRY.clear()
        reg_mod.ADAPTER_REGISTRY.update(original_registry)

    assert raw["success"] == eng.success


@pytest.mark.parametrize("control_id", CA_CONTROL_IDS)
def test_parity_ca_control_fails(control_id):
    """CA adapter fails when the underlying CA verifier returns False."""
    from app.services.remediation.verification.ca_verifier_adapter import make_ca_verifier_adapter

    async def _fail_verifier(*, graph_client):
        return False

    # Use a no-op client_factory so db=None doesn't cause RemediationGraphClient to fail.
    patched_adapter = make_ca_verifier_adapter(
        _fail_verifier,
        control_id=control_id,
        client_factory=lambda **kw: None,
    )
    cr = SimpleNamespace(evidence={}, id=1)
    kwargs = dict(db=None, tenant=SimpleNamespace(id="t"), compliance_result=cr)

    from app.services.remediation.verification.adapter import LegacyFunctionAdapter
    from app.services.remediation.verification import adapter_registry as reg_mod

    original_registry = dict(reg_mod.ADAPTER_REGISTRY)
    reg_mod.ADAPTER_REGISTRY[control_id] = LegacyFunctionAdapter(patched_adapter, control_id=control_id)
    try:
        raw = asyncio.run(patched_adapter(**kwargs))
        eng = asyncio.run(verification_engine.run(control_id, **kwargs))
    finally:
        reg_mod.ADAPTER_REGISTRY.clear()
        reg_mod.ADAPTER_REGISTRY.update(original_registry)

    assert raw["success"] == eng.success


# ---------------------------------------------------------------------------
# verify_execution integration � engine path
# ---------------------------------------------------------------------------


def test_verify_execution_routes_through_engine_for_verifiable_control(monkeypatch):
    """verify_execution must delegate to the engine via verify_once, not call the verifier directly."""
    import app.services.remediation.verification.verify_execution as ve_mod
    from app.services.remediation.verification.engine import VerificationEngine, VerificationResult

    calls = []

    async def _fake_engine_verify_once(control_id, *, db, tenant, compliance_result, execution_id):
        calls.append(control_id)
        return (
            VerificationResult(success=True, reason=None, evidence={}, control_id=control_id),
            None,  # lifecycle row (not needed for this test)
        )

    fake_engine = VerificationEngine()
    fake_engine.verify_once = _fake_engine_verify_once

    monkeypatch.setattr(ve_mod, "verification_engine", fake_engine)

    from sqlalchemy import create_engine as sa_create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.models.compliance_result import ComplianceResult
    from app.db.models.remediation_audit import RemediationAuditLog
    from app.db.models.tenant import Tenant

    engine = sa_create_engine("sqlite:///:memory:")
    ComplianceResult.__table__.create(engine)
    RemediationAuditLog.__table__.create(engine)
    Tenant.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    t = Tenant(id="t-ve-test", tenant_name="VE Tenant")
    db.add(t)
    cr = ComplianceResult(
        tenant_id="t-ve-test",
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        passed=False,
        severity="HIGH",
        evidence={},
    )
    db.add(cr)
    db.flush()

    audit = RemediationAuditLog(
        compliance_result_id=cr.id,
        tenant_id="t-ve-test",
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id="t-ve-test",
        decision="EXECUTED",
        rolled_back=False,
    )
    db.add(audit)
    db.commit()

    result = asyncio.run(ve_mod.verify_execution(db=db, tenant=t, compliance_result_id=cr.id))
    db.close()

    assert "IDENTITY_GUEST_INVITES_OPEN" in calls, "verify_execution must call engine.verify_once with the control_id"
    assert result["success"] is True
    assert result["verification_supported"] is True


# ---------------------------------------------------------------------------
# run_verification_job — engine path
# ---------------------------------------------------------------------------


def test_run_verification_job_routes_through_engine(monkeypatch):
    """run_verification_job must use engine.verify_confirmed (not engine.run) for lifecycle tracking."""
    import uuid
    import app.jobs.remediation_verification as job_mod
    from app.services.remediation.verification.engine import VerificationEngine, VerificationResult

    engine_calls = []

    async def _fake_verify_confirmed(control_id, *, db, tenant, compliance_result, execution_id):
        engine_calls.append({"control_id": control_id, "execution_id": execution_id})
        return (
            VerificationResult(success=True, reason=None, evidence={}, control_id=control_id),
            None,  # lifecycle row (not needed for this test)
        )

    fake_engine = VerificationEngine()
    fake_engine.verify_confirmed = _fake_verify_confirmed
    monkeypatch.setattr(job_mod, "verification_engine", fake_engine)

    from sqlalchemy import create_engine as sa_create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.models.compliance_result import ComplianceResult, RemediationStatus
    from app.db.models.remediation_audit import RemediationAuditLog
    from app.db.models.tenant import Tenant
    from unittest.mock import patch

    engine = sa_create_engine("sqlite:///:memory:")
    ComplianceResult.__table__.create(engine)
    RemediationAuditLog.__table__.create(engine)
    Tenant.__table__.create(engine)
    Session = sessionmaker(bind=engine)

    def _fake_session():
        return Session()

    audit_id = uuid.uuid4()

    t = Tenant(id="t-job-test", tenant_name="Job Tenant")
    cr = ComplianceResult(
        tenant_id="t-job-test",
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        passed=False,
        severity="HIGH",
        evidence={},
        remediation_status=RemediationStatus.SUCCESS,
    )

    db = Session()
    db.add(t)
    db.add(cr)
    db.flush()

    audit = RemediationAuditLog(
        id=audit_id,
        compliance_result_id=cr.id,
        tenant_id="t-job-test",
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id="t-job-test",
        decision="EXECUTED",
        execution_status="EXECUTED",
        rolled_back=False,
    )
    db.add(audit)
    db.commit()
    db.close()

    with patch("app.jobs.remediation_verification.SyncSessionLocal", _fake_session):
        with patch("app.jobs.remediation_verification.create_posture_snapshot"):
            asyncio.run(job_mod.run_verification_job())

    assert len(engine_calls) == 1, "run_verification_job must call engine.verify_confirmed exactly once"
    assert (
        engine_calls[0]["control_id"] == "IDENTITY_GUEST_INVITES_OPEN"
    ), "run_verification_job must call engine.verify_confirmed with the correct control_id"
    assert (
        engine_calls[0]["execution_id"] == audit_id
    ), "run_verification_job must pass the audit log id as execution_id"


# ---------------------------------------------------------------------------
# verify_execution lifecycle integration (Task 6)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_execution_creates_lifecycle_row_on_success():
    """After verify_execution() completes, a RemediationVerification row exists."""
    import uuid
    import unittest.mock as mock
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
    from app.services.remediation.verification.verify_execution import verify_execution

    engine_db = create_engine("sqlite:///:memory:")
    RemediationVerification.__table__.create(engine_db)
    VerificationEvent.__table__.create(engine_db)
    Session = sessionmaker(bind=engine_db)
    db = Session()

    eid = uuid.uuid4()
    fake_compliance = SimpleNamespace(
        id=1, tenant_id="t1", evidence={}, resource_id="r1", control_id="IDENTITY_UNUSED_ACCOUNT"
    )
    fake_execution = SimpleNamespace(
        id=eid,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        decision="EXECUTED",
        rolled_back=False,
        verified=False,
        verified_at=None,
        created_at=datetime(2026, 1, 1),
    )
    fake_tenant = SimpleNamespace(id="t1")

    with mock.patch(
        "app.services.remediation.verification.verify_execution.verification_engine.verify_once",
        new_callable=mock.AsyncMock,
    ) as mock_verify_once:
        fake_rv = SimpleNamespace(
            id=uuid.uuid4(),
            status="VERIFIED_PROVISIONAL",
            verification_count=1,
        )
        mock_verify_once.return_value = (
            SimpleNamespace(
                success=True,
                reason=None,
                evidence={},
                to_legacy_dict=lambda: {"success": True, "details": {"reason": None, "evidence": {}}},
            ),
            fake_rv,
        )
        # db is passed as arg, no module-level patch needed

        # Patch the DB queries to return our fakes
        with mock.patch.object(db, "query") as mock_query:
            mock_query.return_value.filter.return_value.one_or_none.return_value = fake_compliance
            mock_query.return_value.filter.return_value.order_by.return_value.first.return_value = fake_execution

            result = await verify_execution(db=db, tenant=fake_tenant, compliance_result_id=1)

    assert result["verification_supported"] is True
    mock_verify_once.assert_called_once()
    # control_id is passed positionally; execution_id is a keyword arg
    call_args = mock_verify_once.call_args
    assert call_args.args[0] == "IDENTITY_UNUSED_ACCOUNT"
    assert call_args.kwargs["execution_id"] == eid
    db.close()
