import asyncio
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.ca_policy_engine import (
    CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
    CONTROL_BREAK_GLASS_EXCLUSION,
    CONTROL_DEVICE_CODE_FLOW_BLOCK,
    CONTROL_GUEST_MFA,
    CONTROL_LEGACY_AUTH_BLOCK,
    CONTROL_MFA_ADMINS,
    CONTROL_MFA_ALL_USERS,
    ControlEngineError,
    _build_exclude_users_patch,
    apply_policies_bulk,
    build_policy,
    fetch_clx_policies,
    rollback_control,
    rollback_break_glass_exclusion,
    verify_exact_state,
)
from app.services.detection.conditional_access.ca_mfa_checks import (
    detect_ca_mfa_admins,
)
from app.services.detection.conditional_access.ca_auth_vector_checks import (
    detect_ca_authentication_transfer_blocked,
)
from app.services.detection.conditional_access.ca_guest_mfa import (
    detect_ca_guest_mfa,
)
from app.services.detection.conditional_access.constants import (
    PRIVILEGED_ROLE_TEMPLATE_IDS,
)
from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.remediation.mfa_policy import build_mfa_admins_policy


class _FakeGraphClient:
    def __init__(self, policies: list[dict]):
        self._policies = policies

    async def list_conditional_access_policies(self):
        return list(self._policies)


class _FakeGraphMutationClient(_FakeGraphClient):
    def __init__(self, policies: list[dict]):
        super().__init__(policies)
        self.created: list[str] = []
        self.updated: list[str] = []
        self.deleted: list[str] = []

    async def update_conditional_access_policy(self, policy_id: str, policy: dict):
        self.updated.append(policy_id)
        for idx, current in enumerate(self._policies):
            if current.get("id") == policy_id:
                self._policies[idx] = {**policy, "id": policy_id}
                return self._policies[idx]
        raise AssertionError(f"policy not found: {policy_id}")

    async def create_conditional_access_policy(self, policy: dict):
        created = {**policy, "id": f"created-{len(self.created) + 1}"}
        self.created.append(created["id"])
        self._policies.append(created)
        return created

    async def delete_conditional_access_policy(self, policy_id: str):
        self.deleted.append(policy_id)
        self._policies = [policy for policy in self._policies if policy.get("id") != policy_id]
        return {}


class _FakePatchGraphClient(_FakeGraphClient):
    def __init__(self, policies: list[dict]):
        super().__init__(policies)
        self.patch_bodies: list[dict] = []

    async def update_conditional_access_policy(self, policy_id: str, patch_body: dict):
        self.patch_bodies.append({"policy_id": policy_id, "patch": patch_body})
        for policy in self._policies:
            if policy.get("id") == policy_id:
                users = policy.setdefault("conditions", {}).setdefault("users", {})
                users["excludeUsers"] = patch_body["conditions"]["users"]["excludeUsers"]
                return policy
        raise AssertionError(f"policy not found: {policy_id}")


def test_fetch_clx_policies_isolates_controls_by_exact_base_name():
    graph_client = _FakeGraphClient(
        [
            {"id": "customer-prefix-collision", "displayName": "CLX-MFA-ADMINS-v1"},
            {"id": "2", "displayName": "CLX-MFA-ALL-USERS-v1"},
            {"id": "managed-admin", "displayName": "CLX-MFA-ADMINS-v2"},
            {"id": "4", "displayName": "CLX-MFA-UNRELATED-v1"},
        ]
    )

    admin_policies = asyncio.run(
        fetch_clx_policies(
            graph_client,
            CONTROL_MFA_ADMINS,
            managed_policy_ids=["managed-admin"],
        )
    )
    untracked_admin_policies = asyncio.run(fetch_clx_policies(graph_client, CONTROL_MFA_ADMINS))

    assert [policy["displayName"] for policy in admin_policies] == [
        "CLX-MFA-ADMINS-v2",
    ]
    assert untracked_admin_policies == []


def test_apply_policy_creates_new_policy_when_prefix_collision_is_untracked():
    graph_client = _FakeGraphMutationClient(
        [
            {
                "id": "customer-prefix-collision",
                "displayName": "CLX-MFA-ADMINS-v1",
                "state": "enabled",
                "conditions": {},
                "grantControls": {},
            },
        ]
    )
    desired_policy = {
        "displayName": "CLX-MFA-ADMINS-v1",
        "state": "enabled",
        "conditions": {"users": {"includeRoles": []}},
        "grantControls": {"builtInControls": ["mfa"]},
    }

    applied = asyncio.run(
        apply_policies_bulk(
            graph_client=graph_client,
            control_id=CONTROL_MFA_ADMINS,
            policies=[desired_policy],
            managed_policy_ids=[],
        )
    )

    assert applied[0]["id"] == "created-1"
    assert graph_client.updated == []
    assert graph_client.deleted == []
    assert "customer-prefix-collision" in [policy["id"] for policy in graph_client._policies]


def test_build_policy_rejects_empty_rollout_scope():
    try:
        build_policy(
            CONTROL_MFA_ALL_USERS,
            mode="audit",
            rollout_phase="none",
            break_glass_ids=["bg-1"],
        )
    except ControlEngineError as exc:
        assert "no rollout scope" in str(exc)
    else:
        raise AssertionError("Expected ControlEngineError for empty rollout scope")


def test_build_mfa_admins_policy_includes_all_privileged_role_template_ids():
    policy = build_mfa_admins_policy(enforcement_mode="ENFORCED")

    assert policy["conditions"]["users"]["includeRoles"] == sorted(PRIVILEGED_ROLE_TEMPLATE_IDS)
    assert len(policy["conditions"]["users"]["includeRoles"]) == len(PRIVILEGED_ROLE_TEMPLATE_IDS)


def test_admin_mfa_detector_and_remediation_role_sets_are_identical():
    policy = build_mfa_admins_policy(enforcement_mode="ENFORCED")

    assert set(policy["conditions"]["users"]["includeRoles"]) == set(PRIVILEGED_ROLE_TEMPLATE_IDS)


def test_generated_admin_mfa_policy_passes_admin_detector():
    policy = build_mfa_admins_policy(enforcement_mode="ENFORCED")
    ctx = TenantGraphContext(
        tenant_id="tenant-admin-mfa",
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=[policy],
        break_glass_accounts=[],
    )

    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))

    assert len(results) == 1
    assert results[0]["control_id"] == CONTROL_MFA_ADMINS
    assert results[0]["passed"] is True
    assert results[0]["evidence"]["uncovered_role_template_ids"] == []


def test_admin_mfa_noop_uses_full_privileged_role_baseline():
    from app.services import ca_policy_engine

    mock_state = MagicMock()
    mock_state.mode = "enforced"
    mock_state.rollout_phase = "admins"
    mock_state.rollout_percentage = 0
    mock_state.target_group_id = None
    mock_state.policy_version = 1
    mock_state.status = "active"

    mock_tenant = MagicMock()
    mock_tenant.id = "tenant-admin-noop"
    mock_tenant.provider = "microsoft"

    async def fake_policy_matches(**_kwargs):
        return True

    async def fake_calculate_affected(**_kwargs):
        return 3

    with (
        patch.object(ca_policy_engine, "get_control_state", new=AsyncMock(return_value=mock_state)),
        patch.object(ca_policy_engine, "policy_matches_expected", new=fake_policy_matches),
        patch.object(ca_policy_engine, "list_break_glass_user_ids", return_value=["bg-1"]),
        patch.object(ca_policy_engine, "_validate_break_glass_accounts", new=AsyncMock()),
        patch.object(ca_policy_engine, "check_conditional_access_license", new=AsyncMock(return_value=True)),
        patch.object(ca_policy_engine, "calculate_affected_users", new=fake_calculate_affected),
        patch("app.services.ca_policy_engine.settings") as mock_settings,
    ):
        mock_settings.ENABLE_AUTO_REMEDIATION = False
        result = asyncio.run(
            ca_policy_engine.apply_control(
                db=MagicMock(),
                tenant=mock_tenant,
                control_id="CA_MFA_ADMINS",
                mode="enforced",
                rollout_phase="admins",
            )
        )

    assert result["status"] == "no-op"
    assert result["verified"] is True
    assert result["control_id"] == "CA_MFA_ADMINS"
    assert result["state"]["rollout_phase"] == "admins"

    built_policy = ca_policy_engine.build_policy(
        "CA_MFA_ADMINS",
        mode="enforced",
        rollout_phase="admins",
        break_glass_ids=["bg-1"],
        policy_version=1,
    )
    assert built_policy["conditions"]["users"]["includeRoles"] == sorted(PRIVILEGED_ROLE_TEMPLATE_IDS)


def test_apply_policies_bulk_restores_multiple_policies_without_sibling_cleanup():
    graph_client = _FakeGraphMutationClient(
        [
            {"id": "1", "displayName": "CLX-MFA-ADMINS-v1", "state": "enabled", "conditions": {}, "grantControls": {}},
            {
                "id": "2",
                "displayName": "CLX-MFA-ADMINS-v2",
                "state": "enabledForReportingButNotEnforced",
                "conditions": {},
                "grantControls": {},
            },
        ]
    )

    applied = asyncio.run(
        apply_policies_bulk(
            graph_client=graph_client,
            control_id=CONTROL_MFA_ADMINS,
            policies=[
                {
                    "id": "1",
                    "displayName": "CLX-MFA-ADMINS-v1",
                    "state": "enabled",
                    "conditions": {},
                    "grantControls": {},
                },
                {
                    "id": "2",
                    "displayName": "CLX-MFA-ADMINS-v2",
                    "state": "enabledForReportingButNotEnforced",
                    "conditions": {},
                    "grantControls": {},
                },
            ],
            managed_policy_ids=["1", "2"],
        )
    )

    assert len(applied) == 2
    assert graph_client.deleted == []
    assert sorted(policy["displayName"] for policy in graph_client._policies) == [
        "CLX-MFA-ADMINS-v1",
        "CLX-MFA-ADMINS-v2",
    ]


def test_verify_exact_state_accepts_empty_expected_policy_set():
    graph_client = _FakeGraphClient([])

    current = asyncio.run(
        verify_exact_state(
            graph_client=graph_client,
            control_id=CONTROL_MFA_ADMINS,
            expected_policies=[],
        )
    )

    assert current == []


def test_verify_exact_state_normalizes_authentication_transfer_shape():
    expected_policy = build_policy(
        CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1"],
    )
    expected_with_id = {**expected_policy, "id": "policy-auth-transfer"}
    graph_client = _FakeGraphClient(
        [
            {
                **expected_with_id,
                "id": "policy-auth-transfer",
                "conditions": {
                    **expected_policy["conditions"],
                    "authenticationFlows": {
                        "transferMethods": "authenticationTransfer",
                    },
                },
            }
        ]
    )

    current = asyncio.run(
        verify_exact_state(
            graph_client=graph_client,
            control_id=CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
            expected_policies=[expected_with_id],
            managed_policy_ids=["policy-auth-transfer"],
        )
    )

    assert len(current) == 1
    assert current[0]["conditions"]["authenticationFlows"]["transferMethods"] == ["authenticationTransfer"]


def test_verify_exact_state_ignores_graph_generated_ids_for_semantic_match():
    expected_policy = build_policy(
        CONTROL_MFA_ADMINS,
        mode="enforced",
        rollout_phase="admins",
        break_glass_ids=["bg-1"],
    )
    graph_client = _FakeGraphClient(
        [
            {
                **expected_policy,
                "id": "live-graph-id",
            }
        ]
    )

    current = asyncio.run(
        verify_exact_state(
            graph_client=graph_client,
            control_id=CONTROL_MFA_ADMINS,
            expected_policies=[{**expected_policy, "id": "snapshot-graph-id"}],
            managed_policy_ids=["live-graph-id"],
        )
    )

    assert current[0]["id"] == "live-graph-id"


class _FakeDBResult:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return self

    def first(self):
        return self._value


class _FakeDB:
    def __init__(self, execution):
        self.execution = execution

    def execute(self, _query):
        return _FakeDBResult(self.execution)


def test_rollback_control_uses_execution_bound_snapshot_instead_of_latest():
    execution_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    execution = SimpleNamespace(
        id=execution_id,
        tenant_id="tenant-1",
        control_id=CONTROL_MFA_ADMINS,
        status="success",
        snapshot_id=snapshot_id,
    )
    snapshot = SimpleNamespace(
        id=snapshot_id,
        tenant_id="tenant-1",
        control_id=CONTROL_MFA_ADMINS,
        policies=[{"id": "p-a", "displayName": "CLX-MFA-ADMINS-v1"}],
    )
    tenant = SimpleNamespace(id="tenant-1")
    db = _FakeDB(execution)
    fake_remediation_executor = SimpleNamespace(RemediationGraphClient=lambda **kwargs: object())

    with (
        patch.dict(sys.modules, {"app.services.remediation_executor": fake_remediation_executor}),
        patch(
            "app.services.ca_policy_engine.get_snapshot_by_id", new=AsyncMock(return_value=snapshot)
        ) as get_snapshot_by_id_mock,
        patch(
            "app.services.ca_policy_engine.get_latest_snapshot",
            new=AsyncMock(side_effect=AssertionError("latest snapshot should not be used")),
        ),
        patch("app.services.ca_policy_engine.list_break_glass_user_ids", return_value=["bg-1"]),
        patch("app.services.ca_policy_engine._validate_break_glass_accounts", new=AsyncMock(return_value=None)),
        patch("app.services.ca_policy_engine.delete_clx_policies", new=AsyncMock(return_value=["old-policy"])),
        patch("app.services.ca_policy_engine.apply_policies_bulk", new=AsyncMock(return_value=[{"id": "p-a"}])),
        patch("app.services.ca_policy_engine.verify_exact_state", new=AsyncMock(return_value=snapshot.policies)),
        patch(
            "app.services.ca_policy_engine.get_control_state",
            new=AsyncMock(return_value=SimpleNamespace(mode="audit", rollout_phase="admins")),
        ),
        patch(
            "app.services.ca_policy_engine.create_or_update_control_state",
            new=AsyncMock(return_value=SimpleNamespace(mode="audit", rollout_phase="admins", status="active")),
        ),
        patch("app.services.ca_policy_engine._record_control_execution", return_value=SimpleNamespace(id=uuid.uuid4())),
    ):
        result = asyncio.run(
            rollback_control(
                db=db,
                tenant=tenant,
                execution_id=str(execution_id),
                control_id=CONTROL_MFA_ADMINS,
            )
        )

    assert result["status"] == "success"
    assert result["snapshot_id"] == str(snapshot_id)
    assert result["rolled_back_execution_id"] == str(execution_id)
    get_snapshot_by_id_mock.assert_awaited_once_with(db, tenant.id, snapshot_id)


def test_rollback_control_restores_authentication_transfer_snapshot():
    execution_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    execution = SimpleNamespace(
        id=execution_id,
        tenant_id="tenant-1",
        control_id=CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
        status="success",
        snapshot_id=snapshot_id,
    )
    snapshot = SimpleNamespace(
        id=snapshot_id,
        tenant_id="tenant-1",
        control_id=CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
        policies=[{"id": "p-auth", "displayName": "CLX-AUTHENTICATION-TRANSFER-BLOCK-v1"}],
    )
    tenant = SimpleNamespace(id="tenant-1")
    db = _FakeDB(execution)
    fake_remediation_executor = SimpleNamespace(RemediationGraphClient=lambda **kwargs: object())

    with (
        patch.dict(sys.modules, {"app.services.remediation_executor": fake_remediation_executor}),
        patch("app.services.ca_policy_engine.get_snapshot_by_id", new=AsyncMock(return_value=snapshot)),
        patch("app.services.ca_policy_engine.list_break_glass_user_ids", return_value=["bg-1"]),
        patch("app.services.ca_policy_engine._validate_break_glass_accounts", new=AsyncMock(return_value=None)),
        patch("app.services.ca_policy_engine.delete_clx_policies", new=AsyncMock(return_value=["old-policy"])),
        patch("app.services.ca_policy_engine.apply_policies_bulk", new=AsyncMock(return_value=[{"id": "p-auth"}])),
        patch("app.services.ca_policy_engine.verify_exact_state", new=AsyncMock(return_value=snapshot.policies)),
        patch(
            "app.services.ca_policy_engine.get_control_state",
            new=AsyncMock(return_value=SimpleNamespace(mode="audit", rollout_phase="full")),
        ),
        patch(
            "app.services.ca_policy_engine.create_or_update_control_state",
            new=AsyncMock(return_value=SimpleNamespace(mode="audit", rollout_phase="full", status="active")),
        ),
        patch("app.services.ca_policy_engine._record_control_execution", return_value=SimpleNamespace(id=uuid.uuid4())),
    ):
        result = asyncio.run(
            rollback_control(
                db=db,
                tenant=tenant,
                execution_id=str(execution_id),
                control_id=CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
            )
        )

    assert result["status"] == "success"
    assert result["snapshot_id"] == str(snapshot_id)
    assert result["rolled_back_execution_id"] == str(execution_id)


def test_rollback_control_restores_and_verifies_before_deleting_superseded():
    call_order: list[str] = []
    execution_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    execution = SimpleNamespace(
        id=execution_id,
        tenant_id="tenant-1",
        control_id=CONTROL_MFA_ADMINS,
        status="success",
        snapshot_id=snapshot_id,
    )
    snapshot = SimpleNamespace(
        id=snapshot_id,
        tenant_id="tenant-1",
        control_id=CONTROL_MFA_ADMINS,
        policies=[{"id": "previous-policy", "displayName": "CLX-MFA-ADMINS-v1"}],
        managed_policy_ids=["previous-policy"],
    )
    tenant = SimpleNamespace(id="tenant-1")
    db = _FakeDB(execution)
    fake_remediation_executor = SimpleNamespace(RemediationGraphClient=lambda **kwargs: object())

    async def fake_apply_policies_bulk(**_kwargs):
        call_order.append("restore")
        return [{"id": "restored-policy", "displayName": "CLX-MFA-ADMINS-v1"}]

    async def fake_verify_exact_state(**_kwargs):
        call_order.append("verify")
        return [{"id": "restored-policy", "displayName": "CLX-MFA-ADMINS-v1"}]

    async def fake_delete_clx_policies(*_args, **_kwargs):
        call_order.append("delete")
        return ["superseded-policy"]

    with (
        patch.dict(sys.modules, {"app.services.remediation_executor": fake_remediation_executor}),
        patch("app.services.ca_policy_engine.get_snapshot_by_id", new=AsyncMock(return_value=snapshot)),
        patch("app.services.ca_policy_engine.list_break_glass_user_ids", return_value=["bg-1"]),
        patch("app.services.ca_policy_engine._validate_break_glass_accounts", new=AsyncMock(return_value=None)),
        patch("app.services.ca_policy_engine.apply_policies_bulk", new=fake_apply_policies_bulk),
        patch("app.services.ca_policy_engine.verify_exact_state", new=fake_verify_exact_state),
        patch("app.services.ca_policy_engine.delete_clx_policies", new=fake_delete_clx_policies),
        patch(
            "app.services.ca_policy_engine.get_control_state",
            new=AsyncMock(
                return_value=SimpleNamespace(
                    mode="audit", rollout_phase="admins", managed_policy_ids=["superseded-policy"]
                )
            ),
        ),
        patch(
            "app.services.ca_policy_engine.create_or_update_control_state",
            new=AsyncMock(
                return_value=SimpleNamespace(
                    mode="audit", rollout_phase="admins", status="active", managed_policy_ids=["restored-policy"]
                )
            ),
        ),
        patch("app.services.ca_policy_engine._record_control_execution", return_value=SimpleNamespace(id=uuid.uuid4())),
    ):
        result = asyncio.run(
            rollback_control(
                db=db,
                tenant=tenant,
                execution_id=str(execution_id),
                control_id=CONTROL_MFA_ADMINS,
            )
        )

    assert result["status"] == "success"
    assert call_order == ["restore", "verify", "delete"]


def test_build_legacy_auth_block_policy_targets_legacy_client_app_types():
    policy = build_policy(
        CONTROL_LEGACY_AUTH_BLOCK,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1", "bg-2"],
    )
    assert policy["displayName"] == "CLX-LEGACY-AUTH-BLOCK-v1"
    assert policy["state"] == "enabled"
    assert policy["conditions"]["clientAppTypes"] == ["exchangeActiveSync", "other"]
    assert policy["conditions"]["applications"]["includeApplications"] == ["All"]
    assert policy["grantControls"]["builtInControls"] == ["block"]
    assert policy["conditions"]["users"]["excludeUsers"] == ["bg-1", "bg-2"]


def test_build_device_code_flow_block_policy_targets_device_code_flow():
    policy = build_policy(
        CONTROL_DEVICE_CODE_FLOW_BLOCK,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1"],
    )
    assert policy["displayName"] == "CLX-DEVICE-CODE-FLOW-BLOCK-v1"
    assert policy["state"] == "enabled"
    assert policy["conditions"]["authenticationFlows"]["transferMethods"] == ["deviceCodeFlow"]
    assert policy["conditions"]["applications"]["includeApplications"] == ["All"]
    assert policy["grantControls"]["builtInControls"] == ["block"]
    assert policy["conditions"]["users"]["excludeUsers"] == ["bg-1"]


def test_build_authentication_transfer_block_policy_targets_authentication_transfer():
    policy = build_policy(
        CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1"],
    )
    assert policy["displayName"] == "CLX-AUTHENTICATION-TRANSFER-BLOCK-v1"
    assert policy["state"] == "enabled"
    assert policy["conditions"]["authenticationFlows"]["transferMethods"] == ["authenticationTransfer"]
    assert policy["conditions"]["applications"]["includeApplications"] == ["All"]
    assert policy["grantControls"]["builtInControls"] == ["block"]
    assert policy["conditions"]["users"]["excludeUsers"] == ["bg-1"]


def test_generated_authentication_transfer_policy_passes_detector():
    policy = build_policy(
        CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1"],
    )
    ctx = TenantGraphContext(
        tenant_id="tenant-auth-transfer",
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=[policy],
        break_glass_accounts=[],
    )

    results = asyncio.run(detect_ca_authentication_transfer_blocked(ctx=ctx))

    assert len(results) == 1
    assert results[0]["control_id"] == CONTROL_AUTHENTICATION_TRANSFER_BLOCK
    assert results[0]["passed"] is True


def test_build_guest_mfa_policy_targets_guest_and_external_users():
    policy = build_policy(
        CONTROL_GUEST_MFA,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1"],
    )
    assert policy["displayName"] == "CLX-GUEST-MFA-v1"
    assert policy["state"] == "enabled"
    assert policy["conditions"]["applications"]["includeApplications"] == ["All"]
    assert policy["conditions"]["users"]["includeGuestsOrExternalUsers"]["externalTenants"]["membershipKind"] == "all"
    assert (
        "serviceProvider" in policy["conditions"]["users"]["includeGuestsOrExternalUsers"]["guestOrExternalUserTypes"]
    )
    assert policy["grantControls"]["builtInControls"] == ["mfa"]
    assert policy["conditions"]["users"]["excludeUsers"] == ["bg-1"]


def test_generated_guest_mfa_policy_passes_detector():
    policy = build_policy(
        CONTROL_GUEST_MFA,
        mode="enforced",
        rollout_phase="full",
        break_glass_ids=["bg-1"],
    )
    ctx = TenantGraphContext(
        tenant_id="tenant-guest-mfa",
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=[policy],
        break_glass_accounts=[],
    )

    results = asyncio.run(detect_ca_guest_mfa(ctx=ctx))

    assert len(results) == 1
    assert results[0]["control_id"] == CONTROL_GUEST_MFA
    assert results[0]["passed"] is True


def test_block_policies_reject_non_full_rollout():
    for control_id in (
        CONTROL_LEGACY_AUTH_BLOCK,
        CONTROL_DEVICE_CODE_FLOW_BLOCK,
        CONTROL_AUTHENTICATION_TRANSFER_BLOCK,
    ):
        try:
            build_policy(
                control_id,
                mode="enforced",
                rollout_phase="admins",
                break_glass_ids=["bg-1"],
            )
        except ControlEngineError as exc:
            assert "rollout_phase=FULL" in str(exc)
        else:
            raise AssertionError(f"Expected ControlEngineError for non-FULL rollout on {control_id}")


def test_guest_mfa_noop_uses_existing_lifecycle():
    from app.services import ca_policy_engine

    mock_state = MagicMock()
    mock_state.mode = "enforced"
    mock_state.rollout_phase = "full"
    mock_state.rollout_percentage = 0
    mock_state.target_group_id = None
    mock_state.policy_version = 1
    mock_state.status = "active"

    mock_tenant = MagicMock()
    mock_tenant.id = "tenant-guest-noop"
    mock_tenant.provider = "microsoft"

    async def fake_policy_matches(**_kwargs):
        return True

    async def fake_calculate_affected(**_kwargs):
        return 8

    with (
        patch.object(ca_policy_engine, "get_control_state", new=AsyncMock(return_value=mock_state)),
        patch.object(ca_policy_engine, "policy_matches_expected", new=fake_policy_matches),
        patch.object(ca_policy_engine, "list_break_glass_user_ids", return_value=["bg-1"]),
        patch.object(ca_policy_engine, "_validate_break_glass_accounts", new=AsyncMock()),
        patch.object(ca_policy_engine, "check_conditional_access_license", new=AsyncMock(return_value=True)),
        patch.object(ca_policy_engine, "calculate_affected_users", new=fake_calculate_affected),
        patch("app.services.ca_policy_engine.settings") as mock_settings,
    ):
        mock_settings.ENABLE_AUTO_REMEDIATION = False
        result = asyncio.run(
            ca_policy_engine.apply_control(
                db=MagicMock(),
                tenant=mock_tenant,
                control_id=CONTROL_GUEST_MFA,
                mode="enforced",
                rollout_phase="full",
            )
        )

    assert result["status"] == "no-op"
    assert result["verified"] is True
    assert result["control_id"] == CONTROL_GUEST_MFA


def test_build_policy_rejects_break_glass_exclusion_control():
    try:
        build_policy(
            CONTROL_BREAK_GLASS_EXCLUSION,
            mode="enforced",
            rollout_phase="full",
            break_glass_ids=["bg-1"],
        )
    except ControlEngineError as exc:
        assert "apply_break_glass_exclusion" in str(exc)
    else:
        raise AssertionError("Expected ControlEngineError for build_policy(CA_BREAK_GLASS_EXCLUSION)")


def test_build_exclude_users_patch_only_touches_exclude_users():
    patch_body = _build_exclude_users_patch(["bg-1", "bg-2", "bg-1"])
    # Top-level body shape: {"conditions": {"users": {"excludeUsers": [...]}}}
    assert set(patch_body.keys()) == {"conditions"}
    assert set(patch_body["conditions"].keys()) == {"users"}
    assert set(patch_body["conditions"]["users"].keys()) == {"excludeUsers"}
    # Deduplication preserves order
    assert patch_body["conditions"]["users"]["excludeUsers"] == ["bg-1", "bg-2"]


def test_break_glass_rollback_preserves_newer_exclusions_and_verifies():
    execution_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    execution = SimpleNamespace(
        id=execution_id,
        tenant_id="tenant-1",
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        status="success",
        snapshot_id=snapshot_id,
    )
    snapshot = SimpleNamespace(
        id=snapshot_id,
        tenant_id="tenant-1",
        control_id=CONTROL_BREAK_GLASS_EXCLUSION,
        policies=[
            {
                "policy_id": "policy-1",
                "policy_name": "Customer CA",
                "prior_exclude_users": ["legacy-exclusion"],
                "added_exclusions": ["bg-1"],
            }
        ],
    )
    graph_client = _FakePatchGraphClient(
        [
            {
                "id": "policy-1",
                "displayName": "Customer CA",
                "conditions": {
                    "users": {
                        "excludeUsers": [
                            "legacy-exclusion",
                            "bg-1",
                            "newer-exclusion",
                            "bg-2",
                        ]
                    }
                },
            }
        ]
    )
    fake_remediation_executor = SimpleNamespace(RemediationGraphClient=lambda **kwargs: graph_client)

    with (
        patch.dict(sys.modules, {"app.services.remediation_executor": fake_remediation_executor}),
        patch("app.services.ca_policy_engine.get_snapshot_by_id", new=AsyncMock(return_value=snapshot)),
        patch(
            "app.services.ca_policy_engine.create_or_update_control_state",
            new=AsyncMock(return_value=SimpleNamespace(mode="enforced", rollout_phase="full", status="active")),
        ),
        patch("app.services.ca_policy_engine._record_control_execution", return_value=SimpleNamespace(id=uuid.uuid4())),
    ):
        result = asyncio.run(
            rollback_break_glass_exclusion(
                db=_FakeDB(execution),
                tenant=SimpleNamespace(id="tenant-1"),
                execution_id=str(execution_id),
            )
        )

    assert result["status"] == "success"
    assert result["verified"] is True
    assert graph_client.patch_bodies[0]["patch"]["conditions"]["users"]["excludeUsers"] == [
        "legacy-exclusion",
        "newer-exclusion",
        "bg-2",
    ]


def test_apply_control_fails_closed_when_tenant_ca_lock_is_held():
    from app.services import ca_policy_engine
    from app.services.remediation.tenant_execution_lock import TenantExecutionLockError

    db = MagicMock()
    tenant = SimpleNamespace(id="tenant-locked")

    with patch(
        "app.services.ca_policy_engine.acquire_tenant_execution_lock",
        side_effect=TenantExecutionLockError("busy"),
    ):
        try:
            asyncio.run(
                ca_policy_engine.apply_control(
                    db=db,
                    tenant=tenant,
                    control_id=CONTROL_MFA_ADMINS,
                    mode="enforced",
                    rollout_phase="admins",
                )
            )
        except ControlEngineError as exc:
            assert "already running" in str(exc)
        else:
            raise AssertionError("Expected ControlEngineError when CA lock is held")


def test_rollback_control_rejects_failed_execution():
    # A PARTIAL execution (applied, verification failed) may be rolled back from its
    # snapshot (B2, live run 2026-11-13; see test_ca_rollback_after_failed_verify).
    # A FAILED one applied nothing, so there is nothing to undo.
    execution = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id="tenant-1",
        control_id=CONTROL_MFA_ADMINS,
        status="failed",
        snapshot_id=uuid.uuid4(),
    )
    tenant = SimpleNamespace(id="tenant-1")
    fake_remediation_executor = SimpleNamespace(RemediationGraphClient=lambda **kwargs: object())

    with patch.dict(sys.modules, {"app.services.remediation_executor": fake_remediation_executor}):
        try:
            asyncio.run(
                rollback_control(
                    db=_FakeDB(execution),
                    tenant=tenant,
                    execution_id=str(execution.id),
                )
            )
        except ControlEngineError as exc:
            assert "nothing was applied" in str(exc)
        else:
            raise AssertionError("Expected ControlEngineError for failed execution rollback")
