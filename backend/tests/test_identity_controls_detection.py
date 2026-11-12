"""
Tests for IDENTITY_USER_CONSENT_POLICY detection, verification, and Graph error visibility.

Tests 5–8 of the IDENTITY_USER_CONSENT_POLICY TDD cycle.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.detection.identity_risky_defaults_detector import (
    evaluate_identity_default_controls,
)
from app.services.graph_client import GraphAPIError, describe_graph_api_error
from app.services.remediation.verification.tenant_identity_verifier import (
    verify_user_consent_restricted,
)


# ---------------------------------------------------------------------------
# Tests 5–7: Detector / Verifier
# ---------------------------------------------------------------------------


# Test 5: Detector passes when permissionGrantPoliciesAssigned is empty.
# ScubaGear test_UserConsentNotAllowedEmptyDefaultUserArray_Correct confirms [] is PASS.
def test_user_consent_detector_passes_with_empty_policies():
    snapshot = {
        "authorization_policy": {
            "allowInvitesFrom": "adminsAndGuestInviters",
            "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []},
        }
    }

    results = evaluate_identity_default_controls(snapshot)
    control = next(r for r in results if r["control_id"] == "IDENTITY_USER_CONSENT_POLICY")

    assert control["passed"] is True


# Test 6: Detector passes when only Teams RSC entries are present (no ManagePermissionGrantsForSelf.*).
# Real Microsoft tenants often have these read-only Teams entries alongside an empty self-consent list.
def test_user_consent_detector_passes_with_only_teams_rsc_entries():
    snapshot = {
        "authorization_policy": {
            "allowInvitesFrom": "adminsAndGuestInviters",
            "defaultUserRolePermissions": {
                "permissionGrantPoliciesAssigned": [
                    "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
                    "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                ]
            },
        }
    }

    results = evaluate_identity_default_controls(snapshot)
    control = next(r for r in results if r["control_id"] == "IDENTITY_USER_CONSENT_POLICY")

    assert control["passed"] is True


# Test 7: Verifier returns success=True when no ManagePermissionGrantsForSelf.* entries exist,
# even when Teams RSC entries are present. The current verifier requires OWNED_RESOURCE_POLICY
# (a literal ".*" wildcard) to be present, which is never a real Microsoft policy ID.
@pytest.mark.asyncio
async def test_verify_user_consent_restricted_passes_with_only_teams_rsc():
    policy = {
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": [
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
            ]
        }
    }
    mock_adapter = AsyncMock()
    mock_adapter.get_authorization_policy.return_value = policy

    with patch(
        "app.services.remediation.verification.tenant_identity_verifier.get_identity_provider_adapter",
        return_value=mock_adapter,
    ):
        result = await verify_user_consent_restricted(db=None, tenant=None, compliance_result=None)

    assert result["success"] is True


# ---------------------------------------------------------------------------
# Test 8: Graph error visibility
# ---------------------------------------------------------------------------


# Test 8: When Microsoft Graph returns HTTP 400, the response body contains a meaningful
# error code and message. describe_graph_api_error must surface these details rather than
# the opaque "Configuration error" string.
def test_describe_graph_api_error_surfaces_graph_message_for_400():
    exc = GraphAPIError(
        method="PATCH",
        path="/policies/authorizationPolicy",
        status_code=400,
        response_body=(
            '{"error":{"code":"Request_BadRequest",' '"message":"The value provided contains invalid policy IDs."}}'
        ),
        category="validation_issue",
    )

    description = describe_graph_api_error(exc)

    # Must contain actionable Graph details — not just the opaque label.
    assert "Request_BadRequest" in description or "invalid policy IDs" in description.lower()
