from app.services.detection.identity_break_glass_account_detector import (
    CONTROL_ID,
    evaluate_break_glass_accounts,
)


def _user(
    user_id: str,
    *,
    display_name: str,
    on_prem_sync: bool | None = None,
    immutable_id=None,
    extension_values: dict | None = None,
) -> dict:
    return {
        "id": user_id,
        "displayName": display_name,
        "userPrincipalName": f"{user_id}@example.com",
        "accountEnabled": True,
        "onPremisesSyncEnabled": on_prem_sync,
        "onPremisesImmutableId": immutable_id,
        "onPremisesExtensionAttributes": extension_values or {},
    }


def test_break_glass_detector_fails_high_when_no_candidates_exist():
    result = evaluate_break_glass_accounts(
        users=[_user("user-1", display_name="Standard Admin")],
        global_admin_user_ids={"user-1"},
        conditional_access_policies=[],
    )

    assert result["control_id"] == CONTROL_ID
    assert result["passed"] is False
    assert result["severity"] == "HIGH"
    assert result["evidence"]["number_of_accounts_found"] == 0
    assert result["evidence"]["properly_configured_accounts"] == []
    assert result["evidence"]["misconfigured_accounts"] == []


def test_break_glass_detector_fails_medium_when_exactly_one_valid_account_exists():
    result = evaluate_break_glass_accounts(
        users=[_user("bg-1", display_name="Break-Glass Admin")],
        global_admin_user_ids={"bg-1"},
        conditional_access_policies=[],
    )

    assert result["passed"] is False
    assert result["severity"] == "MEDIUM"
    assert result["evidence"]["number_of_accounts_found"] == 1
    assert len(result["evidence"]["properly_configured_accounts"]) == 1
    assert result["evidence"]["misconfigured_accounts"] == []


def test_break_glass_detector_fails_high_when_candidates_are_misconfigured():
    result = evaluate_break_glass_accounts(
        users=[
            _user("bg-1", display_name="Break-Glass 01"),
            _user(
                "bg-2",
                display_name="Emergency Access 02",
                on_prem_sync=True,
            ),
        ],
        global_admin_user_ids={"bg-1"},
        conditional_access_policies=[
            {
                "id": "mfa-policy",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["bg-1"],
                        "excludeUsers": [],
                    }
                },
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ],
    )

    assert result["passed"] is False
    assert result["severity"] == "HIGH"
    assert result["evidence"]["number_of_accounts_found"] == 2
    assert result["evidence"]["properly_configured_accounts"] == []
    assert len(result["evidence"]["misconfigured_accounts"]) == 2
    by_user = {
        account["user_id"]: set(account["misconfiguration_reasons"])
        for account in result["evidence"]["misconfigured_accounts"]
    }
    assert "covered_by_mfa_conditional_access" in by_user["bg-1"]
    assert {
        "missing_global_administrator_role",
        "account_is_synced_from_on_prem",
    } <= by_user["bg-2"]


def test_break_glass_detector_passes_with_two_valid_accounts():
    result = evaluate_break_glass_accounts(
        users=[
            _user(
                "bg-1",
                display_name="Admin One",
                extension_values={"extensionAttribute1": "break-glass"},
            ),
            _user("bg-2", display_name="Emergency Account Two"),
        ],
        global_admin_user_ids={"bg-1", "bg-2"},
        conditional_access_policies=[
            {
                "id": "report-only-policy",
                "state": "reportOnly",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": [],
                    }
                },
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ],
    )

    assert result["passed"] is True
    assert result["severity"] == "LOW"
    assert result["evidence"]["number_of_accounts_found"] == 2
    assert len(result["evidence"]["properly_configured_accounts"]) == 2
    assert result["evidence"]["misconfigured_accounts"] == []
