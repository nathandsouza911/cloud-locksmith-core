from app.services.compliance_registry import get_control_metadata


def test_break_glass_control_metadata_is_registered():
    metadata = get_control_metadata("IDENTITY_BREAK_GLASS_ACCOUNT")

    assert metadata["control_id"] == "IDENTITY_BREAK_GLASS_ACCOUNT"
    assert metadata["category"] == "Identity & Access"
    assert metadata["severity"] == "HIGH"
    assert metadata["weight"] == 15
    assert (
        metadata["description"]
        == "Ensure at least two emergency access (break-glass) accounts exist and are excluded from Conditional Access policies."
    )
    assert metadata["detector"] == (
        "app.services.detection.identity_break_glass_account_detector.detect_break_glass_accounts"
    )
