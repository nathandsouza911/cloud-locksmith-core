from app.services.compliance_registry import canonicalize_control_id, get_control_metadata


def test_legacy_dormant_id_canonicalizes_to_unused():
    assert canonicalize_control_id("IDENTITY_DORMANT_ACCOUNT") == "IDENTITY_UNUSED_ACCOUNT"


def test_canonicalize_passes_through_unknown_ids():
    assert canonicalize_control_id("IDENTITY_USER_NO_MFA") == "IDENTITY_USER_NO_MFA"


def test_get_metadata_resolves_legacy_id_to_new_control():
    meta = get_control_metadata("IDENTITY_DORMANT_ACCOUNT")
    assert meta["control_id"] == "IDENTITY_UNUSED_ACCOUNT"
    assert meta["title"]
