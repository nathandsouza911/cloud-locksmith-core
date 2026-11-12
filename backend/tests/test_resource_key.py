"""ResourceKey — the canonical identity of a reviewable resource.

The key property is that it is *identity-equivalent* to the (control_id,
resource_id) tuple the platform already uses. If that ever stops being true,
existing review decisions silently change meaning.
"""

from types import SimpleNamespace

from app.services.workflows._shared.resource_key import ResourceKey


def test_key_is_hashable_and_usable_as_a_dict_key():
    key = ResourceKey("IDENTITY_USER_NO_MFA", "user-1")
    assert {key: "value"}[ResourceKey("IDENTITY_USER_NO_MFA", "user-1")] == "value"


def test_equal_keys_have_equal_hashes():
    a = ResourceKey("C", "r")
    b = ResourceKey("C", "r")
    assert a == b
    assert hash(a) == hash(b)


def test_control_and_resource_are_not_interchangeable():
    """Positional transposition is the bug this type exists to prevent."""
    assert ResourceKey("a", "b") != ResourceKey("b", "a")


def test_as_tuple_matches_the_platforms_existing_tuple_ordering():
    """get_active_decisions keys on (control_id, resource_id). Must match."""
    key = ResourceKey("IDENTITY_UNUSED_ACCOUNT", "user-9")
    assert key.as_tuple() == ("IDENTITY_UNUSED_ACCOUNT", "user-9")


def test_from_finding_reads_control_and_resource_off_a_compliance_result():
    finding = SimpleNamespace(control_id="IDENTITY_USER_NO_MFA", resource_id="user-3", tenant_id="t1")
    assert ResourceKey.from_finding(finding) == ResourceKey("IDENTITY_USER_NO_MFA", "user-3")


def test_from_finding_normalises_a_missing_resource_id_to_empty_string():
    """Review Memory defaults resource_id to '' — the key must agree, or a
    tenant-level finding would key differently from its stored decision."""
    finding = SimpleNamespace(control_id="CA_MFA_ADMINS", resource_id=None)
    assert ResourceKey.from_finding(finding).resource_id == ""


def test_string_form_is_readable_for_logs():
    assert str(ResourceKey("CTRL", "res")) == "CTRL/res"
