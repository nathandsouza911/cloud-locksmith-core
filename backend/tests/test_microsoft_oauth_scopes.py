from app.services.microsoft_oauth_scopes import DELEGATED_SCOPES


def test_delegated_scopes_include_remediation_write_permissions():
    assert "Policy.ReadWrite.Authorization" in DELEGATED_SCOPES
    assert "Policy.ReadWrite.ConditionalAccess" in DELEGATED_SCOPES
    assert "RoleManagement.ReadWrite.Directory" in DELEGATED_SCOPES
    assert "User.ReadWrite.All" in DELEGATED_SCOPES


def test_delegated_scopes_do_not_request_broad_directory_or_auth_method_writes():
    """Least privilege: these broad scopes were dropped from the consent request."""
    assert "Directory.ReadWrite.All" not in DELEGATED_SCOPES
    assert "Policy.ReadWrite.AuthenticationMethod" not in DELEGATED_SCOPES
