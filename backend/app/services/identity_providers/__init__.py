from app.services.identity_providers.base import (
    IdentityProviderAdapter,
    UnsupportedIdentityProviderError,
)
from app.services.identity_providers.factory import get_identity_provider_adapter
from app.services.identity_providers.google import GoogleWorkspaceAdapter
from app.services.identity_providers.microsoft import MicrosoftIdentityProviderAdapter

__all__ = [
    "GoogleWorkspaceAdapter",
    "IdentityProviderAdapter",
    "MicrosoftIdentityProviderAdapter",
    "UnsupportedIdentityProviderError",
    "get_identity_provider_adapter",
]
