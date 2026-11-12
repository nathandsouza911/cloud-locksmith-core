from __future__ import annotations

from app.services.identity_providers.base import (
    IdentityProviderAdapter,
    UnsupportedIdentityProviderError,
)
from app.services.identity_providers.google import GoogleWorkspaceAdapter
from app.services.identity_providers.microsoft import MicrosoftIdentityProviderAdapter


def get_identity_provider_adapter(*, db, tenant) -> IdentityProviderAdapter:
    provider = str(getattr(tenant, "provider", None) or "microsoft").strip().lower()

    if provider == "microsoft":
        return MicrosoftIdentityProviderAdapter(db=db, tenant=tenant)
    if provider == "google":
        return GoogleWorkspaceAdapter(db=db, tenant=tenant)

    raise UnsupportedIdentityProviderError(f"Unsupported identity provider: {provider or 'unknown'}")
