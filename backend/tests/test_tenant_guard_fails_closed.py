"""Gate 0 (M1): enforce_tenant_scope must fail closed in every environment.

Regression: when the query's model couldn't be resolved (or lacked
tenant_id), enforce_tenant_scope only raised in `development`. In every
other environment (production, staging) it silently returned the original,
unscoped query — the opposite of what a defense-in-depth tenant filter is
for. No current caller hits this branch (both pass an explicit `model=`
that carries tenant_id), but the helper itself must never have a silent
unscoped fallback, in any environment.
"""

import pytest

from app.utils.tenant_guard import enforce_tenant_scope


class _UnrelatedModel:
    """A model with no tenant_id attribute."""


class _FakeQuery:
    """Minimal stand-in for a SQLAlchemy Query the resolver can't introspect."""

    column_descriptions = []


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_raises_when_model_unresolvable_outside_development(monkeypatch, environment):
    from app.config import settings

    monkeypatch.setattr(settings, "ENVIRONMENT", environment)

    with pytest.raises(Exception):
        enforce_tenant_scope(_FakeQuery(), tenant_id="tenant-a")


def test_raises_when_model_unresolvable_in_development(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    with pytest.raises(Exception):
        enforce_tenant_scope(_FakeQuery(), tenant_id="tenant-a")


@pytest.mark.parametrize("environment", ["production", "staging", "development"])
def test_raises_when_explicit_model_lacks_tenant_id(monkeypatch, environment):
    from app.config import settings

    monkeypatch.setattr(settings, "ENVIRONMENT", environment)

    with pytest.raises(Exception):
        enforce_tenant_scope(_FakeQuery(), tenant_id="tenant-a", model=_UnrelatedModel)
