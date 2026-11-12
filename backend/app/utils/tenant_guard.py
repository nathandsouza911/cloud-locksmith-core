from __future__ import annotations

from sqlalchemy.orm import Query


def _resolve_model(query: Query, model=None):
    if model is not None:
        return model
    for description in getattr(query, "column_descriptions", []):
        entity = description.get("entity")
        if entity is not None and hasattr(entity, "tenant_id"):
            return entity
    return None


def enforce_tenant_scope(query: Query, tenant_id: str, model=None) -> Query:
    resolved_model = _resolve_model(query, model=model)
    if resolved_model is None or not hasattr(resolved_model, "tenant_id"):
        raise RuntimeError("Tenant scoped query requires a model with tenant_id")
    return query.filter(resolved_model.tenant_id == tenant_id)
