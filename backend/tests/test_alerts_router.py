import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import sqlite

from app.api.routes.alerts import resolve_alert
from app.db.models.alert import Alert


class _FakeTenant:
    def __init__(self, tenant_id: str):
        self.id = tenant_id


class _FakeResult:
    def __init__(self, item):
        self._item = item

    def scalars(self):
        return self

    def first(self):
        return self._item


class _FakeAsyncSession:
    def __init__(self, alert_for_match=None):
        self._alert_for_match = alert_for_match
        self.captured_statement = None
        self.committed = False
        self.refreshed = None

    async def execute(self, statement):
        self.captured_statement = statement
        return _FakeResult(self._alert_for_match)

    async def commit(self):
        self.committed = True

    async def refresh(self, obj):
        self.refreshed = obj


def _compiled_sql(statement) -> str:
    return str(statement.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))


@pytest.mark.asyncio
async def test_resolve_alert_query_filters_by_both_id_and_tenant():
    db = _FakeAsyncSession(alert_for_match=None)
    current_tenant = _FakeTenant("tenant-A")

    with pytest.raises(HTTPException):
        await resolve_alert(alert_id=42, db=db, current_tenant=current_tenant)

    sql = _compiled_sql(db.captured_statement)
    assert "alerts.id = 42" in sql
    assert "alerts.tenant_id = 'tenant-A'" in sql


@pytest.mark.asyncio
async def test_resolve_alert_404_when_alert_belongs_to_another_tenant():
    # execute() returning None simulates the WHERE clause finding no row —
    # i.e. the alert exists but for a different tenant, so no match.
    db = _FakeAsyncSession(alert_for_match=None)
    current_tenant = _FakeTenant("tenant-A")

    with pytest.raises(HTTPException) as exc_info:
        await resolve_alert(alert_id=1, db=db, current_tenant=current_tenant)

    assert exc_info.value.status_code == 404
    assert db.committed is False


@pytest.mark.asyncio
async def test_resolve_alert_marks_resolved_at_and_commits_when_owned():
    alert = Alert(id=1, tenant_id="tenant-A", alert_type="control_regression", severity="critical")
    assert alert.resolved_at is None
    db = _FakeAsyncSession(alert_for_match=alert)
    current_tenant = _FakeTenant("tenant-A")

    result = await resolve_alert(alert_id=1, db=db, current_tenant=current_tenant)

    assert result is alert
    assert alert.resolved_at is not None
    assert db.committed is True
    assert db.refreshed is alert
