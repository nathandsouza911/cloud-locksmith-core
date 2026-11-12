import inspect

import pytest

from app.api.routes.notifications import register_target


class _FakeTenant:
    def __init__(self, tenant_id: str):
        self.id = tenant_id


class _FakeAsyncSession:
    def __init__(self):
        self.added = []
        self.committed = False

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True


def test_register_target_has_no_client_supplied_tenant_id_parameter():
    # Locks in the fix: a client-controlled tenant_id must never be an
    # accepted parameter on this endpoint again. If someone re-adds it,
    # this test fails immediately rather than relying on someone noticing
    # the tenant-isolation regression in review.
    params = inspect.signature(register_target).parameters
    assert "tenant_id" not in params


@pytest.mark.asyncio
async def test_register_target_uses_current_tenant_id_not_client_input():
    db = _FakeAsyncSession()
    current_tenant = _FakeTenant("tenant-A")

    result = await register_target(
        channel="email",
        destination="ops@example.com",
        db=db,
        current_tenant=current_tenant,
    )

    assert result == {"status": "registered"}
    assert len(db.added) == 1
    target = db.added[0]
    assert target.tenant_id == "tenant-A"
    assert target.channel == "email"
    assert target.destination == "ops@example.com"
    assert db.committed is True
