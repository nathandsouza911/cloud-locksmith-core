import asyncio

from app.api.routes import attack_paths


class _Tenant:
    id = "tenant-authorized"


class _Db:
    async def scalar(self, *_args, **_kwargs):
        raise AssertionError("attack path route must not resolve tenant_id from client input")


def test_attack_paths_uses_authenticated_tenant_context(monkeypatch):
    captured = {}

    async def fake_evaluate_attack_paths(db, tenant_id):
        captured["db"] = db
        captured["tenant_id"] = tenant_id
        return {
            "total_paths": 0,
            "affected_controls": set(),
            "critical_controls": set(),
        }

    monkeypatch.setattr(attack_paths, "evaluate_attack_paths", fake_evaluate_attack_paths)

    result = asyncio.run(
        attack_paths.get_attack_paths(
            db=_Db(),
            current_tenant=_Tenant(),
        )
    )

    assert captured["tenant_id"] == "tenant-authorized"
    assert result["affected_controls"] == []
    assert result["critical_controls"] == []
