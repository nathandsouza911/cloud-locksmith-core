from tests.integration.utils import seed_decision, seed_tenant_with_user


def test_stats_basic(client, db_session):
    headers = seed_tenant_with_user(db_session)
    seed_decision(db_session, decision="AUTO_REMEDIATE", approved=True)
    seed_decision(db_session, decision="BLOCK")

    resp = client.get("/api/v1/remediation/decisions/stats", headers=headers)
    assert resp.status_code == 200

    stats = resp.json()
    assert stats["total"] == 2
    assert stats["blocked"] == 1


def test_stats_window_7d(client, db_session):
    headers = seed_tenant_with_user(db_session)
    seed_decision(db_session)

    resp = client.get("/api/v1/remediation/decisions/stats/window?window=7d", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
