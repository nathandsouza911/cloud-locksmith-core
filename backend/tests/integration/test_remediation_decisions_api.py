from tests.integration.utils import seed_decision, seed_tenant, seed_tenant_with_user


def test_list_decisions(client, db_session):
    headers = seed_tenant_with_user(db_session)
    seed_decision(db_session)
    seed_decision(db_session, decision="AUTO_REMEDIATE", approved=True)

    resp = client.get("/api/v1/remediation/decisions", headers=headers)
    assert resp.status_code == 200

    data = resp.json()
    assert len(data) == 2
    assert all(row["tenant_id"] == "tenant-123" for row in data)


def test_list_decisions_excludes_other_tenants(client, db_session):
    headers = seed_tenant_with_user(db_session)
    other = seed_tenant(db_session, None, "tenant-other")
    seed_decision(db_session)
    seed_decision(db_session, tenant_id=other.id)

    resp = client.get("/api/v1/remediation/decisions", headers=headers)
    assert resp.status_code == 200
    assert [row["tenant_id"] for row in resp.json()] == ["tenant-123"]
