from tests.integration.utils import seed_decision, seed_tenant, seed_tenant_with_user


def test_approve_decision(client, db_session):
    headers = seed_tenant_with_user(db_session)
    record = seed_decision(db_session, approved=False)

    resp = client.post(f"/api/v1/remediation/decisions/{record.id}/approve", headers=headers, json={})
    assert resp.status_code == 200
    assert resp.json()["status"] == "APPROVED"


def test_cannot_approve_another_tenants_decision(client, db_session):
    headers = seed_tenant_with_user(db_session)
    other = seed_tenant(db_session, None, "tenant-other")
    foreign = seed_decision(db_session, approved=False, tenant_id=other.id)

    resp = client.post(f"/api/v1/remediation/decisions/{foreign.id}/approve", headers=headers, json={})
    assert resp.status_code in (403, 404)

    db_session.refresh(foreign)
    assert foreign.approved is False
