import pytest
from app.realtime.event_models import make_event


def test_make_event_sets_required_fields():
    evt = make_event(
        event_type="CampaignCreated",
        organization_id="org-123",
        payload={"campaign_id": "c-1", "status": "AWAITING_APPROVAL"},
    )
    assert evt.event_type == "CampaignCreated"
    assert evt.organization_id == "org-123"
    assert evt.event_version == "1"
    assert evt.payload["campaign_id"] == "c-1"
    assert evt.event_id is not None
    assert evt.occurred_at is not None


def test_event_is_frozen():
    evt = make_event("CampaignCreated", "org-1", {})
    with pytest.raises(Exception):
        evt.event_type = "Other"


def test_event_version_is_string_one():
    evt = make_event("TaskFailed", "org-1", {"task_id": "t-1"})
    assert evt.event_version == "1"


def test_make_event_unique_ids():
    e1 = make_event("CampaignCreated", "org-1", {})
    e2 = make_event("CampaignCreated", "org-1", {})
    assert e1.event_id != e2.event_id


def test_make_event_json_serialisable():
    import json

    evt = make_event("DriftNotificationCreated", "org-1", {"tenant_id": "t-1", "tenant_name": "Acme"})
    data = json.dumps(evt.model_dump())
    parsed = json.loads(data)
    assert parsed["event_type"] == "DriftNotificationCreated"
