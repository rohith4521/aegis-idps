import pytest
from fastapi import status
from app.services.event_service import EventService
from app.detection.generator import DemoEventGenerator


def test_ingest_single_and_duplicate(db):
    raw = DemoEventGenerator.generate_event(scenario_key="brute_force")
    
    # 1. First ingestion
    event1, err1, is_dup1 = EventService.ingest_single_event(db, raw)
    assert err1 is None
    assert is_dup1 is False
    assert event1 is not None
    assert event1.id is not None
    assert event1.is_simulation is True

    # 2. Second ingestion of exact same event should detect duplicate
    event2, err2, is_dup2 = EventService.ingest_single_event(db, raw)
    assert is_dup2 is True
    assert event2 is None


def test_ingest_batch_api(client):
    # 1. Login to get token
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Generate batch of raw events
    events = DemoEventGenerator.generate_batch(count=5, scenario="port_scan")
    
    # 3. Post to /api/events/ingest
    resp = client.post(
        "/api/events/ingest",
        json={"events": events},
        headers=headers
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["ingested_count"] == 5
    assert len(data["created_event_ids"]) == 5

    # 4. Query /api/events
    list_resp = client.get("/api/events?limit=10", headers=headers)
    assert list_resp.status_code == status.HTTP_200_OK
    items = list_resp.json()
    assert len(items) >= 5


def test_generate_demo_events_api(client):
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@123456"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/api/events/demo/generate",
        json={"count": 8, "scenario": "mixed"},
        headers=headers
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["ingested_count"] == 8
    assert data["error_count"] == 0
