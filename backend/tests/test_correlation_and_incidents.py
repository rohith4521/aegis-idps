import pytest
from datetime import datetime, timedelta, timezone
from fastapi import status
from app.models.security_event import SecurityEvent
from app.models.incident import Incident
from app.models.threat_score import ThreatScore
from app.models.audit_log import AuditLog
from app.services.event_service import EventService
from app.services.correlation_service import CorrelationService


def test_correlation_groups_matching_events(db):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.77"

    # Create 3 sequential brute force events within 30 seconds
    for i in range(3):
        eve_dict = {
            "timestamp": (now + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "event_type": "alert",
            "src_ip": ip,
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Potential SSH Brute Force Attack",
                "category": "attempted-admin",
                "severity": 1,
            },
            "is_simulation": False,
        }
        event, err, is_dup = EventService.ingest_single_event(db, eve_dict)
        assert err is None
        assert is_dup is False
        assert event is not None

    # Should have exactly 1 incident with event_count == 3
    incidents = db.query(Incident).filter(Incident.source_ip == ip).all()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.event_count == 3
    assert incident.category == "Brute Force"
    assert incident.threat_score >= 50
    assert incident.threat_score_detail is not None
    assert len(incident.threat_score_detail.factors) >= 2


def test_correlation_time_window_separation(db):
    now = datetime.now(timezone.utc)
    ip = "203.0.113.55"

    # First event
    ev1 = {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": ip,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "ET SCAN SYN Port Scan Detected",
            "category": "attempted-recon",
            "severity": 2,
        },
    }
    EventService.ingest_single_event(db, ev1)

    # Second event 10 minutes (600s) later, well outside the 300s window
    ev2 = {
        "timestamp": (now + timedelta(seconds=600)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": ip,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "ET SCAN SYN Port Scan Detected",
            "category": "attempted-recon",
            "severity": 2,
        },
    }
    EventService.ingest_single_event(db, ev2)

    # Should result in 2 distinct incidents
    incidents = db.query(Incident).filter(Incident.source_ip == ip).all()
    assert len(incidents) == 2


def test_unrelated_categories_separate(db):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.99"

    # Event 1: Port Scan
    ev1 = {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": ip,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "alert": {
            "signature": "ET SCAN SYN Port Scan Detected",
            "category": "attempted-recon",
            "severity": 2,
        },
    }
    EventService.ingest_single_event(db, ev1)

    # Event 2: Web SQL Injection
    ev2 = {
        "timestamp": (now + timedelta(seconds=15)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": ip,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "alert": {
            "signature": "ET WEB_SPECIFIC_APPS SQL Injection Attempt in URI",
            "category": "web-application-attack",
            "severity": 1,
        },
    }
    EventService.ingest_single_event(db, ev2)

    incidents = db.query(Incident).filter(Incident.source_ip == ip).all()
    assert len(incidents) == 2
    categories = {inc.category for inc in incidents}
    assert "Port Scan" in categories
    assert "Web Application Attack" in categories


def test_simulation_flag_propagated_to_incident(db):
    now = datetime.now(timezone.utc)
    ev = {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": "198.51.100.123",
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "alert": {
            "signature": "[SIMULATION] ET SCAN Potential SSH Brute Force Attack",
            "category": "attempted-admin",
            "severity": 1,
        },
        "is_simulation": True,
    }
    event, _, _ = EventService.ingest_single_event(db, ev)
    assert event.is_simulation is True

    incident = db.query(Incident).filter(Incident.id == event.incident_id).first()
    assert incident is not None
    assert incident.is_simulation is True
    assert "[SIMULATION]" in incident.title


def test_incidents_api_endpoints(client):
    # 1. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Ingest batch of events to ensure incidents exist
    client.post(
        "/api/events/demo/generate",
        json={"count": 5, "scenario": "sqli"},
        headers=headers
    )

    # 3. GET /api/incidents
    incidents_resp = client.get("/api/incidents", headers=headers)
    assert incidents_resp.status_code == status.HTTP_200_OK
    incidents = incidents_resp.json()
    assert len(incidents) >= 1
    first_incident = incidents[0]
    incident_id = first_incident["id"]

    # 4. GET /api/incidents/{id}
    detail_resp = client.get(f"/api/incidents/{incident_id}", headers=headers)
    assert detail_resp.status_code == status.HTTP_200_OK
    detail = detail_resp.json()
    assert detail["id"] == incident_id
    assert "events" in detail
    assert "threat_score_detail" in detail
    assert len(detail["threat_score_detail"]["factors"]) >= 1

    # 5. PATCH /api/incidents/{id}/status
    patch_resp = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={"status": "INVESTIGATING", "notes": "SOC analyst triaging incident."},
        headers=headers
    )
    assert patch_resp.status_code == status.HTTP_200_OK
    assert patch_resp.json()["status"] == "INVESTIGATING"

    # 6. Verify Threats API
    threats_resp = client.get("/api/threats", headers=headers)
    assert threats_resp.status_code == status.HTTP_200_OK
    threats = threats_resp.json()
    assert len(threats) >= 1

    threat_id = threats[0]["id"]
    single_threat_resp = client.get(f"/api/threats/{threat_id}", headers=headers)
    assert single_threat_resp.status_code == status.HTTP_200_OK
    assert single_threat_resp.json()["id"] == threat_id


def test_mixed_origin_incident_correlation(db):
    now = datetime.now(timezone.utc)
    # 1. Ingest real event
    real_ev = {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": "198.51.100.188",
        "dest_ip": "10.0.0.8",
        "dest_port": 80,
        "alert": {
            "signature": "ET EXPLOIT Apache Struts RCE CVE-2017-5638",
            "category": "attempted-admin",
            "severity": 1,
        },
        "is_simulation": False,
    }
    ev1, err1, _ = EventService.ingest_single_event(db, real_ev)
    assert err1 is None
    assert ev1.is_simulation is False
    inc1 = db.query(Incident).filter(Incident.id == ev1.incident_id).first()
    assert inc1 is not None
    assert inc1.is_simulation is False
    assert inc1.origin == "REAL"
    assert "[SIMULATION]" not in inc1.title

    # 2. Ingest simulated event for same src_ip and category within correlation window
    sim_ev = {
        "timestamp": (now + timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "event_type": "alert",
        "src_ip": "198.51.100.188",
        "dest_ip": "10.0.0.8",
        "dest_port": 80,
        "alert": {
            "signature": "[SIMULATION] ET EXPLOIT Remote Command Execution Log4j CVE-2021-44228",
            "category": "attempted-admin",
            "severity": 1,
        },
        "is_simulation": True,
    }
    ev2, err2, _ = EventService.ingest_single_event(db, sim_ev)
    assert err2 is None
    assert ev2.incident_id == inc1.id
    inc2 = db.query(Incident).filter(Incident.id == inc1.id).first()
    assert inc2.event_count == 2
    # Verify mixed origin properties:
    assert inc2.origin == "MIXED"
    assert "[MIXED: REAL+SIMULATION]" in inc2.title
    assert inc2.is_simulation is True  # Enforces prevention engine safety
