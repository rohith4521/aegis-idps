import pytest
from app.detection.parser import SuricataEveParser


def test_parse_valid_suricata_alert():
    eve_dict = {
        "timestamp": "2026-10-04T16:45:00.123456+0000",
        "flow_id": 987654321,
        "event_type": "alert",
        "src_ip": "198.51.100.42",
        "src_port": 54321,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": "ET SCAN Potential SSH Brute Force Attack",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
    }

    parsed, error = SuricataEveParser.parse_event_dict(eve_dict)
    assert error is None
    assert parsed is not None
    assert parsed.source_ip == "198.51.100.42"
    assert parsed.destination_ip == "10.0.0.5"
    assert parsed.source_port == 54321
    assert parsed.destination_port == 22
    assert parsed.protocol == "TCP"
    assert parsed.event_type == "alert"
    assert parsed.signature_id == 2000001
    assert parsed.category == "Brute Force"
    assert parsed.severity == 1
    assert parsed.is_simulation is False


def test_parse_simulation_event():
    eve_dict = {
        "timestamp": "2026-10-04T16:50:00.000000+0000",
        "event_type": "alert",
        "src_ip": "203.0.113.88",
        "dest_ip": "10.0.0.12",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "[SIMULATION] ET WEB_SPECIFIC_APPS SQL Injection Attempt in URI",
            "signature_id": 2000002,
            "category": "Web Application Attack",
            "severity": 1,
        },
        "is_simulation": True,
    }

    parsed, error = SuricataEveParser.parse_event_dict(eve_dict)
    assert error is None
    assert parsed.is_simulation is True
    assert parsed.category == "Web Application Attack"


def test_parse_malformed_json_line():
    line = '{"timestamp": "2026-10-04", "src_ip": "192.168.1.1", unclosed json'
    parsed, error = SuricataEveParser.parse_eve_json_line(line)
    assert parsed is None
    assert "Malformed JSON" in error


def test_parse_missing_required_fields():
    # Missing source IP
    data = {
        "timestamp": "2026-10-04T12:00:00Z",
        "dest_ip": "10.0.0.5",
    }
    parsed, error = SuricataEveParser.parse_event_dict(data)
    assert parsed is None
    assert "source IP" in error

    # Invalid destination IP
    data2 = {
        "timestamp": "2026-10-04T12:00:00Z",
        "src_ip": "10.0.0.1",
        "dest_ip": "invalid-not-an-ip",
    }
    parsed2, error2 = SuricataEveParser.parse_event_dict(data2)
    assert parsed2 is None
    assert "destination IP" in error2


def test_parse_http_telemetry():
    eve_dict = {
        "timestamp": "2026-10-04T12:00:00Z",
        "event_type": "http",
        "src_ip": "10.0.0.20",
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "http": {
            "hostname": "internal.service",
            "url": "/api/users",
            "http_method": "GET"
        }
    }
    parsed, error = SuricataEveParser.parse_event_dict(eve_dict)
    assert error is None
    assert parsed.event_type == "http"
    assert parsed.category == "HTTP Traffic"
    assert parsed.severity == 4
