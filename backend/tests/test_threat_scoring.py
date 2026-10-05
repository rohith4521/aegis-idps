import pytest
from datetime import datetime, timedelta
from app.models.security_event import SecurityEvent
from app.intelligence.scoring import ThreatScoringEngine, ThreatAssessment


def test_empty_events_scoring():
    engine = ThreatScoringEngine()
    assessment = engine.evaluate_events([])
    assert assessment.score == 0
    assert assessment.severity == "LOW"
    assert len(assessment.factors) == 1


def test_whitelisted_source_scoring():
    engine = ThreatScoringEngine()
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        category="Port Scan",
        severity=1,
        signature="ET SCAN SYN Port Scan Detected"
    )
    assessment = engine.evaluate_events([event], known_whitelisted=True)
    assert assessment.score == 0
    assert assessment.severity == "LOW"
    assert assessment.confidence == 100
    assert "whitelisted" in assessment.factors[0]["reason"].lower()


def test_exploit_rce_critical_scoring():
    engine = ThreatScoringEngine()
    now = datetime.utcnow()
    # 5 rapid RCE exploit events
    events = [
        SecurityEvent(
            timestamp=now + timedelta(seconds=i * 5),
            source_ip="198.51.100.42",
            destination_ip="10.0.0.5",
            destination_port=443,
            category="Exploit",
            severity=1,
            signature="ET EXPLOIT Remote Command Execution Shell Spawn Attempt"
        )
        for i in range(6)
    ]
    assessment = engine.evaluate_events(events)
    
    # Exploit category (35) + High severity (25) + Critical sig match (30) + Repeated (15) + Burst (10)
    # Total would exceed 100, clamped to 100
    assert assessment.score == 100
    assert assessment.severity == "CRITICAL"
    assert assessment.confidence >= 85
    assert any("exploit" in f["reason"].lower() for f in assessment.factors)
    assert any("verified critical" in f["reason"].lower() for f in assessment.factors)


def test_severity_thresholds():
    engine = ThreatScoringEngine()
    assert engine.determine_severity(0) == "LOW"
    assert engine.determine_severity(29) == "LOW"
    assert engine.determine_severity(30) == "MEDIUM"
    assert engine.determine_severity(59) == "MEDIUM"
    assert engine.determine_severity(60) == "HIGH"
    assert engine.determine_severity(79) == "HIGH"
    assert engine.determine_severity(80) == "CRITICAL"
    assert engine.determine_severity(100) == "CRITICAL"


def test_score_clamping():
    engine = ThreatScoringEngine()
    now = datetime.utcnow()
    # 25 events to max out all categories
    events = [
        SecurityEvent(
            timestamp=now + timedelta(seconds=i),
            source_ip="203.0.113.88",
            destination_ip=f"10.0.0.{i % 3 + 1}",
            destination_port=80 + i,
            category="Exploit",
            severity=1,
            signature="ET EXPLOIT Remote Command Execution Shell Spawn Attempt"
        )
        for i in range(25)
    ]
    assessment = engine.evaluate_events(events)
    assert assessment.score == 100
    assert 0 <= assessment.score <= 100


def test_custom_config_override():
    custom_config = {
        "scoring_port_scan_points": 10,
        "scoring_malicious_sig_points": 5,
    }
    engine = ThreatScoringEngine(config=custom_config)
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        source_ip="198.51.100.10",
        destination_ip="10.0.0.5",
        destination_port=22,
        category="Port Scan",
        severity=3,
        signature="Generic Scan"
    )
    assessment = engine.evaluate_events([event])
    # Port scan (10) + Low severity (5) = 15
    assert assessment.score == 15
    assert assessment.severity == "LOW"
