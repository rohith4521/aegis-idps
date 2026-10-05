import pytest
from app.detection.generator import DemoEventGenerator
from app.detection.parser import SuricataEveParser


def test_demo_generator_simulation_markers():
    for scenario in ["brute_force", "sqli", "rce", "port_scan", "smb_exploit", "benign"]:
        event = DemoEventGenerator.generate_event(scenario_key=scenario)
        assert event["is_simulation"] is True
        assert "[SIMULATION]" in event["alert"]["signature"]
        assert event["alert"]["metadata"]["simulation"] is True
        
        # Test that Suricata parser successfully parses every generated scenario
        parsed, error = SuricataEveParser.parse_event_dict(event)
        assert error is None
        assert parsed is not None
        assert parsed.is_simulation is True


def test_demo_batch_generation():
    batch = DemoEventGenerator.generate_batch(count=15, scenario="mixed")
    assert len(batch) == 15
    for ev in batch:
        assert ev["is_simulation"] is True
        assert ev["event_type"] == "alert"
