import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any


class DemoEventGenerator:
    """
    Safe deterministic generator for simulated network events.
    All events are strictly labeled as [SIMULATION] / DEMO.
    No live network traffic is generated.
    """

    SIMULATED_ATTACKERS = [
        "198.51.100.42",   # Documentation/Test Net RFC 5737
        "203.0.113.88",    # Documentation/Test Net RFC 5737
        "198.51.100.105",
        "203.0.113.199",
    ]

    INTERNAL_TARGETS = [
        "10.0.0.5",
        "10.0.0.12",
        "192.168.1.100",
    ]

    SCENARIOS = {
        "brute_force": {
            "signature": "[SIMULATION] ET SCAN Potential SSH Brute Force Attack",
            "sid": 2000001,
            "category": "attempted-admin",
            "dest_port": 22,
            "proto": "TCP",
            "severity": 1,
        },
        "sqli": {
            "signature": "[SIMULATION] ET WEB_SPECIFIC_APPS SQL Injection Attempt in URI",
            "sid": 2000002,
            "category": "web-application-attack",
            "dest_port": 80,
            "proto": "TCP",
            "severity": 1,
        },
        "rce": {
            "signature": "[SIMULATION] ET EXPLOIT Remote Command Execution Shell Spawn Attempt",
            "sid": 2000003,
            "category": "attempted-admin",
            "dest_port": 443,
            "proto": "TCP",
            "severity": 1,
        },
        "port_scan": {
            "signature": "[SIMULATION] ET SCAN SYN Port Scan Detected",
            "sid": 2000005,
            "category": "attempted-recon",
            "dest_port": None,  # randomized in port scan generator
            "proto": "TCP",
            "severity": 2,
        },
        "smb_exploit": {
            "signature": "[SIMULATION] ET EXPLOIT SMB Ghost Remote Code Execution Attempt",
            "sid": 2000006,
            "category": "trojan-activity",
            "dest_port": 445,
            "proto": "TCP",
            "severity": 1,
        },
        "benign": {
            "signature": "[SIMULATION] Benign Inbound HTTPS Web Traffic",
            "sid": 1000001,
            "category": "policy-violation",
            "dest_port": 443,
            "proto": "TCP",
            "severity": 3,
        }
    }

    @classmethod
    def generate_event(
        cls,
        scenario_key: str = "mixed",
        attacker_ip: str = None,
        target_ip: str = None,
        timestamp_offset_seconds: int = 0
    ) -> Dict[str, Any]:
        """Generates a single Suricata-compatible EVE JSON dictionary."""
        if scenario_key == "mixed" or scenario_key not in cls.SCENARIOS:
            weights = [25, 20, 15, 20, 10, 10]
            scenario_key = random.choices(list(cls.SCENARIOS.keys()), weights=weights, k=1)[0]

        scenario = cls.SCENARIOS[scenario_key]
        src_ip = attacker_ip or random.choice(cls.SIMULATED_ATTACKERS)
        dest_ip = target_ip or random.choice(cls.INTERNAL_TARGETS)
        src_port = random.randint(30000, 65000)
        
        if scenario["dest_port"] is None:
            # For port scan, choose from common ports
            dest_port = random.choice([21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080])
        else:
            dest_port = scenario["dest_port"]

        event_time = datetime.now(timezone.utc) - timedelta(seconds=timestamp_offset_seconds)
        ts_str = event_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

        eve_dict = {
            "timestamp": ts_str,
            "flow_id": random.randint(100000000000000, 999999999999999),
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": scenario["proto"],
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": scenario["sid"],
                "rev": 1,
                "signature": scenario["signature"],
                "category": scenario["category"],
                "severity": scenario["severity"],
                "metadata": {
                    "simulation": True,
                    "lab_authorized": True,
                }
            },
            "is_simulation": True,
        }
        return eve_dict

    @classmethod
    def generate_batch(cls, count: int = 10, scenario: str = "mixed") -> List[Dict[str, Any]]:
        """Generates a deterministic batch of simulated EVE events."""
        events = []
        for i in range(count):
            # Spread events over the past few minutes for realistic time windows
            offset = (count - i) * random.randint(2, 15)
            ev = cls.generate_event(scenario_key=scenario, timestamp_offset_seconds=offset)
            events.append(ev)
        return events
