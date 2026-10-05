from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from app.models.security_event import SecurityEvent


@dataclass
class ThreatAssessment:
    score: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: int  # 0 to 100
    factors: List[Dict[str, Any]] = field(default_factory=list)


class ThreatScoringEngine:
    """
    Modular, deterministic, explainable rule-based threat scoring engine.
    Calculates threat scores (0-100) and severity ratings based on transparent
    rule evaluation without arbitrary or unexplainable black-box models.
    """

    SEVERITY_THRESHOLDS = [
        (80, "CRITICAL"),
        (60, "HIGH"),
        (30, "MEDIUM"),
        (0, "LOW"),
    ]

    DEFAULT_CONFIG = {
        "scoring_port_scan_points": 30,
        "scoring_malicious_sig_points": 30,
        "scoring_repeated_conn_points": 20,
        "scoring_freq_activity_points": 10,
        "scoring_exploit_points": 35,
        "scoring_brute_force_points": 30,
        "scoring_sqli_points": 30,
    }

    def __init__(self, config: Optional[Dict[str, int]] = None):
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}

    @classmethod
    def determine_severity(cls, score: int) -> str:
        clamped_score = max(0, min(100, score))
        for threshold, severity in cls.SEVERITY_THRESHOLDS:
            if clamped_score >= threshold:
                return severity
        return "LOW"

    def evaluate_events(
        self,
        events: List[SecurityEvent],
        known_whitelisted: bool = False
    ) -> ThreatAssessment:
        """
        Evaluate a collection of correlated security events and calculate
        an explainable threat score, confidence level, and factor breakdown.
        """
        if not events:
            return ThreatAssessment(
                score=0,
                severity="LOW",
                confidence=50,
                factors=[{"reason": "No security events observed", "points": 0}]
            )

        if known_whitelisted:
            return ThreatAssessment(
                score=0,
                severity="LOW",
                confidence=100,
                factors=[{"reason": "Source IP is explicitly whitelisted in SOC policies", "points": 0}]
            )

        factors: List[Dict[str, Any]] = []
        raw_score = 0
        event_count = len(events)

        # 1. Base attack category evaluation (applied once per category present)
        categories = {e.category for e in events if e.category}
        signatures = {e.signature for e in events if e.signature}

        if any("Exploit" in c for c in categories):
            pts = self.config.get("scoring_exploit_points", 35)
            factors.append({"reason": "Active software exploit attempt detected", "points": pts})
            raw_score += pts
        elif any("Web Application Attack" in c for c in categories):
            pts = self.config.get("scoring_sqli_points", 30)
            factors.append({"reason": "Web application attack / SQL injection vector detected", "points": pts})
            raw_score += pts
        elif any("Brute Force" in c for c in categories):
            pts = self.config.get("scoring_brute_force_points", 30)
            factors.append({"reason": "Authentication brute-force pattern detected", "points": pts})
            raw_score += pts
        elif any("Port Scan" in c for c in categories):
            pts = self.config.get("scoring_port_scan_points", 30)
            factors.append({"reason": "Network reconnaissance / port scanning activity detected", "points": pts})
            raw_score += pts
        elif any("Denial of Service" in c for c in categories):
            pts = 30
            factors.append({"reason": "Volumetric denial of service pattern detected", "points": pts})
            raw_score += pts
        elif any("Suspicious Activity" in c for c in categories):
            pts = 15
            factors.append({"reason": "Suspicious network behavior detected", "points": pts})
            raw_score += pts

        # 2. Highest alert severity evaluation
        # Suricata severity: 1: High, 2: Medium, 3: Low, 4: Info
        min_suricata_sev = min((e.severity for e in events if e.severity is not None), default=3)
        if min_suricata_sev == 1:
            pts = 25
            factors.append({"reason": "High-severity IDS detection rule triggered", "points": pts})
            raw_score += pts
        elif min_suricata_sev == 2:
            pts = 15
            factors.append({"reason": "Medium-severity IDS detection rule triggered", "points": pts})
            raw_score += pts
        elif min_suricata_sev == 3:
            pts = 5
            factors.append({"reason": "Low-severity IDS event observed", "points": pts})
            raw_score += pts

        # 3. Known high-impact signatures
        has_critical_sig = False
        for sig in signatures:
            sig_lower = sig.lower()
            if any(term in sig_lower for term in ["shell", "rce", "smb ghost", "command execution", "union select"]):
                has_critical_sig = True
                break

        if has_critical_sig:
            pts = self.config.get("scoring_malicious_sig_points", 30)
            factors.append({"reason": "Signature matches verified critical threat pattern (RCE/SQLi/SMB)", "points": pts})
            raw_score += pts

        # 4. Repeated suspicious connections & burst frequency
        if event_count >= 15:
            pts = self.config.get("scoring_repeated_conn_points", 20)
            factors.append({"reason": f"Sustained high attack volume ({event_count} alerts logged)", "points": pts})
            raw_score += pts
        elif event_count >= 5:
            pts = 15
            factors.append({"reason": f"Repeated suspicious connection attempts ({event_count} alerts logged)", "points": pts})
            raw_score += pts
        elif event_count >= 2:
            pts = 5
            factors.append({"reason": f"Correlated multi-event sequence ({event_count} alerts)", "points": pts})
            raw_score += pts

        # 5. Temporal burst: rapid connections within short interval
        timestamps = sorted([e.timestamp for e in events if e.timestamp])
        if len(timestamps) >= 3:
            time_delta = (timestamps[-1] - timestamps[0]).total_seconds()
            if time_delta <= 60:
                pts = self.config.get("scoring_freq_activity_points", 10)
                factors.append({"reason": f"High-frequency attack burst ({len(timestamps)} events in {int(time_delta)}s)", "points": pts})
                raw_score += pts

        # 6. Target diversification (multi-port scanning or multi-host targeting)
        distinct_ports = {e.destination_port for e in events if e.destination_port is not None}
        if len(distinct_ports) >= 3:
            pts = 15
            factors.append({"reason": f"Multi-port probing behavior ({len(distinct_ports)} distinct ports targeted)", "points": pts})
            raw_score += pts

        distinct_targets = {e.destination_ip for e in events if e.destination_ip}
        if len(distinct_targets) >= 2:
            pts = 10
            factors.append({"reason": f"Lateral movement or multi-host probing ({len(distinct_targets)} hosts targeted)", "points": pts})
            raw_score += pts

        # 7. Final score clamping (0 to 100)
        final_score = max(0, min(100, raw_score))
        severity = self.determine_severity(final_score)

        # 8. Explainable confidence calculation based on corroboration
        confidence = 60
        if event_count >= 5:
            confidence += 15
        elif event_count >= 2:
            confidence += 10
        if has_critical_sig:
            confidence += 15
        if min_suricata_sev == 1:
            confidence += 10
        confidence = min(98, confidence)

        return ThreatAssessment(
            score=final_score,
            severity=severity,
            confidence=confidence,
            factors=factors
        )
