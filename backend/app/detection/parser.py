import json
import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class ParsedEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    event_type: str
    signature: str
    signature_id: Optional[int]
    category: str
    severity: int  # 1: High, 2: Medium, 3: Low, 4: Info
    action: str
    raw_reference: Optional[str]
    is_simulation: bool
    dedup_hash: str


class SuricataEveParser:
    """Robust Suricata EVE JSON parser and normalizer."""

    CATEGORY_MAPPINGS = {
        "attempted-admin": "Brute Force",
        "attempted-user": "Brute Force",
        "web-application-attack": "Web Application Attack",
        "attempted-recon": "Port Scan",
        "network-scan": "Port Scan",
        "trojan-activity": "Exploit & Malware",
        "misc-attack": "Exploit & Malware",
        "bad-unknown": "Suspicious Activity",
        "policy-violation": "Policy Violation",
    }

    @staticmethod
    def _parse_timestamp(ts_raw: Any) -> Optional[datetime]:
        if isinstance(ts_raw, datetime):
            return ts_raw.astimezone(timezone.utc).replace(tzinfo=None) if ts_raw.tzinfo else ts_raw
        if not isinstance(ts_raw, str):
            return None
        
        # Support various ISO-8601 Suricata formats
        # e.g., "2026-10-04T16:45:00.123456+0000", "2026-10-04T16:45:00Z"
        cleaned_ts = ts_raw.strip()
        # Normalize timezone offsets like +0000 or -0500 to +00:00
        if re.search(r"[+-]\d{4}$", cleaned_ts):
            cleaned_ts = cleaned_ts[:-2] + ":" + cleaned_ts[-2:]

        try:
            dt = datetime.fromisoformat(cleaned_ts.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except Exception:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(cleaned_ts, fmt)
                    if dt.tzinfo:
                        return dt.astimezone(timezone.utc).replace(tzinfo=None)
                    return dt
                except ValueError:
                    continue
        return None

    @staticmethod
    def _validate_ip(ip_str: Any) -> Optional[str]:
        if not ip_str or not isinstance(ip_str, str):
            return None
        try:
            validated = ipaddress.ip_address(ip_str.strip())
            return str(validated)
        except ValueError:
            return None

    @staticmethod
    def _validate_port(port_val: Any) -> Optional[int]:
        if port_val is None:
            return None
        try:
            p = int(port_val)
            if 1 <= p <= 65535:
                return p
        except (ValueError, TypeError):
            pass
        return None

    @classmethod
    def _map_category(cls, suricata_category: Optional[str], signature: str) -> str:
        sig_lower = signature.lower()
        if "port scan" in sig_lower or "syn scan" in sig_lower or "rdp scan" in sig_lower or "nmap" in sig_lower:
            return "Port Scan"
        if "brute force" in sig_lower or "login" in sig_lower or "password" in sig_lower:
            return "Brute Force"
        if "sql" in sig_lower or "injection" in sig_lower or "uri" in sig_lower or "xss" in sig_lower:
            return "Web Application Attack"
        if "exploit" in sig_lower or "rce" in sig_lower or "shell" in sig_lower or "smb" in sig_lower:
            return "Exploit"
        if "dos" in sig_lower or "ddos" in sig_lower or "flood" in sig_lower:
            return "Denial of Service"
        
        if suricata_category:
            cat_key = suricata_category.strip().lower()
            if cat_key in cls.CATEGORY_MAPPINGS:
                return cls.CATEGORY_MAPPINGS[cat_key]
        
        return "Suspicious Activity"

    @classmethod
    def parse_event_dict(cls, data: Dict[str, Any]) -> Tuple[Optional[ParsedEvent], Optional[str]]:
        """
        Parses and normalizes a Suricata EVE dictionary.
        Returns: (ParsedEvent, None) on success, or (None, error_reason) on failure.
        """
        if not isinstance(data, dict):
            return None, "Event data is not a dictionary"

        # 1. Timestamp validation
        timestamp_raw = data.get("timestamp")
        timestamp = cls._parse_timestamp(timestamp_raw)
        if not timestamp:
            return None, f"Invalid or missing timestamp: {timestamp_raw}"

        # 2. IP validation
        src_ip = cls._validate_ip(data.get("src_ip"))
        dest_ip = cls._validate_ip(data.get("dest_ip"))
        if not src_ip:
            return None, f"Invalid or missing source IP: {data.get('src_ip')}"
        if not dest_ip:
            return None, f"Invalid or missing destination IP: {data.get('dest_ip')}"

        # 3. Ports & Protocol
        src_port = cls._validate_port(data.get("src_port"))
        dest_port = cls._validate_port(data.get("dest_port"))
        proto_raw = data.get("proto") or "TCP"
        protocol = str(proto_raw).upper()

        # 4. Event Type & Sub-structures
        event_type = str(data.get("event_type", "alert")).lower()

        signature = "Suspicious Network Event"
        signature_id = None
        category = "Suspicious Activity"
        severity = 3
        action = "allowed"

        if event_type == "alert":
            alert_obj = data.get("alert")
            if isinstance(alert_obj, dict):
                signature = alert_obj.get("signature", "Generic Alert")
                signature_id = alert_obj.get("signature_id")
                raw_cat = alert_obj.get("category")
                category = cls._map_category(raw_cat, signature)
                raw_sev = alert_obj.get("severity")
                if isinstance(raw_sev, int) and 1 <= raw_sev <= 4:
                    severity = raw_sev
                action = alert_obj.get("action", "allowed")
        elif event_type == "http":
            http_obj = data.get("http", {})
            hostname = http_obj.get("hostname", dest_ip)
            url = http_obj.get("url", "/")
            signature = f"HTTP Request: {hostname}{url}"
            category = "HTTP Traffic"
            severity = 4
        elif event_type == "dns":
            dns_obj = data.get("dns", {})
            query = dns_obj.get("rrname", "unknown.domain")
            signature = f"DNS Query: {query}"
            category = "DNS Traffic"
            severity = 4
        elif event_type == "tls":
            tls_obj = data.get("tls", {})
            sni = tls_obj.get("sni", dest_ip)
            signature = f"TLS Handshake SNI: {sni}"
            category = "TLS Traffic"
            severity = 4
        elif event_type == "flow":
            signature = f"Network Flow: {src_ip}:{src_port} -> {dest_ip}:{dest_port}"
            category = "Flow Telemetry"
            severity = 4
        else:
            signature = f"Suricata {event_type.upper()} Event"
            category = "Other Telemetry"
            severity = 4

        # 5. Simulation flag detection
        is_simulation = bool(data.get("is_simulation", False))
        if "[SIMULATION]" in signature or "DEMO" in signature.upper():
            is_simulation = True

        # 6. Sanitize raw reference (remove raw payloads or sensitive passwords)
        sanitized_data = {
            "timestamp": timestamp.isoformat(),
            "event_type": event_type,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "proto": protocol,
        }
        if "alert" in data and isinstance(data["alert"], dict):
            sanitized_data["alert"] = {
                "signature": data["alert"].get("signature"),
                "signature_id": data["alert"].get("signature_id"),
                "category": data["alert"].get("category"),
                "severity": data["alert"].get("severity"),
            }
        if "http" in data and isinstance(data["http"], dict):
            sanitized_data["http"] = {
                "hostname": data["http"].get("hostname"),
                "url": data["http"].get("url"),
                "http_method": data["http"].get("http_method"),
            }
        
        raw_ref_str = json.dumps(sanitized_data)

        # 7. Deduplication key (hash of key event characteristics)
        dedup_hash = f"{int(timestamp.timestamp())}_{src_ip}_{dest_ip}_{src_port}_{dest_port}_{signature_id or signature}"

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dest_ip,
            source_port=src_port,
            destination_port=dest_port,
            protocol=protocol,
            event_type=event_type,
            signature=signature,
            signature_id=signature_id,
            category=category,
            severity=severity,
            action=action,
            raw_reference=raw_ref_str,
            is_simulation=is_simulation,
            dedup_hash=dedup_hash,
        )
        return parsed, None

    @classmethod
    def parse_eve_json_line(cls, line: str) -> Tuple[Optional[ParsedEvent], Optional[str]]:
        """Parses a single JSON line string from an EVE log file."""
        if not line or not line.strip():
            return None, "Empty line"
        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError as e:
            return None, f"Malformed JSON: {str(e)}"
        
        return cls.parse_event_dict(data)
