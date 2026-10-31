"""
Matter forensic artifact collector — passive traffic analysis and device fingerprinting.
"""
import time
import json
import struct
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import defaultdict

from ..protocols.matter import (
    parse_message_header, MessageType,
    PROTOCOL_ID_SECURE_CHANNEL, PROTOCOL_ID_INTERACTION_MODEL,
)


@dataclass
class MatterDevice:
    node_id: int = 0
    ip_address: str = ""
    port: int = 5540
    vendor_id: Optional[int] = None
    product_id: Optional[int] = None
    device_type: str = ""
    fabric_id: Optional[int] = None
    sessions_observed: int = 0
    messages_observed: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    message_types_seen: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "node_id": f"0x{self.node_id:016X}" if self.node_id else "Unknown",
            "ip": f"{self.ip_address}:{self.port}",
            "vendor_id": f"0x{self.vendor_id:04X}" if self.vendor_id else None,
            "product_id": f"0x{self.product_id:04X}" if self.product_id else None,
            "device_type": self.device_type,
            "sessions": self.sessions_observed,
            "messages": self.messages_observed,
            "first_seen": time.ctime(self.first_seen) if self.first_seen else None,
            "last_seen": time.ctime(self.last_seen) if self.last_seen else None,
        }


@dataclass
class ForensicArtifact:
    timestamp: float
    artifact_type: str
    source_ip: str
    detail: str
    raw_data: Optional[bytes] = None
    severity: str = "info"


class MatterForensicCollector:

    def __init__(self):
        self.devices: Dict[str, MatterDevice] = {}
        self.artifacts: List[ForensicArtifact] = []
        self.sessions: Dict[int, Dict] = {}
        self.anomalies: List[ForensicArtifact] = []
        self._sigma1_tracker: Dict[str, List[float]] = defaultdict(list)
        self._fabric_ids_seen: set = set()
        self._known_fabrics: set = set()

    def process_packet(self, data: bytes, source_ip: str, source_port: int):
        """Process a captured Matter packet."""
        now = time.time()
        parsed = parse_message_header(data)
        if not parsed:
            self.anomalies.append(ForensicArtifact(
                now, "malformed_header", source_ip,
                f"Unparseable Matter message ({len(data)} bytes)",
                raw_data=data[:64], severity="warning",
            ))
            return

        key = f"{source_ip}:{source_port}"
        if key not in self.devices:
            self.devices[key] = MatterDevice(
                ip_address=source_ip, port=source_port,
                first_seen=now,
            )
        dev = self.devices[key]
        dev.last_seen = now
        dev.messages_observed += 1
        if parsed.get("source_node"):
            dev.node_id = parsed["source_node"]

        session_id = parsed["session_id"]
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "id": session_id, "first_seen": now,
                "participants": set(), "message_count": 0,
            }
            dev.sessions_observed += 1
        self.sessions[session_id]["participants"].add(key)
        self.sessions[session_id]["message_count"] += 1

        # Extract protocol opcode from payload for deeper analysis
        payload = parsed.get("payload", b"")
        opcode = None
        if len(payload) >= 6:
            try:
                opcode = struct.unpack("<B", payload[5:6])[0] if len(payload) > 5 else None
            except Exception:
                pass

        # Anomaly 1: MaDoS — unsecured status reports
        if session_id == 0 and len(payload) >= 6:
            raw_opcode = payload[1] if len(payload) > 1 else -1
            if raw_opcode == MessageType.STATUS_REPORT:
                self.anomalies.append(ForensicArtifact(
                    now, "unsecured_status_report", source_ip,
                    "Status Report on unsecured session — possible MaDoS attack",
                    severity="critical",
                ))

        # Anomaly 2: Counter near max — desync attack
        if parsed["message_counter"] > 0xFFFFFFF0:
            self.anomalies.append(ForensicArtifact(
                now, "counter_near_max", source_ip,
                f"Message counter 0x{parsed['message_counter']:08X} near max — "
                f"possible counter desync attack",
                severity="warning",
            ))

        # Anomaly 3: Excessive CASE Sigma1 — session exhaustion
        if session_id == 0 and opcode is not None:
            self._sigma1_tracker[source_ip].append(now)
            # Keep only last 10 seconds of entries
            cutoff = now - 10.0
            self._sigma1_tracker[source_ip] = [
                t for t in self._sigma1_tracker[source_ip] if t > cutoff
            ]
            if len(self._sigma1_tracker[source_ip]) > 20:
                self.anomalies.append(ForensicArtifact(
                    now, "excessive_sigma1", source_ip,
                    f"{len(self._sigma1_tracker[source_ip])} unsecured-session messages "
                    f"in 10s from {source_ip} — possible session exhaustion",
                    severity="warning",
                ))

        # Anomaly 4: Unknown fabric ID
        if parsed.get("dest_node") and parsed["dest_node"] > 0:
            fabric_hint = (parsed["dest_node"] >> 48) & 0xFFFF
            if fabric_hint > 0:
                if self._known_fabrics and fabric_hint not in self._known_fabrics:
                    self.anomalies.append(ForensicArtifact(
                        now, "unknown_fabric", source_ip,
                        f"Node referencing fabric 0x{fabric_hint:04X} — "
                        f"not in known fabric set",
                        severity="warning",
                    ))
                self._fabric_ids_seen.add(fabric_hint)
                if len(self._known_fabrics) == 0 and len(self._fabric_ids_seen) >= 3:
                    self._known_fabrics = set(self._fabric_ids_seen)

        # Anomaly 5: Beacon anomaly — duplicate info from different source
        # (tracked via node IDs claiming same identity from different IPs)
        if parsed.get("source_node"):
            for other_key, other_dev in self.devices.items():
                if (other_key != key and other_dev.node_id == parsed["source_node"]
                        and other_dev.node_id != 0):
                    self.anomalies.append(ForensicArtifact(
                        now, "beacon_anomaly", source_ip,
                        f"Node 0x{parsed['source_node']:016X} seen from {source_ip} "
                        f"and {other_dev.ip_address} — possible spoofing",
                        severity="warning",
                    ))

    def add_known_fabric(self, fabric_id: int):
        self._known_fabrics.add(fabric_id)

    def generate_report(self) -> Dict:
        return {
            "timestamp": time.ctime(),
            "summary": {
                "devices_discovered": len(self.devices),
                "sessions_observed": len(self.sessions),
                "total_messages": sum(d.messages_observed for d in self.devices.values()),
                "anomalies_detected": len(self.anomalies),
            },
            "devices": [d.to_dict() for d in self.devices.values()],
            "anomalies": [
                {"time": time.ctime(a.timestamp), "type": a.artifact_type,
                 "source": a.source_ip, "detail": a.detail, "severity": a.severity}
                for a in self.anomalies
            ],
        }

    def export_report(self, path: str):
        report = self.generate_report()
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
