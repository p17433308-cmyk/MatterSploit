"""
Thread network protocol structures — IEEE 802.15.4 + MLE + CoAP.

Thread is the underlying mesh network for Matter devices. It uses:
  - IEEE 802.15.4 MAC frames at Layer 2
  - 6LoWPAN for IPv6 header compression
  - MLE (Mesh Link Establishment) for neighbor discovery and routing
  - CoAP for application-layer messaging

Security: Thread uses AES-CCM with a Network Key distributed during commissioning.
Attack vectors:
  - Network Key extraction from commissioned devices
  - MLE frame injection (some frames are unauthenticated during joining)
  - Beacon request/response manipulation
  - Border Router advertisement spoofing
"""
import struct
import os
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import IntEnum


THREAD_CHANNEL_MIN = 11
THREAD_CHANNEL_MAX = 26
THREAD_PAN_ID_BROADCAST = 0xFFFF
IEEE802154_FRAME_TYPE_BEACON = 0x00
IEEE802154_FRAME_TYPE_DATA = 0x01
IEEE802154_FRAME_TYPE_ACK = 0x02
IEEE802154_FRAME_TYPE_CMD = 0x03

MLE_UDP_PORT = 19788
THREAD_MANAGEMENT_PORT = 61631


class MLECommandType(IntEnum):
    LINK_REQUEST = 0
    LINK_ACCEPT = 1
    LINK_ACCEPT_AND_REQUEST = 2
    LINK_REJECT = 3
    ADVERTISEMENT = 4
    UPDATE = 5
    UPDATE_REQUEST = 6
    DATA_REQUEST = 7
    DATA_RESPONSE = 8
    PARENT_REQUEST = 9
    PARENT_RESPONSE = 10
    CHILD_ID_REQUEST = 11
    CHILD_ID_RESPONSE = 12
    CHILD_UPDATE_REQUEST = 13
    CHILD_UPDATE_RESPONSE = 14
    ANNOUNCE = 15
    DISCOVERY_REQUEST = 16
    DISCOVERY_RESPONSE = 17


class MLETLVType(IntEnum):
    SOURCE_ADDRESS = 0
    MODE = 1
    TIMEOUT = 2
    CHALLENGE = 3
    RESPONSE = 4
    LINK_LAYER_FRAME_COUNTER = 5
    MLE_FRAME_COUNTER = 8
    ROUTE64 = 9
    ADDRESS16 = 10
    LEADER_DATA = 11
    NETWORK_DATA = 12
    TLV_REQUEST = 13
    SCAN_MASK = 14
    CONNECTIVITY = 15
    LINK_MARGIN = 16
    STATUS = 17
    VERSION = 18
    ADDRESS_REGISTRATION = 19
    CHANNEL = 20


@dataclass
class IEEE802154Frame:
    frame_type: int = IEEE802154_FRAME_TYPE_DATA
    security_enabled: bool = False
    frame_pending: bool = False
    ack_request: bool = False
    pan_id_compression: bool = True
    sequence_number: int = 0
    dest_pan_id: int = 0xFFFF
    dest_addr: bytes = b"\xFF\xFF"
    source_addr: bytes = b"\x00\x00"
    payload: bytes = b""


@dataclass
class ThreadBeacon:
    protocol_id: int = 3  # Thread
    version: int = 4
    native_commissioning: bool = True
    network_name: str = "OpenThread"
    extended_pan_id: bytes = b"\x00" * 8
    steering_data: bytes = b"\xFF"


def build_ieee802154_frame(frame: IEEE802154Frame) -> bytes:
    fcf = frame.frame_type & 0x07
    if frame.security_enabled:
        fcf |= 0x08
    if frame.frame_pending:
        fcf |= 0x10
    if frame.ack_request:
        fcf |= 0x20
    if frame.pan_id_compression:
        fcf |= 0x40
    # dest addressing mode: short (0x02)
    fcf |= (0x02 << 10)
    # source addressing mode: short (0x02)
    fcf |= (0x02 << 14)

    buf = struct.pack("<H", fcf)
    buf += struct.pack("<B", frame.sequence_number)
    buf += struct.pack("<H", frame.dest_pan_id)
    buf += frame.dest_addr[:2]
    if not frame.pan_id_compression:
        buf += struct.pack("<H", frame.dest_pan_id)
    buf += frame.source_addr[:2]
    buf += frame.payload
    return buf


def build_thread_beacon(beacon: ThreadBeacon) -> bytes:
    buf = struct.pack("<B", beacon.protocol_id)
    flags = (beacon.version & 0x0F) << 4
    if beacon.native_commissioning:
        flags |= 0x08
    buf += struct.pack("<B", flags)
    name_bytes = beacon.network_name.encode("utf-8")[:16].ljust(16, b"\x00")
    buf += name_bytes
    buf += beacon.extended_pan_id[:8]
    buf += beacon.steering_data
    return buf


def build_mle_discovery_request(version: int = 4) -> bytes:
    """Build an MLE Discovery Request — sent UNENCRYPTED."""
    buf = struct.pack("<B", MLECommandType.DISCOVERY_REQUEST)
    # Version TLV
    buf += struct.pack("<BBH", MLETLVType.VERSION, 2, version)
    return buf


def build_mle_discovery_response(source_addr: int, network_name: str,
                                   pan_id: int, channel: int) -> bytes:
    """Build an MLE Discovery Response."""
    buf = struct.pack("<B", MLECommandType.DISCOVERY_RESPONSE)
    # Source Address TLV
    buf += struct.pack("<BBH", MLETLVType.SOURCE_ADDRESS, 2, source_addr)
    # Network Data TLV (simplified)
    name_data = network_name.encode("utf-8")[:16]
    buf += struct.pack("<BB", MLETLVType.NETWORK_DATA, len(name_data))
    buf += name_data
    # Channel TLV
    buf += struct.pack("<BB", MLETLVType.CHANNEL, 3)
    buf += struct.pack("<BH", 0, channel)  # channel page 0
    return buf


def build_beacon_request() -> bytes:
    """Build IEEE 802.15.4 Beacon Request command frame."""
    frame = IEEE802154Frame(
        frame_type=IEEE802154_FRAME_TYPE_CMD,
        dest_pan_id=THREAD_PAN_ID_BROADCAST,
        dest_addr=b"\xFF\xFF",
        payload=struct.pack("<B", 0x07),  # Beacon Request command ID
    )
    return build_ieee802154_frame(frame)
