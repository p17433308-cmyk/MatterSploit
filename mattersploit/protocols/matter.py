"""
Matter protocol implementation — message framing, TLV encoding, and session structures.

Matter uses:
  - CASE (Certificate Authenticated Session Establishment) for node-to-node
  - PASE (Passcode Authenticated Session Establishment) for commissioning
  - MRP (Message Reliability Protocol) for retransmission
  - Interaction Model for read/write/subscribe/invoke

Message format:
  Message Header (variable):
    Flags (1 byte) — version, source/dest node ID presence
    Session ID (2 bytes)
    Security Flags (1 byte) — session type, privacy flag
    Message Counter (4 bytes)
    [Source Node ID (8 bytes)] — if flag set
    [Dest Node ID (8 bytes)] — if flag set
  Payload (encrypted with AES-CCM after session establishment)

Status Reports (Section 11.9.7) are UNENCRYPTED and UNAUTHENTICATED — the MaDoS vector.
"""
import struct
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import IntEnum


MATTER_UDP_PORT = 5540
MATTER_TCP_PORT = 5540
MATTER_MDNS_PORT = 5353

PROTOCOL_ID_SECURE_CHANNEL = 0x0000
PROTOCOL_ID_INTERACTION_MODEL = 0x0001
PROTOCOL_ID_BDX = 0x0002  # Bulk Data Exchange
PROTOCOL_ID_USER_DIRECTED_COMMISSIONING = 0x0003


class MessageType(IntEnum):
    # Secure Channel (Protocol 0x0000)
    MSG_COUNTER_SYNC_REQ = 0x00
    MSG_COUNTER_SYNC_RSP = 0x01
    MRP_STANDALONE_ACK = 0x10
    PBKDF_PARAM_REQUEST = 0x20  # PASE
    PBKDF_PARAM_RESPONSE = 0x21
    PASE_PAKE1 = 0x22
    PASE_PAKE2 = 0x23
    PASE_PAKE3 = 0x24
    CASE_SIGMA1 = 0x30
    CASE_SIGMA2 = 0x31
    CASE_SIGMA3 = 0x32
    CASE_SIGMA2_RESUME = 0x33
    STATUS_REPORT = 0x40


class InteractionType(IntEnum):
    STATUS_RESPONSE = 0x01
    READ_REQUEST = 0x02
    SUBSCRIBE_REQUEST = 0x03
    SUBSCRIBE_RESPONSE = 0x04
    REPORT_DATA = 0x05
    WRITE_REQUEST = 0x06
    WRITE_RESPONSE = 0x07
    INVOKE_REQUEST = 0x08
    INVOKE_RESPONSE = 0x09
    TIMED_REQUEST = 0x0A


class StatusCode(IntEnum):
    SUCCESS = 0
    FAILURE = 1
    INVALID_SUBSCRIPTION = 0x007D
    UNSUPPORTED_ACCESS = 0x007E
    UNSUPPORTED_ENDPOINT = 0x007F
    INVALID_ACTION = 0x0080
    UNSUPPORTED_COMMAND = 0x0081
    INVALID_COMMAND = 0x0085
    UNSUPPORTED_ATTRIBUTE = 0x0086
    CONSTRAINT_ERROR = 0x0087
    UNSUPPORTED_WRITE = 0x0088
    RESOURCE_EXHAUSTED = 0x0089
    NOT_FOUND = 0x008B
    UNREPORTABLE_ATTRIBUTE = 0x008C
    INVALID_DATA_TYPE = 0x008D
    BUSY = 0x009C
    NEEDS_TIMED_INTERACTION = 0x00C6
    UNSUPPORTED_CLUSTER = 0x00C3
    DATA_VERSION_MISMATCH = 0x00C4
    TIMEOUT = 0x0094
    FAILSAFE_REQUIRED = 0x00CA
    INVALID_IN_STATE = 0x00CB


class TLVType(IntEnum):
    SIGNED_INT = 0x00
    UNSIGNED_INT = 0x04
    BOOLEAN_FALSE = 0x08
    BOOLEAN_TRUE = 0x09
    FLOAT = 0x0A
    DOUBLE = 0x0B
    UTF8_STRING = 0x0C
    BYTE_STRING = 0x10
    NULL = 0x14
    STRUCTURE = 0x15
    ARRAY = 0x16
    LIST = 0x17
    END_OF_CONTAINER = 0x18


@dataclass
class MatterMessageHeader:
    flags: int = 0x04  # version 1, no source/dest IDs by default
    session_id: int = 0
    security_flags: int = 0
    message_counter: int = 0
    source_node_id: Optional[int] = None
    dest_node_id: Optional[int] = None


@dataclass
class MatterProtocolHeader:
    exchange_flags: int = 0x01  # initiator
    protocol_opcode: int = 0
    exchange_id: int = 0
    protocol_id: int = 0
    ack_counter: Optional[int] = None


def build_message_header(hdr: MatterMessageHeader) -> bytes:
    flags = hdr.flags & 0xFF
    if hdr.source_node_id is not None:
        flags |= 0x04
    if hdr.dest_node_id is not None:
        flags |= 0x01

    buf = struct.pack("<B", flags)
    buf += struct.pack("<H", hdr.session_id)
    buf += struct.pack("<B", hdr.security_flags)
    buf += struct.pack("<I", hdr.message_counter)

    if hdr.source_node_id is not None:
        buf += struct.pack("<Q", hdr.source_node_id)
    if hdr.dest_node_id is not None:
        buf += struct.pack("<Q", hdr.dest_node_id)

    return buf


def build_protocol_header(phdr: MatterProtocolHeader) -> bytes:
    buf = struct.pack("<B", phdr.exchange_flags)
    buf += struct.pack("<B", phdr.protocol_opcode)
    buf += struct.pack("<H", phdr.exchange_id)
    buf += struct.pack("<H", phdr.protocol_id)

    if phdr.ack_counter is not None:
        buf += struct.pack("<I", phdr.ack_counter)

    return buf


def build_status_report(general_code: int, protocol_id: int = 0,
                         protocol_code: int = 0) -> bytes:
    """Build a Status Report message — UNENCRYPTED and UNAUTHENTICATED."""
    return struct.pack("<IHI", general_code, protocol_id, protocol_code)


def build_matter_message(session_id: int, message_counter: int,
                          protocol_id: int, opcode: int,
                          payload: bytes = b"",
                          source_node: Optional[int] = None,
                          dest_node: Optional[int] = None,
                          exchange_id: int = 1) -> bytes:
    hdr = MatterMessageHeader(
        session_id=session_id,
        message_counter=message_counter,
        source_node_id=source_node,
        dest_node_id=dest_node,
    )
    phdr = MatterProtocolHeader(
        protocol_opcode=opcode,
        exchange_id=exchange_id,
        protocol_id=protocol_id,
    )
    return build_message_header(hdr) + build_protocol_header(phdr) + payload


def encode_tlv_unsigned(tag: int, value: int) -> bytes:
    base = TLVType.UNSIGNED_INT << 2
    if value <= 0xFF:
        return struct.pack("<BBB", base | 0x00, tag, value)
    elif value <= 0xFFFF:
        return struct.pack("<BBH", base | 0x01, tag, value)
    elif value <= 0xFFFFFFFF:
        return struct.pack("<BBI", base | 0x02, tag, value)
    else:
        return struct.pack("<BBQ", base | 0x03, tag, value)


def encode_tlv_string(tag: int, value: str) -> bytes:
    data = value.encode("utf-8")
    buf = struct.pack("<BB", (TLVType.UTF8_STRING << 2) | 0x01, tag)
    buf += struct.pack("<H", len(data))
    buf += data
    return buf


def encode_tlv_bytes(tag: int, value: bytes) -> bytes:
    buf = struct.pack("<BB", (TLVType.BYTE_STRING << 2) | 0x01, tag)
    buf += struct.pack("<H", len(value))
    buf += value
    return buf


def parse_message_header(data: bytes) -> Optional[Dict]:
    if len(data) < 8:
        return None
    flags = data[0]
    session_id = struct.unpack("<H", data[1:3])[0]
    security_flags = data[3]
    message_counter = struct.unpack("<I", data[4:8])[0]

    offset = 8
    source_node = None
    dest_node = None

    if flags & 0x04:
        if len(data) < offset + 8:
            return None
        source_node = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8

    has_dest = flags & 0x01
    if security_flags & 0x01:
        has_dest = True
    if has_dest:
        if len(data) < offset + 8:
            return None
        dest_node = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8

    return {
        "flags": flags, "session_id": session_id,
        "security_flags": security_flags, "message_counter": message_counter,
        "source_node": source_node, "dest_node": dest_node,
        "header_size": offset, "payload": data[offset:],
    }
