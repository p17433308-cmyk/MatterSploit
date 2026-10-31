"""MatterSploit — Matter/Thread Offensive Security Framework"""
__version__ = "1.0.0"

from .protocols.matter import (
    MATTER_UDP_PORT, MATTER_TCP_PORT, MATTER_MDNS_PORT,
    PROTOCOL_ID_SECURE_CHANNEL, PROTOCOL_ID_INTERACTION_MODEL,
    PROTOCOL_ID_BDX, PROTOCOL_ID_USER_DIRECTED_COMMISSIONING,
    MessageType, InteractionType, StatusCode, TLVType,
    MatterMessageHeader, MatterProtocolHeader,
    build_message_header, build_protocol_header, build_status_report,
    build_matter_message, parse_message_header,
    encode_tlv_unsigned, encode_tlv_string, encode_tlv_bytes,
)

from .protocols.thread import (
    IEEE802154Frame, ThreadBeacon,
    MLECommandType, MLETLVType,
    build_ieee802154_frame, build_thread_beacon,
    build_mle_discovery_request, build_mle_discovery_response,
    build_beacon_request,
)

from .attacks.matter_attacks import (
    AttackResult, MatterAttacks, ThreadAttacks,
)

from .attacks.ble_attacks import (
    MatterBLEAdvertisement, BLEAttacks,
    build_spoofed_matter_adv, parse_matter_ble_adv,
)

from .attacks.fuzzer import (
    FuzzCase, MatterFuzzer,
)

from .attacks.interaction_attacks import (
    InteractionAttacks, ClusterID, CommandID, AttributeID,
    build_read_request, build_subscribe_request,
    build_write_request, build_invoke_request, build_timed_request,
)

from .discovery.scanner import (
    MatterDeviceInfo, MatterScanner,
)

from .forensics.collector import (
    MatterDevice, ForensicArtifact, MatterForensicCollector,
)

__all__ = [
    "MATTER_UDP_PORT", "MATTER_TCP_PORT", "MATTER_MDNS_PORT",
    "PROTOCOL_ID_SECURE_CHANNEL", "PROTOCOL_ID_INTERACTION_MODEL",
    "PROTOCOL_ID_BDX", "PROTOCOL_ID_USER_DIRECTED_COMMISSIONING",
    "MessageType", "InteractionType", "StatusCode", "TLVType",
    "MatterMessageHeader", "MatterProtocolHeader",
    "build_message_header", "build_protocol_header", "build_status_report",
    "build_matter_message", "parse_message_header",
    "encode_tlv_unsigned", "encode_tlv_string", "encode_tlv_bytes",
    "IEEE802154Frame", "ThreadBeacon",
    "MLECommandType", "MLETLVType",
    "build_ieee802154_frame", "build_thread_beacon",
    "build_mle_discovery_request", "build_mle_discovery_response",
    "build_beacon_request",
    "AttackResult", "MatterAttacks", "ThreadAttacks",
    "MatterBLEAdvertisement", "BLEAttacks",
    "build_spoofed_matter_adv", "parse_matter_ble_adv",
    "FuzzCase", "MatterFuzzer",
    "InteractionAttacks", "ClusterID", "CommandID", "AttributeID",
    "build_read_request", "build_subscribe_request",
    "build_write_request", "build_invoke_request", "build_timed_request",
    "MatterDeviceInfo", "MatterScanner",
    "MatterDevice", "ForensicArtifact", "MatterForensicCollector",
]
