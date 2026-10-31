"""
Matter and Thread protocol fuzzer — grammar-aware mutation engine.
"""
import struct
import random
import os
from dataclasses import dataclass
from typing import List

from ..protocols.matter import (
    build_matter_message, build_message_header, build_status_report,
    MatterMessageHeader, MessageType,
    PROTOCOL_ID_SECURE_CHANNEL, PROTOCOL_ID_INTERACTION_MODEL,
    encode_tlv_unsigned, encode_tlv_bytes,
)
from ..protocols.thread import (
    build_ieee802154_frame, IEEE802154Frame, build_mle_discovery_request,
)


@dataclass
class FuzzCase:
    name: str
    protocol: str
    data: bytes
    description: str
    cve: str = ""
    severity: str = "medium"


class MatterFuzzer:

    def generate_message_header_fuzz(self) -> List[FuzzCase]:
        cases = []

        # CVE-2025-56365: nonexistent endpoint → assertion failure → SIGABRT
        payload = encode_tlv_unsigned(1, 0xFFFF)  # endpoint 0xFFFF
        payload += encode_tlv_unsigned(2, 0x0006)  # cluster: OnOff
        payload += encode_tlv_unsigned(3, 0x0002)  # command: Toggle
        msg = build_matter_message(0, 1, PROTOCOL_ID_INTERACTION_MODEL, 0x08,
                                    payload)
        cases.append(FuzzCase(
            "cve_2025_56365_nonexistent_endpoint", "Matter",
            msg, "InvokeRequest to nonexistent endpoint 0xFFFF — SIGABRT in SDK",
            cve="CVE-2025-56365", severity="high",
        ))

        # CVE-2025-56364: uninitialized group ID → SIGABRT
        msg2 = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                     MessageType.STATUS_REPORT,
                                     build_status_report(0, 0, 0),
                                     dest_node=0xFFFFFFFFFFFF0000)
        cases.append(FuzzCase(
            "cve_2025_56364_uninitialized_group", "Matter",
            msg2, "Status Report with group-addressed dest — uninitialized group ID crash",
            cve="CVE-2025-56364", severity="high",
        ))

        # Invalid version in flags
        for ver in [0x00, 0x08, 0x0C, 0x0F]:
            hdr = MatterMessageHeader(flags=ver << 4, session_id=0, message_counter=1)
            raw = build_message_header(hdr)
            cases.append(FuzzCase(
                f"invalid_version_0x{ver:X}", "Matter", raw,
                f"Message version {ver} — only 0 is valid",
            ))

        # Max session ID
        msg = build_matter_message(0xFFFF, 0xFFFFFFFF,
                                    PROTOCOL_ID_SECURE_CHANNEL, 0x10)
        cases.append(FuzzCase(
            "max_session_counter", "Matter", msg,
            "Session ID 0xFFFF + max counter — boundary rollover",
        ))

        # Truncated messages
        full = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL, 0x10,
                                     b"\x00" * 16)
        for t in [2, 4, 7, 8, 12]:
            cases.append(FuzzCase(
                f"truncated_{t}B", "Matter", full[:t],
                f"Message truncated at {t} bytes — OOB read in header parser",
            ))

        # Both source and dest node IDs (max size header)
        msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL, 0x10,
                                    b"\x00" * 8,
                                    source_node=0xFFFFFFFFFFFFFFFF,
                                    dest_node=0xFFFFFFFFFFFFFFFF)
        cases.append(FuzzCase(
            "max_header_both_nodes", "Matter", msg,
            "Both source and dest node IDs present with max values",
        ))

        return cases

    def generate_pase_fuzz(self) -> List[FuzzCase]:
        cases = []

        # PBKDF with invalid iterations
        for iters in [0, 1, 0x7FFFFFFF]:
            payload = encode_tlv_unsigned(1, random.randint(1, 0xFFFF))
            payload += encode_tlv_bytes(2, os.urandom(32))
            payload += encode_tlv_unsigned(3, 1)  # has params
            payload += encode_tlv_unsigned(4, iters)  # iterations
            payload += encode_tlv_bytes(5, os.urandom(32))  # salt
            msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                        MessageType.PBKDF_PARAM_REQUEST, payload)
            cases.append(FuzzCase(
                f"pase_iterations_{iters}", "Matter-PASE", msg,
                f"PBKDF iterations={iters} — DoS (max) or bypass (0/1)",
                severity="high" if iters == 0x7FFFFFFF else "medium",
            ))

        # PAKE1 with invalid point (not on curve)
        payload = encode_tlv_bytes(1, b"\xFF" * 65)  # invalid EC point
        msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                    MessageType.PASE_PAKE1, payload)
        cases.append(FuzzCase(
            "pake1_invalid_point", "Matter-PASE", msg,
            "PAKE1 with invalid elliptic curve point — crash if not validated",
            severity="high",
        ))

        # PAKE2 with zero-length elements
        msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                    MessageType.PASE_PAKE2, b"")
        cases.append(FuzzCase(
            "pake2_empty", "Matter-PASE", msg,
            "PAKE2 with empty payload — null pointer dereference",
            severity="high",
        ))

        return cases

    def generate_case_fuzz(self) -> List[FuzzCase]:
        cases = []

        # Sigma1 with oversized destination ID
        payload = encode_tlv_bytes(1, os.urandom(32))  # random
        payload += encode_tlv_unsigned(2, 1)
        payload += encode_tlv_bytes(3, b"\x41" * 1024)  # oversized dest ID
        msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                    MessageType.CASE_SIGMA1, payload)
        cases.append(FuzzCase(
            "sigma1_oversized_dest", "Matter-CASE", msg,
            "Sigma1 with 1KB destination ID — buffer overflow in HKDF input",
            severity="high",
        ))

        # Sigma2 with invalid certificate
        payload = encode_tlv_bytes(1, os.urandom(32))
        payload += encode_tlv_bytes(2, b"\x00" * 4)  # truncated cert
        payload += encode_tlv_bytes(3, os.urandom(64))
        msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                    MessageType.CASE_SIGMA2, payload)
        cases.append(FuzzCase(
            "sigma2_invalid_cert", "Matter-CASE", msg,
            "Sigma2 with malformed certificate — ASN.1 parser crash",
            severity="high",
        ))

        # Sigma2 Resume with wrong session
        payload = encode_tlv_bytes(1, os.urandom(32))
        payload += encode_tlv_unsigned(2, 0xFFFF)
        msg = build_matter_message(0, 1, PROTOCOL_ID_SECURE_CHANNEL,
                                    MessageType.CASE_SIGMA2_RESUME, payload)
        cases.append(FuzzCase(
            "sigma2_resume_invalid_session", "Matter-CASE", msg,
            "Sigma2 Resume for non-existent session — use-after-free if not checked",
            severity="high",
        ))

        return cases

    def generate_thread_fuzz(self) -> List[FuzzCase]:
        cases = []

        # Oversized IEEE 802.15.4 frame
        frame = IEEE802154Frame(payload=b"\x41" * 300)  # exceeds 127-byte PHY limit
        cases.append(FuzzCase(
            "ieee802154_oversized", "Thread",
            build_ieee802154_frame(frame),
            "802.15.4 frame exceeds 127-byte limit — radio driver buffer overflow",
            severity="high",
        ))

        # MLE with invalid version
        for ver in [0, 0xFF]:
            cases.append(FuzzCase(
                f"mle_discovery_version_{ver}", "Thread",
                build_mle_discovery_request(ver),
                f"MLE Discovery with version {ver} — undefined behavior in version check",
            ))

        # Zero-length 802.15.4 frame
        cases.append(FuzzCase(
            "ieee802154_empty", "Thread",
            struct.pack("<H", 0x0001),  # minimal FCF, nothing else
            "Minimal 802.15.4 frame — parser underflow",
        ))

        return cases

    def generate_all(self) -> List[FuzzCase]:
        cases = []
        cases.extend(self.generate_message_header_fuzz())
        cases.extend(self.generate_pase_fuzz())
        cases.extend(self.generate_case_fuzz())
        cases.extend(self.generate_thread_fuzz())
        return cases



def print_fuzz_results(cases: List[FuzzCase]):
    by_proto = {}
    high_count = sum(1 for c in cases if c.severity == "high")
    cve_count = sum(1 for c in cases if c.cve)

    for c in cases:
        by_proto.setdefault(c.protocol, []).append(c)

    print(f"\n  {'='*70}")
    print(f"  FUZZ CASE GENERATION — {len(cases)} test cases")
    print(f"  {'='*70}")
    print(f"  CVE reproducers: {cve_count} | High severity: {high_count}")

    for proto, proto_cases in by_proto.items():
        print(f"\n  {proto}: {len(proto_cases)} cases")
        for c in proto_cases[:5]:
            sev = "!!!" if c.severity == "high" else "  !"
            cve_tag = f" [{c.cve}]" if c.cve else ""
            print(f"    [{sev}] {c.name}{cve_tag}")
            print(f"         {c.description}")
        if len(proto_cases) > 5:
            print(f"    ... and {len(proto_cases) - 5} more")
