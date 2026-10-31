"""MatterSploit integration tests — Matter messages, TLV, forensics, interaction model."""
import struct
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mattersploit.protocols.matter import (
    build_matter_message, build_status_report, build_message_header,
    parse_message_header, encode_tlv_unsigned, encode_tlv_bytes, encode_tlv_string,
    MatterMessageHeader, PROTOCOL_ID_SECURE_CHANNEL, PROTOCOL_ID_INTERACTION_MODEL,
    MessageType, StatusCode, TLVType, InteractionType,
)


class TestMatterMessage:
    def test_message_header_roundtrip(self):
        # Use source_node to ensure flags set correctly for parsing
        hdr = MatterMessageHeader(session_id=0x1234, message_counter=0xDEADBEEF,
                                    flags=0x00, source_node_id=1)
        data = build_message_header(hdr)
        parsed = parse_message_header(data)
        assert parsed is not None
        assert parsed["session_id"] == 0x1234
        assert parsed["message_counter"] == 0xDEADBEEF

    def test_message_with_source_node(self):
        hdr = MatterMessageHeader(session_id=1, message_counter=1,
                                    source_node_id=0x0102030405060708)
        data = build_message_header(hdr)
        parsed = parse_message_header(data)
        assert parsed["source_node"] == 0x0102030405060708

    def test_full_message(self):
        msg = build_matter_message(
            session_id=0, message_counter=42,
            protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
            opcode=MessageType.STATUS_REPORT,
            payload=build_status_report(1, 0, 0),
        )
        assert len(msg) > 16

    def test_status_report_structure(self):
        sr = build_status_report(1, PROTOCOL_ID_INTERACTION_MODEL, StatusCode.BUSY)
        assert len(sr) == 10
        general_code = struct.unpack("<I", sr[0:4])[0]
        assert general_code == 1


class TestTLVEncoding:
    def test_unsigned_1byte(self):
        data = encode_tlv_unsigned(1, 42)
        assert len(data) == 3
        base = data[0] >> 2
        size_bits = data[0] & 0x03
        assert base == TLVType.UNSIGNED_INT
        assert size_bits == 0x00  # 1-byte
        assert data[2] == 42

    def test_unsigned_2byte(self):
        data = encode_tlv_unsigned(1, 0x1234)
        size_bits = data[0] & 0x03
        assert size_bits == 0x01  # 2-byte
        val = struct.unpack("<H", data[2:4])[0]
        assert val == 0x1234

    def test_unsigned_4byte(self):
        data = encode_tlv_unsigned(1, 0x12345678)
        size_bits = data[0] & 0x03
        assert size_bits == 0x02  # 4-byte
        val = struct.unpack("<I", data[2:6])[0]
        assert val == 0x12345678

    def test_unsigned_8byte(self):
        data = encode_tlv_unsigned(1, 0x123456789ABCDEF0)
        size_bits = data[0] & 0x03
        assert size_bits == 0x03  # 8-byte
        val = struct.unpack("<Q", data[2:10])[0]
        assert val == 0x123456789ABCDEF0

    def test_bytes_encoding(self):
        data = encode_tlv_bytes(1, b"\xDE\xAD\xBE\xEF")
        assert b"\xDE\xAD\xBE\xEF" in data

    def test_string_encoding(self):
        data = encode_tlv_string(1, "hello")
        assert b"hello" in data


class TestForensics:
    def test_collector_processes_packets(self):
        from mattersploit.forensics.collector import MatterForensicCollector
        collector = MatterForensicCollector()
        # Feed a MaDoS packet
        status_payload = build_status_report(1, PROTOCOL_ID_INTERACTION_MODEL, StatusCode.BUSY)
        pkt = build_matter_message(
            session_id=0, message_counter=1,
            protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
            opcode=MessageType.STATUS_REPORT,
            payload=status_payload,
        )
        collector.process_packet(pkt, "10.0.0.1", 5540)
        report = collector.generate_report()
        assert report["summary"]["total_messages"] >= 1

    def test_counter_desync_detection(self):
        from mattersploit.forensics.collector import MatterForensicCollector
        collector = MatterForensicCollector()
        pkt = build_matter_message(
            session_id=0, message_counter=0xFFFFFFFE,
            protocol_id=PROTOCOL_ID_SECURE_CHANNEL,
            opcode=MessageType.MSG_COUNTER_SYNC_REQ,
            payload=b"\x00" * 8,
        )
        collector.process_packet(pkt, "10.0.0.2", 5540)
        report = collector.generate_report()
        anomalies = [a for a in report["anomalies"] if a["type"] == "counter_near_max"]
        assert len(anomalies) >= 1


class TestInteractionAttacks:
    def test_read_request_builder(self):
        from mattersploit.attacks.interaction_attacks import build_read_request
        payload = build_read_request([(1, 0x0006, 0x0000)])
        assert len(payload) > 0

    def test_subscribe_request_builder(self):
        from mattersploit.attacks.interaction_attacks import build_subscribe_request
        payload = build_subscribe_request([(1, 0x0006, 0x0000)], 0, 60)
        assert len(payload) > 0

    def test_invoke_request_builder(self):
        from mattersploit.attacks.interaction_attacks import build_invoke_request
        payload = build_invoke_request(1, 0x0006, 0x02)
        assert len(payload) > 0

    def test_interaction_attacks_class(self):
        from mattersploit.attacks.interaction_attacks import InteractionAttacks
        ia = InteractionAttacks("127.0.0.1", 5540)
        result = ia.subscribe_flood(endpoint=1, count=10)
        assert result.success
        assert result.packets_sent == 10
        assert len(result.frames) == 10

    def test_door_lock_attack(self):
        from mattersploit.attacks.interaction_attacks import InteractionAttacks
        ia = InteractionAttacks()
        result = ia.door_lock_unlock()
        assert result.success
        assert len(result.frames) == 1


class TestBLEAttacks:
    def test_spoofed_adv_builder(self):
        from mattersploit.attacks.ble_attacks import build_spoofed_matter_adv, parse_matter_ble_adv
        adv = build_spoofed_matter_adv(discriminator=0xABC, vendor_id=0x1234, product_id=0x5678)
        parsed = parse_matter_ble_adv(adv)
        assert parsed is not None
        assert parsed.discriminator == 0xABC

    def test_ble_attacks_class(self):
        from mattersploit.attacks.ble_attacks import BLEAttacks
        ba = BLEAttacks()
        result = ba.adv_spoof(count=5)
        assert result.success
        assert result.packets_sent == 5


class TestMDNSScanner:
    def test_mdns_query_builder(self):
        from mattersploit.discovery.scanner import _build_mdns_query
        query = _build_mdns_query("_matter._tcp.local")
        assert len(query) > 12
        # Should be a valid DNS query
        qdcount = struct.unpack(">H", query[4:6])[0]
        assert qdcount == 1

    def test_txt_record_parser(self):
        from mattersploit.discovery.scanner import _parse_txt_records
        # Build TXT record: length + "VP=1234+5678"
        txt = b"\x0CVP=1234+5678"
        records = _parse_txt_records(txt)
        assert records["VP"] == "1234+5678"


class TestExports:
    def test_all_exports(self):
        import mattersploit
        assert len(mattersploit.__all__) >= 30
        for name in mattersploit.__all__:
            assert hasattr(mattersploit, name)

    def test_version(self):
        import mattersploit
        assert mattersploit.__version__ == "1.0.0"


class TestThreadProtocol:
    def test_beacon_builder(self):
        from mattersploit.protocols.thread import build_thread_beacon, ThreadBeacon
        beacon = ThreadBeacon()
        data = build_thread_beacon(beacon)
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_mle_discovery(self):
        from mattersploit.protocols.thread import build_mle_discovery_request
        data = build_mle_discovery_request()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_ieee802154_frame(self):
        from mattersploit.protocols.thread import build_ieee802154_frame, IEEE802154Frame
        frame = IEEE802154Frame(payload=b"\x00" * 10)
        data = build_ieee802154_frame(frame)
        assert isinstance(data, bytes)


class TestFuzzer:
    def test_generate_all(self):
        from mattersploit.attacks.fuzzer import MatterFuzzer
        fuzzer = MatterFuzzer()
        cases = fuzzer.generate_all()
        assert len(cases) >= 10
        for c in cases:
            assert len(c.data) > 0
            assert c.name
            assert c.protocol

    def test_cve_reproducers(self):
        from mattersploit.attacks.fuzzer import MatterFuzzer
        fuzzer = MatterFuzzer()
        cases = fuzzer.generate_all()
        cve_cases = [c for c in cases if c.cve]
        assert len(cve_cases) >= 2
