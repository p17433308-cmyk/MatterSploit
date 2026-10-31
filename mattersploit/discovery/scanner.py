"""
Matter mDNS device discovery scanner.

Matter devices advertise via mDNS:
- Operational: _matter._tcp.local (commissioned devices)
- Commissioning: _matterc._udp.local (devices awaiting commissioning)

TXT records carry device type, vendor ID, product ID, discriminator, etc.
"""
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional


MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

MATTER_OPERATIONAL = "_matter._tcp.local"
MATTER_COMMISSIONING = "_matterc._udp.local"

# DNS record types
QTYPE_PTR = 12
QTYPE_SRV = 33
QTYPE_TXT = 16
QTYPE_A = 1
QTYPE_AAAA = 28


@dataclass
class MatterDeviceInfo:
    name: str = ""
    ip_address: str = ""
    port: int = 5540
    service_type: str = ""
    vendor_id: Optional[int] = None
    product_id: Optional[int] = None
    device_type: Optional[int] = None
    discriminator: Optional[int] = None
    pairing_hint: Optional[int] = None
    commissioning_mode: int = 0
    fabric_id: Optional[str] = None
    node_id: Optional[str] = None
    txt_records: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "ip": self.ip_address,
            "port": self.port,
            "service": self.service_type,
            "vendor_id": f"0x{self.vendor_id:04X}" if self.vendor_id else None,
            "product_id": f"0x{self.product_id:04X}" if self.product_id else None,
            "device_type": self.device_type,
            "discriminator": self.discriminator,
            "commissioning_mode": self.commissioning_mode,
            "txt": self.txt_records,
        }


def _build_mdns_query(service_name: str) -> bytes:
    """Build a DNS query packet for mDNS service discovery."""
    # Transaction ID (0 for mDNS), Flags, Questions=1, Answers=0, Auth=0, Additional=0
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)

    # Encode domain name
    qname = b""
    for label in service_name.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"

    # QTYPE=PTR, QCLASS=IN
    question = qname + struct.pack(">HH", QTYPE_PTR, 0x0001)

    return header + question


def _parse_dns_name(data: bytes, offset: int) -> tuple:
    """Parse a DNS name with pointer compression."""
    labels = []
    original_offset = offset
    jumped = False
    max_jumps = 20

    while max_jumps > 0:
        if offset >= len(data):
            break
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            max_jumps -= 1
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def _parse_txt_records(rdata: bytes) -> Dict[str, str]:
    """Parse TXT record data into key=value pairs."""
    records = {}
    pos = 0
    while pos < len(rdata):
        if pos >= len(rdata):
            break
        txt_len = rdata[pos]
        pos += 1
        if pos + txt_len > len(rdata):
            break
        txt = rdata[pos:pos + txt_len].decode("utf-8", errors="replace")
        pos += txt_len
        if "=" in txt:
            k, v = txt.split("=", 1)
            records[k] = v
        else:
            records[txt] = ""
    return records


def _parse_mdns_response(data: bytes) -> List[Dict]:
    """Parse mDNS response packets for Matter device records."""
    if len(data) < 12:
        return []

    _txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    # Response flag must be set
    if not (flags & 0x8000):
        return []

    offset = 12
    # Skip questions
    for _ in range(qdcount):
        _, offset = _parse_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    records = []
    total_records = ancount + nscount + arcount

    for _ in range(total_records):
        if offset + 10 > len(data):
            break

        name, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10

        if offset + rdlength > len(data):
            break

        rdata = data[offset:offset + rdlength]
        offset += rdlength

        record = {"name": name, "type": rtype, "rdata": rdata, "ttl": ttl}

        if rtype == QTYPE_TXT:
            record["txt"] = _parse_txt_records(rdata)
        elif rtype == QTYPE_SRV and len(rdata) >= 6:
            record["priority"] = struct.unpack(">H", rdata[0:2])[0]
            record["weight"] = struct.unpack(">H", rdata[2:4])[0]
            record["port"] = struct.unpack(">H", rdata[4:6])[0]
            target, _ = _parse_dns_name(data, offset - rdlength + 6)
            record["target"] = target
        elif rtype == QTYPE_A and len(rdata) == 4:
            record["address"] = socket.inet_ntoa(rdata)
        elif rtype == QTYPE_PTR:
            ptr_name, _ = _parse_dns_name(data, offset - rdlength)
            record["ptr"] = ptr_name

        records.append(record)

    return records


class MatterScanner:

    def __init__(self, timeout: float = 5.0, interface: str = ""):
        self.timeout = timeout
        self.interface = interface

    def scan(self) -> List[MatterDeviceInfo]:
        """Scan for Matter devices via mDNS."""
        devices = {}

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)

        try:
            sock.bind(("", MDNS_PORT))
        except OSError:
            sock.bind(("", 0))

        # Join multicast group
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0"))
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass

        # Send queries for both operational and commissioning services
        for service in [MATTER_OPERATIONAL, MATTER_COMMISSIONING]:
            query = _build_mdns_query(service)
            try:
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            except OSError:
                pass

        # Collect responses
        start = time.time()
        while time.time() - start < self.timeout:
            try:
                data, (src_ip, src_port) = sock.recvfrom(4096)
                records = _parse_mdns_response(data)
                self._process_records(records, src_ip, devices)
            except socket.timeout:
                break
            except OSError:
                break

        sock.close()
        return list(devices.values())

    def _process_records(self, records: List[Dict], src_ip: str,
                          devices: Dict[str, MatterDeviceInfo]):
        """Extract Matter device info from DNS records."""
        # First pass: collect A/SRV/TXT records
        addresses = {}
        srv_info = {}
        txt_info = {}
        ptr_names = set()

        for r in records:
            if r["type"] == QTYPE_PTR:
                ptr_names.add(r.get("ptr", ""))
            elif r["type"] == QTYPE_A:
                addresses[r["name"]] = r.get("address", src_ip)
            elif r["type"] == QTYPE_SRV:
                srv_info[r["name"]] = {
                    "port": r.get("port", 5540),
                    "target": r.get("target", ""),
                }
            elif r["type"] == QTYPE_TXT:
                txt_info[r["name"]] = r.get("txt", {})

        # Build device entries
        for name in ptr_names | set(srv_info.keys()) | set(txt_info.keys()):
            key = f"{src_ip}:{name}"
            if key not in devices:
                devices[key] = MatterDeviceInfo(name=name, ip_address=src_ip)

            dev = devices[key]

            if MATTER_COMMISSIONING in name:
                dev.service_type = "commissioning"
            elif MATTER_OPERATIONAL in name:
                dev.service_type = "operational"

            if name in srv_info:
                dev.port = srv_info[name]["port"]

            if name in txt_info:
                txt = txt_info[name]
                dev.txt_records = txt
                if "VP" in txt:
                    parts = txt["VP"].split("+")
                    if len(parts) >= 1:
                        try:
                            dev.vendor_id = int(parts[0])
                        except ValueError:
                            pass
                    if len(parts) >= 2:
                        try:
                            dev.product_id = int(parts[1])
                        except ValueError:
                            pass
                if "DT" in txt:
                    try:
                        dev.device_type = int(txt["DT"])
                    except ValueError:
                        pass
                if "D" in txt:
                    try:
                        dev.discriminator = int(txt["D"])
                    except ValueError:
                        pass
                if "CM" in txt:
                    try:
                        dev.commissioning_mode = int(txt["CM"])
                    except ValueError:
                        pass
                if "PH" in txt:
                    try:
                        dev.pairing_hint = int(txt["PH"])
                    except ValueError:
                        pass

            for host in addresses:
                if host in name or name in host:
                    dev.ip_address = addresses[host]


def print_scan_results(devices: List[MatterDeviceInfo]):
    print(f"\n  {'='*70}")
    print(f"  MATTER DEVICE SCAN — {len(devices)} devices found")
    print(f"  {'='*70}")
    if not devices:
        print("\n  [*] No Matter devices found on the network")
        print("  [*] Ensure Matter devices are on the same subnet")
        return
    for d in devices:
        print(f"\n  [{d.service_type.upper()}] {d.name}")
        print(f"    IP:           {d.ip_address}:{d.port}")
        if d.vendor_id:
            print(f"    Vendor ID:    0x{d.vendor_id:04X}")
        if d.product_id:
            print(f"    Product ID:   0x{d.product_id:04X}")
        if d.device_type:
            print(f"    Device Type:  {d.device_type}")
        if d.discriminator is not None:
            print(f"    Discriminator: {d.discriminator}")
        if d.commissioning_mode:
            print(f"    Commissioning: Mode {d.commissioning_mode} (OPEN)")
        if d.txt_records:
            print(f"    TXT:          {d.txt_records}")
