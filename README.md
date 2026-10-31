# MatterSploit — Matter/Thread Offensive Security Framework

**The first offensive security framework for the Matter smart home protocol and Thread mesh networks.**

Matter is the unified smart home protocol adopted by **Apple, Google, Amazon, and Samsung** — deployed on hundreds of millions of devices. MatterSploit provides attack, fuzzing, and forensic capabilities for security researchers.

## Why This Matters

| Attack | Auth Required | Impact | CVE |
|--------|:---:|--------|-----|
| **MaDoS** — Status Report flood | **None** | Network-wide device communication failure | ASIACCS 2026 |
| **CASE Session Exhaustion** | **None** | Block all new secure sessions | — |
| **PASE PBKDF Flood** | **None** | Block device commissioning + CPU exhaustion | — |
| **Counter Desync** | **None** | Reject legitimate messages from controllers | — |
| **Thread Beacon Spoof** | **None** | Lure devices to fake mesh network | — |
| **Subscribe Flood** | **None** | Exhaust Interaction Model subscription slots | — |
| **SDK Crash** (CVE-2025-56364) | **None** | SIGABRT via uninitialized group ID | CVE-2025-56364 |
| **SDK Crash** (CVE-2025-56365) | **None** | SIGABRT via nonexistent endpoint | CVE-2025-56365 |

**Key finding:** Multiple devastating attacks require **zero authentication** — an attacker on the local network with no keys or commissioning can disrupt all Matter devices.

## Features

### Attacks — Matter
- **MaDoS** — Unencrypted/unauthenticated Status Report flood → network-wide DoS
- **Message Counter Desync** — Spoof counter sync → legitimate messages rejected
- **PASE PBKDF Flood** — Exhaust commissioning session slots + CPU
- **CASE Sigma1 Flood** — Exhaust secure session table → no new connections

### Attacks — Thread
- **Beacon Spoofing** — Lure scanning devices to fake mesh network
- **MLE Discovery Flood** — Exhaust Border Router CPU via unencrypted discovery
- **PAN ID Conflict** — Trigger network-wide PAN ID migration

### Attacks — BLE Commissioning
- **Advertisement Spoofing** — Craft fake Matter BLE advertisements (UUID 0xFFF6)
- **Passcode Bruteforce Analysis** — Estimate 20-bit passcode search space
- **PASE BLE Flood** — Flood BLE transport with PASE handshake requests

### Attacks — Interaction Model
- **Subscribe Flood** — Exhaust device subscription slots (3-5 per device)
- **Attribute Enumeration** — Discover all clusters, attributes, and endpoints
- **Door Lock Unlock** — Send unlock commands to door lock clusters
- **Thermostat Setpoint** — Manipulate heating/cooling setpoints
- **Toggle Flood** — Rapid on/off cycling of smart devices
- **Timed Interaction Race** — Race condition in timed write/invoke flows
- **ACL Probe** — Enumerate Access Control List entries

### Protocol Fuzzing
- **Matter message header** — version, flags, session ID, counter boundaries
- **PASE (commissioning)** — PBKDF iterations, invalid EC points, empty PAKE
- **CASE (sessions)** — oversized Sigma1, invalid certs, session resume
- **Thread (802.15.4/MLE)** — oversized frames, invalid MLE versions
- **CVE reproducers** — CVE-2025-56364 and CVE-2025-56365

### mDNS Discovery
- **Device scanning** — Discover Matter devices via _matter._tcp.local and _matterc._udp.local
- **TXT record parsing** — Extract vendor ID, product ID, device type, discriminator
- **DNS pointer compression** — Full mDNS response parsing with name compression

### Forensic Collection
- **Passive traffic analysis** — Capture and decode Matter messages on UDP 5540
- **Device fingerprinting** — Identify vendors, products, firmware
- **Anomaly detection** — Detect MaDoS, session floods, counter attacks, rogue fabrics
- **Threat hunting** — Monitor for beacon spoofing, unknown nodes, counter near-max

## Quick Start

```bash
pip install -e .

# Full demo (real packet construction, fuzzing, forensic analysis)
mattersploit demo

# Live MaDoS attack
mattersploit attack -t 192.168.1.100 --attack mados --count 1000

# CASE session exhaustion
mattersploit attack -t 192.168.1.100 --attack case-flood --count 500

# Thread beacon spoofing with pcap export
mattersploit attack --attack beacon-spoof --pcap beacon.pcap

# Interaction Model attacks
mattersploit interact -t 192.168.1.100 --attack subscribe-flood --count 100
mattersploit interact -t 192.168.1.100 --attack enumerate
mattersploit interact -t 192.168.1.100 --attack unlock

# BLE commissioning attacks
mattersploit ble --attack spoof --discriminator 0xABC
mattersploit ble --attack bruteforce

# Generate fuzz cases
mattersploit fuzz -o fuzz_cases.json

# Discover Matter devices
mattersploit scan --timeout 10

# Forensic capture
mattersploit forensics --duration 30 -o report.json
```

## Architecture

```
mattersploit/
├── protocols/
│   ├── matter.py              # Matter message framing, TLV encoding, session types
│   └── thread.py              # IEEE 802.15.4, MLE, Thread beacon structures
├── attacks/
│   ├── matter_attacks.py      # MaDoS, session flood, counter desync, Thread attacks
│   ├── ble_attacks.py         # BLE advertisement spoofing, PASE flood, bruteforce
│   ├── interaction_attacks.py # Subscribe flood, enumeration, door lock, thermostat, ACL
│   └── fuzzer.py              # Grammar-aware Matter/PASE/CASE/Thread fuzzer with CVE repros
├── discovery/
│   └── scanner.py             # mDNS device discovery with full DNS parsing
├── forensics/
│   └── collector.py           # Passive collection, device fingerprinting, anomaly detection
└── cli.py                     # CLI: attack / fuzz / forensics / scan / ble / interact / demo
```

## Dependencies

**None** — pure Python standard library. No third-party packages required.

## Tests

```bash
pytest tests/     # builders, attacks, fuzzing, forensics, BLE, mDNS, interaction model
```

## References

- Matter Specification v1.3 (Connectivity Standards Alliance)
- MaDoS: Matter Denial of Service (ASIACCS 2026)
- CVE-2025-56364: Matter SDK uninitialized group ID
- CVE-2025-56365: Matter SDK assertion on nonexistent endpoint
- OpenThread radio frame vulnerability disclosure
- Thread Specification v1.3.0 (Thread Group)

## Responsible Use

This tool is for **authorized security testing only**. Use it on:
- Your own Matter/Thread devices and infrastructure
- Authorized penetration testing engagements
- The built-in `demo` command (no target device needed)

## License

MIT
