<div align="center">

# Leetha

### Passive Network Fingerprinting and Analysis Engine

[![CI](https://github.com/tjnull/leetha/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tjnull/leetha/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/tjnull/leetha/releases)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Tests](https://img.shields.io/badge/tests-551%20passing-brightgreen.svg)](#testing)

</div>

**Leetha identifies devices on your network by analyzing broadcast traffic and protocol exchanges** -- combining passive observation with active service probing to build a comprehensive device inventory, detect anomalies, and map your attack surface. No agents, no credentials, no device cooperation required.

> *Named after **K7-Leetha**, the sentient necroplasmic symbiote from Todd McFarlane's Spawn. The suit bonds with its host, silently observing and adapting to every threat in its environment -- much like this tool bonds with your network, passively learning every device and anomaly without ever revealing its presence.*

---

## Why Leetha

- **Passive-first design** -- identifies devices without sending a single packet; active probing is optional
- **Multi-evidence fusion** -- weighted certainty scoring across 15+ protocol sources with agreement boosting when independent sources corroborate
- **mDNS SRV target extraction** -- captures device hostnames, service ports, model names, and HomeKit categories from SRV/TXT records
- **Infrastructure-aware mDNS filtering** -- automatically detects routers/gateways/APs and suppresses forwarded multicast that would pollute device identity
- **30 protocol banner matchers** -- passively reads service banners (SSH, MySQL, SMB, RDP, MQTT, RTSP, and more) from observed traffic
- **315 active probe plugins** -- protocol-specific request/response parsing, not just banner grabs
- **11.5 million fingerprint signatures** -- synced from 12 upstream databases including IEEE OUI, Huginn-Muninn, Satori, p0f, JA3/JA4
- **Real-time web dashboard** -- host inventory with numeric IP sorting, live packet stream, network topology, and attack surface analysis via WebSocket
- **PCAP import** -- import captured traffic from Wireshark or tcpdump for offline analysis through the full fingerprinting pipeline
- **Behavioral detection** -- DNS vendor affinity drift, identity shift alerts, MAC spoofing detection, DHCP anomaly analysis
- **OT / ICS / SCADA support** -- passive identification of Modbus, BACnet, EtherNet/IP, CoAP, MQTT, and industrial device fingerprinting
- **Auth & notifications** -- token-based API authentication with role-based access control; alert notifications via Apprise (Slack, email, webhooks, and 80+ services)

## How It Works

```
Network Traffic
      |
      v
Capture Engine -----> Parser Chain (20 protocol parsers)
(per-interface          |
 scapy threads)    CapturedPacket
                        |
                Registry-Based Processors
                (Network, Services, Names,
                 Infrastructure, IoT/SCADA,
                 Banners, Behavioral)
                        |
                     Evidence
                        |
                  Verdict Engine
            (weighted certainty fusion
             + agreement boosting)
                        |
           +------------+------------+
           v            v            v
      Host Store   Finding Rules  Active Probes
      (SQLite)     (8 rule types) (315 plugins)
           |
      Web Dashboard / Console / API
```

1. **Capture** -- per-interface threads with BPF filters parse traffic through an ordered protocol chain
2. **Process** -- registered processors extract evidence from captured packets
3. **Fuse** -- verdict engine combines all evidence per host using weighted certainty and agreement boosting
4. **Store** -- host identity, evidence chain, and findings persisted to SQLite with configurable retention
5. **Detect** -- finding rules evaluate each host for anomalies, spoofing, and identity drift
6. **Probe** -- optional active probing sends protocol-specific requests for service confirmation

## Quick Start

Requires **Python 3.11+** and packet capture privileges (root, sudo, or `CAP_NET_RAW`).

```bash
# Install from source
git clone https://github.com/tjnull/leetha.git && cd leetha
cd frontend && bun install && bun run build && cd ..
pipx install -e .  # or: pip install -e .

# Sync fingerprint databases (recommended, ~880 MB)
leetha sync

# Launch the web dashboard
sudo $(which leetha) --web

# Interactive console on a specific interface
sudo $(which leetha) -i eth0

# Multi-interface capture
sudo $(which leetha) -i eth0 -i wlan0
```

Open `https://localhost` to view discovered devices in real-time.

## Installation

### From source (pipx — recommended)

```bash
git clone https://github.com/tjnull/leetha.git
cd leetha

# Build the frontend (requires bun — https://bun.sh)
cd frontend && bun install && bun run build && cd ..

# Install with pipx (isolated environment, editable)
pipx install -e .

# Or install with pip
pip install -e .
```

### Docker

```bash
# Build locally (includes frontend build)
docker build -t leetha .
docker run --net=host --cap-add=NET_RAW --cap-add=NET_BIND_SERVICE leetha --web
```

The Docker image exposes port 443 (HTTPS) by default and adds `cap_net_bind_service` for binding to privileged ports.

### Docker Compose

```bash
docker compose up -d
```

## Capture Privileges

Leetha needs raw socket access to capture network traffic. There are three ways to grant this:

### Option 1: Linux capabilities (recommended)

Grant `CAP_NET_RAW` to the Python binary. Leetha runs as your normal user -- no root, no sudo, no file ownership issues.

```bash
# Find your Python binary
which python3

# Grant capture capability
sudo setcap cap_net_raw+ep $(which python3)

# Run leetha without sudo
leetha --web -i eth0
```

To remove the capability later:

```bash
sudo setcap -r $(which python3)
```

### Option 2: sudo

Use `$(which leetha)` because sudo resets your PATH and won't find user-installed commands.

```bash
sudo $(which leetha) --web -i eth0
```

When running under sudo, leetha automatically chowns its data directory back to the original user (via `SUDO_UID`/`SUDO_GID`) so files remain accessible without sudo on subsequent runs.

### Option 3: Docker

Docker with `--cap-add=NET_RAW` and `--net=host` gives the container capture access without granting root to the host.

```bash
docker run -d \
  --name leetha \
  --net=host \
  --cap-add=NET_RAW \
  -v leetha-data:/home/appuser/.leetha \
  ghcr.io/tjnull/leetha:latest --web
```

### macOS

On macOS, packet capture requires access to BPF devices. Run with sudo or adjust BPF permissions:

```bash
# With sudo
sudo leetha --web -i en0

# Or grant BPF access to your user (persistent across reboots)
sudo chgrp staff /dev/bpf*
sudo chmod g+r /dev/bpf*
```

### Windows

Windows requires [Npcap](https://npcap.com) installed for packet capture. Download and install Npcap, then run leetha from an Administrator command prompt. The live terminal viewer is not available on Windows -- use `--web` for the dashboard.

## Network Stack Analysis

| Layer | Protocol | Leetha Analysis |
|-------|----------|-----------------|
| 2 | Ethernet | ARP bindings, MAC vendor resolution, randomization detection |
| 2 | LLDP, CDP, STP | Switch/AP/router identification, network topology |
| 3 | ICMPv6 | Router advertisements, neighbor discovery, IPv6 host detection |
| 4 | TCP SYN | p0f-style OS fingerprinting (TTL, window, MSS, options) |
| 4 | TCP Banners | Passive service identification from 30 protocols (SSH, MySQL, SMB, RDP, ...) |
| 7 | DHCPv4 / DHCPv6 | Device fingerprinting via Option 55/60, vendor class, ORO, DUID |
| 7 | DNS / mDNS | Hostname resolution, vendor affinity profiling, exclusive service detection |
| 7 | SSDP / WS-Discovery | UPnP device type, manufacturer, model identification |
| 7 | TLS ClientHello | JA3 and JA4 fingerprinting, SNI extraction |
| 7 | HTTP | User-Agent parsing, platform and browser detection |
| 7 | SNMP | System description, OID-based device classification |
| 7 | MQTT, CoAP, Modbus, BACnet, EtherNet/IP | IoT and OT device identification |
| 7 | SIP, RTSP | VoIP phone and IP camera detection |
| 7 | LLMNR / NetBIOS | Windows hostname and workgroup resolution |

## Detection Capabilities

### Device Categories

| Category | Examples |
|----------|----------|
| **Network Infrastructure** | Routers, switches, access points, firewalls, load balancers, mesh routers |
| **Compute** | Servers, workstations, laptops, desktops, hypervisors, virtual machines, containers, cloud instances |
| **Mobile** | Phones, tablets (Apple, Android, Windows with MAC randomization handling) |
| **OT / ICS / SCADA** | PLCs (Siemens S7, Allen-Bradley, Beckhoff), RTUs, HMIs, building automation controllers, EV charging stations |
| **IoT / Smart Home** | Cameras, doorbells, thermostats, smart locks, smart plugs, smart lighting, robot vacuums, sensors |
| **Entertainment** | Smart TVs (Samsung, LG, Roku), game consoles, streaming devices, media players, smart speakers |
| **Storage** | NAS devices (Synology, QNAP, TrueNAS, Unraid, OpenMediaVault) |
| **Printers** | Network printers, scanners (IPP, JetDirect, LPD) |
| **VoIP** | IP phones, PBX systems, SIP endpoints |
| **Security** | Docker APIs (unencrypted), Kubernetes APIs, SOCKS proxies, VPN concentrators |

### Passive Banner Identification

Leetha passively captures service banners from observed TCP traffic without sending any packets:

| Protocol | Ports | What Is Identified |
|----------|-------|--------------------|
| SSH | 22 | Software, version, OS hints (OpenSSH, Dropbear) |
| MySQL / MariaDB | 3306 | Server version, auth plugin, MariaDB detection |
| PostgreSQL | 5432 | Server version from ParameterStatus |
| MSSQL | 1433 | TDS prelogin response |
| MongoDB | 27017 | Wire protocol version, server version |
| Redis | 6379 | RESP protocol, version from INFO |
| SMB | 445, 139 | SMB1/SMB2 dialect, server GUID |
| RDP | 3389 | X.224 negotiation, NLA/TLS capability |
| SMTP | 25, 465, 587 | MTA software (Postfix, Exim, Exchange) |
| IMAP / POP3 | 143, 110 | Server software (Dovecot, Cyrus) |
| FTP | 21 | Server software and version |
| MQTT | 1883 | CONNACK response, broker identification |
| RTSP | 554 | IP camera detection (Hikvision, Dahua, Axis) |
| SIP | 5060 | VoIP phone vendor identification |
| LDAP | 389, 636 | Directory server detection |
| Elasticsearch | 9200 | Cluster name, version |
| Docker API | 2375 | API version, OS (security finding if unencrypted) |
| SOCKS | 1080 | Proxy detection (SOCKS4/5), open proxy finding |
| BGP | 179 | Router identification, AS number extraction |
| VNC, Telnet, IRC | Various | Protocol version, login banners |

### Finding Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `new_host` | INFO | New device discovered on the network |
| `identity_shift` | CRITICAL / HIGH | Device fingerprint class changed (category, vendor, or platform) |
| `addr_conflict` | WARNING | Multiple MACs claiming the same IP address |
| `low_certainty` | INFO | Device identification below confidence threshold |
| `stale_source` | INFO | Evidence source has not been seen recently |
| `randomized_addr` | INFO | MAC address randomization detected |
| `dhcp_anomaly` | HIGH | Rogue DHCP server, starvation attack, or relay-agent injection |
| `behavioral_drift` | WARNING | DNS vendor affinity shifted from one ecosystem to another |

### Fingerprint Sources

| Source | Records | Data Provided |
|--------|---------|---------------|
| Huginn-Muninn MAC Vendors | 10.1M | MAC to vendor/device mapping |
| Huginn DHCP Vendors | 425K | DHCP vendor class identifiers |
| Huginn DHCP Signatures | 368K | DHCP option fingerprints |
| Huginn-Muninn Devices | 116K | Device profiles (model, category, OS) |
| IEEE OUI | 86K+ | MAC manufacturer lookup |
| Huginn DHCPv6 Enterprise | 58K | DHCPv6 enterprise identifiers |
| IANA Enterprise Numbers | 50K+ | SNMP/protocol enterprise OIDs |
| Huginn DHCPv6 | 40K | DHCPv6 fingerprints |
| JA3 TLS Fingerprints | Database | TLS client identification with matching |
| JA4+ TLS Fingerprints | Database | Modern TLS client identification with matching |
| p0f TCP Signatures | Database | TCP/IP stack OS fingerprinting |
| Custom Vendor Patterns | 4,645 | Banner and protocol-specific identification |

## Architecture

```
src/leetha/
  capture/
    engine.py            Packet capture (per-interface scapy threads, BPF filters)
    protocols/           20 protocol parsers (ARP, DHCP, DNS, TLS, L2, banners, ...)
    banner/              Passive TCP banner capture (30 service matchers, connection tracking)
    dedup.py             TTL-based LRU deduplication cache
  processors/            Registry-based packet processors
    network.py           ARP, DHCP, DHCPv6, ICMPv6 discovery
    services.py          TCP SYN, TLS, HTTP User-Agent fingerprinting
    names.py             DNS, mDNS, SSDP, NetBIOS hostname/service resolution
    infrastructure.py    LLDP, CDP, STP, SNMP network device identification
    iot_scada.py         Modbus, BACnet, CoAP, MQTT, EtherNet/IP
    banner.py            Passive service banner evidence emission
    behavioral.py        DNS vendor affinity tracking
  evidence/              Evidence models and verdict computation engine
  fingerprint/           Device identification, OS intelligence, MAC analysis
  patterns/              JSON pattern loader, compiled regex matching, category index
  rules/                 Finding rules (identity shift, behavioral drift, DHCP anomaly, ...)
  probe/                 315 active service identification plugins
  store/                 SQLite persistence with retention policies
  analysis/              Attack surface analysis, spoofing detection, DHCP anomaly detection
  sync/                  Fingerprint database sync with streaming JSON parsers
  topology.py            Network topology graph (gateway, core switch, AP, VM detection)
  pipeline.py            MAC-sharded packet dispatch with bounded queues
  ui/
    web/                 FastAPI dashboard with WebSocket real-time updates
    live.py              Live packet stream viewer
  console.py             Interactive REPL console
  cli.py                 Entry point and argument parsing
```

## Performance and Resource Management

| Component | Mechanism | Bound |
|-----------|-----------|-------|
| Worker queues | Bounded asyncio queues, drop-and-count on overflow | 10K packets per shard |
| Packet dedup | TTL-based LRU cache (300s TTL, 50K entries) | Stable memory, no state loss |
| Pattern matching | Pre-compiled regexes with category-indexed lookup | O(k) per match, not O(n) |
| Evidence chains | Capped at 20 per source, 200 total per device | Bounded per host |
| Database | Configurable retention (7d observations, 30d alerts) | Pruned periodically |
| Sync downloads | Streaming JSON parsers (ijson support) | O(item) memory, not O(file) |
| Batch writes | Grouped SQLite transactions (50 ops, 100ms window) | Amortized I/O |

## Testing

```bash
# Run full test suite
PYTHONPATH=src python -m pytest spec/ -v

# Run specific test group
PYTHONPATH=src python -m pytest spec/capture/ -v
PYTHONPATH=src python -m pytest spec/processors/ -v
PYTHONPATH=src python -m pytest spec/evidence/ -v
```

## Documentation

See [docs/wiki/](docs/wiki/Home.md) for detailed guides:

- [Getting Started](docs/wiki/Getting-Started.md)
- [How It Works](docs/wiki/How-It-Works.md)
- [Passive Network Discovery](docs/wiki/Passive-Network-Discovery.md)
- [Active Probing](docs/wiki/Active-Probing.md)
- [Fingerprint Sources](docs/wiki/Fingerprint-Sources.md)
- [CLI Reference](docs/wiki/CLI-Reference.md)
- [Web Dashboard](docs/wiki/Web-Dashboard.md)
- [Remote Sensors](docs/wiki/Remote-Sensors.md)
- [Attack Surface Analysis](docs/wiki/Attack-Surface-Analysis.md)
- [Spoofing Detection](docs/wiki/Spoofing-Detection.md)

## Disclaimer

Leetha is a passive network analysis tool intended for **authorized use only** on networks you own or have explicit written permission to monitor.


- **No warranty.** This tool is provided as-is for educational, research, and defensive security purposes. The authors assume no liability for misuse, false positives, missed detections, or any actions taken based on its output.
- **Legal compliance required.** Unauthorized network monitoring may violate local, state, or federal law. Passive packet capture in promiscuous mode may be subject to wiretapping statutes in some jurisdictions. Always ensure compliance with applicable regulations, organizational policies, and rules of engagement before deploying.
- **Not a substitute for professional assessment.** Leetha is a supplementary tool for network visibility. It does not replace vulnerability scanners, penetration tests, or qualified security assessments.

## Credits

### Upstream Data Sources

Leetha's fingerprinting accuracy depends on data generously maintained by these projects:

- **[Huginn-Muninn](https://github.com/Ringmast4r/Huginn-Muninn)** by **[Ringmast4r](https://github.com/Ringmast4r)** -- MAC vendor database, DHCP fingerprints, device hierarchy, and DHCPv6 patterns. The backbone of leetha's device identification.
- **[IEEE OUI Registry](https://standards-oui.ieee.org/)** -- Official MAC address manufacturer assignments.
- **[p0f](https://lcamtuf.coredump.cx/p0f3/)** -- TCP/IP stack fingerprinting signatures by Michal Zalewski. The foundation for passive OS detection.
- **[JA3](https://github.com/salesforce/ja3)** -- TLS client fingerprinting method by Salesforce.
- **[JA4+](https://github.com/FoxIO-LLC/ja4)** -- Next-generation TLS fingerprinting by FoxIO, LLC. JA4 methodology and specification are Copyright (c) 2023, FoxIO, LLC.
- **[IANA](https://www.iana.org/assignments/enterprise-numbers/)** -- Enterprise number assignments for SNMP and protocol OIDs.

### Inspiration

- **[p0f](https://lcamtuf.coredump.cx/p0f3/)** by Michal Zalewski -- pioneered passive TCP/IP fingerprinting. Leetha's TCP SYN analysis draws from p0f's methodology.


## License

[GNU General Public License v3.0](LICENSE)
</div>
