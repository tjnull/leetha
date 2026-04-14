# Leetha

**Registry-driven network reconnaissance through passive traffic analysis.**

Leetha watches network traffic to build a detailed inventory of every device on the wire. Rather than scanning or probing, it intercepts protocol exchanges that devices already produce -- DHCP negotiations, multicast announcements, TLS handshakes, ARP broadcasts, and more -- then runs each captured packet through a chain of registered processors that extract, correlate, and score device attributes. The result is a continuously updated map of hosts, operating systems, services, and security exposures.

Beyond identification, Leetha applies `FindingRule` evaluations (registered via `@register_rule`) against accumulated evidence to surface attack opportunities. Each rule references concrete network observations and outputs actionable tool commands for penetration testers.

---

## Get Running in 60 Seconds

```bash
pipx install leetha                # pull the package
leetha sync                        # fetch reference databases (~880 MB, optional)
leetha start web                   # open the React dashboard at https://localhost
```

Detailed walkthrough: [Getting Started](Getting-Started.md)

---

## Wiki Navigation

- [Getting Started](Getting-Started.md) -- Setup, first capture, adapter selection, configuration knobs
- [CLI Reference](CLI-Reference.md) -- Every command, flag, and subcommand with usage examples
- [How It Works](How-It-Works.md) -- PacketCapture, PARSER_CHAIN, ProcessorRegistry, VerdictEngine, Store
- [Fingerprint Sources](Fingerprint-Sources.md) -- The 12 upstream databases and the PatternLoader pipeline
- [Passive Network Discovery](Passive-Network-Discovery.md) -- Processor-based evidence extraction from ambient traffic
- [Active Probing](Active-Probing.md) -- ServiceProbe interface, ServiceConnection, identify() method
- [PCAP Import](PCAP-Import.md) -- Import captured traffic for offline analysis through the fingerprinting pipeline
- [Web Dashboard](Web-Dashboard.md) -- React frontend pages, REST API, WebSocket events
- [Attack Surface Analysis](Attack-Surface-Analysis.md) -- FindingRules, chain activation, tool command templates
- [Remote Sensors](Remote-Sensors.md) -- Build, deploy, and manage remote packet capture sensors
- [Interface Types & VPN Capture](Interface-Types-VPN-Capture.md) -- NetworkAdapter, AdapterConfig, scan_adapters
- [Spoofing Detection](Spoofing-Detection.md) -- AddressVerifier, addr_conflict finding, trusted binding management
- [Authentication](Authentication.md) -- Token-based API security, roles, and token management
- [Notifications](Notifications.md) -- Alert notifications via Apprise (Slack, email, webhooks, 80+ services)

---

## What Leetha Provides

**Protocol coverage** -- 11 dissectors handle TCP SYN, DHCPv4/v6, mDNS, DNS (with IPv6 support), SSDP (including M-SEARCH requests), LLMNR, NetBIOS NS, TLS ClientHello (including detection on non-standard ports), ARP, and ICMPv6 (including Router Solicitation) packets.

**Processor architecture** -- Every analysis step is a processor registered with `@register_processor` in the `ProcessorRegistry`. Processors emit `Evidence` objects that the `VerdictEngine` fuses into a final `Verdict` per host.

**Reference data** -- 12 community databases (IEEE OUI, Huginn-Muninn, p0f, JA3, JA4+) totaling ~880 MB, loaded on demand by `PatternLoader` from JSON files under `patterns/data/`.

**Service identification** -- 300+ `ServiceProbe` plugins connect via `ServiceConnection` and call `identify(conn)` to return a `ServiceIdentity` with version strings and protocol metadata.

**Security assessment** -- 35 rules (23 passive, 12 service-based) registered with `@register_rule` produce findings stored in `FindingRepository`. A chain builder links related findings into multi-step attack playbooks.

**Persistent storage** -- The `Store` facade exposes `HostRepository`, `FindingRepository`, and other repositories backed by async SQLite.

**Vendor enrichment** -- 86,000+ IEEE OUI records plus 1,900+ curated vendor patterns with device type, category, and model metadata.

**MAC randomization handling** -- Locally-administered bit detection with behavioral correlation to group multiple random addresses belonging to the same physical device. mDNS exclusive services and DHCP Option 61 (Client-ID) provide vendor identification even when the OUI is randomized.

**Identity shift and behavioral drift detection** -- The `AddressVerifier` compares full fingerprint classes (category, vendor, platform) against stored verdicts to detect MAC spoofing and device substitution. DNS vendor affinity tracking monitors behavioral drift over adaptive time windows.

**Container, VM, and cloud awareness** -- 39 cloud/VM/IoT MAC OUI prefixes are recognized, covering Docker (`02:42`), VMware (`00:50:56`, `00:0C:29`), QEMU (`52:54:00`), Hyper-V, VirtualBox, cloud provider virtual NICs, and common IoT platform prefixes. These are excluded from randomized MAC classification and receive appropriate device type attribution.

**Multi-adapter support** -- Parallel capture across physical, tap, and tun adapters with per-adapter BPF filters and type-aware rule suppression.

## System Requirements

- Python 3.11 or newer
- Linux with raw socket support (scapy)
- Root privileges or `CAP_NET_RAW` for live packet capture
