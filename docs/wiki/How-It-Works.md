# How It Works

Leetha transforms raw network frames into confident device identifications through a five-component pipeline: **PacketCapture**, **PARSER_CHAIN**, **ProcessorRegistry**, **VerdictEngine**, and **Store**. Every component is decoupled -- processors are self-registering, evidence is typed, and verdicts are computed from weighted evidence fusion rather than hard-coded rules.

---

## Pipeline Overview

```
  Network Adapter
       |
       v
  PacketCapture  (scapy sniff, one thread per adapter)
       |
       v
  PARSER_CHAIN   (ordered list of protocol-specific parsers)
       |  produces CapturedPacket
       v
  ProcessorRegistry  (@register_processor decorators)
       |  emits Evidence objects
       v
  VerdictEngine  (weighted fusion across all Evidence for a host)
       |  produces Verdict
       v
  Store  (HostRepository, FindingRepository, ...)
       |
       v
  FindingRules  (@register_rule, queries Store for security findings)
```

---

## PacketCapture

`PacketCapture` launches a scapy `sniff()` loop on each selected adapter. Each adapter runs in its own background thread with an independent BPF filter.

### BPF Filter Construction

The base filter targets protocol traffic that carries fingerprint-worthy data:

```
tcp[tcpflags] & tcp-syn != 0 or
tcp port 443 or
udp port 67 or udp port 68 or
udp port 546 or udp port 547 or
udp port 5353 or
udp port 1900 or
udp port 5355 or udp port 137 or
udp port 53 or
icmp6 or arp
```

For adapters with a known IPv4 subnet, the filter is scoped: `(net 10.10.14.0/24) and (<base>)`. Tap adapters broaden to `ip or ip6 or arp` and enable promiscuous mode. Tun adapters use `ip or ip6` (no Layer 2 framing).

---

## PARSER_CHAIN

When a raw frame arrives, `PacketCapture` passes it through the `PARSER_CHAIN` -- an ordered sequence of protocol-specific parsing functions. The first parser that matches claims the packet and returns a `CapturedPacket` enriched with protocol fields. If no specific parser matches, a fallback IP observer creates a minimal record.

### Protocol Parsers

| Parser | Trigger Condition | Extracted Fields |
|--------|-------------------|------------------|
| `parse_tcp_syn` | TCP with SYN flag set | TTL, window size, MSS, TCP option order (p0f signature) |
| `parse_dhcpv4` | UDP ports 67/68 | Option 55 list, Option 60 vendor class, hostname, raw option bytes |
| `parse_dhcpv6` | UDP ports 546/547 | ORO option set, DUID, enterprise ID, vendor class, client FQDN |
| `parse_mdns` | UDP port 5353 | Service type (e.g. `_spotify-connect._tcp`), instance name, TXT key-value pairs, hostnames from non-service records |
| `parse_dns` | UDP port 53 | Query name, query type, answer records (A/AAAA/PTR); full IPv6 support |
| `parse_ssdp` | UDP port 1900 | Server header, ST/NT field, USN, Location URL (both NOTIFY and M-SEARCH requests) |
| `parse_llmnr_netbios` | UDP ports 5355/137 | Queried name, query type |
| `parse_tls_hello` | TCP with TLS Client Hello (any port) | JA3 digest, JA4 fingerprint, SNI, protocol version, cipher list, extension list |
| `parse_arp` | All ARP frames | Sender/target MAC and IP, ARP operation (request/reply) |
| `parse_icmpv6` | All ICMPv6 | RA flags (M/O), hop limit, prefix info, NS/NA addresses, Router Solicitation |
| `parse_ip_observed` | Catch-all for remaining IP | Source/destination IP+MAC, TTL, protocol number, ports |

Every `CapturedPacket` carries the adapter name and observed CIDR for downstream context.

---

## ProcessorRegistry

Processors implement the core analysis logic. Each processor is a class decorated with `@register_processor` that accepts a `CapturedPacket` and optionally emits one or more `Evidence` objects.

```python
@register_processor("oui_lookup")
class OUIProcessor:
    def process(self, pkt: CapturedPacket) -> list[Evidence]:
        ...
```

When a `CapturedPacket` arrives, the `ProcessorRegistry` dispatches it to every registered processor in parallel. Processors are stateless -- all persistent state lives in the `Store`.

### Key Processors

**OUI Resolver** -- Resolves the first 3 bytes of the source MAC against (a) 1,900+ curated vendor records with device type and model hints, and (b) the 86,000-entry IEEE OUI table as a fallback. Emits an `Evidence` with manufacturer, and optionally device_type.

**DHCP Option 55 Matcher** -- Converts the ordered parameter request list into a lookup key and searches the Huginn-Muninn DHCP database (368K+ signatures). Different operating systems request different DHCP options in different orders, making this a strong OS fingerprint. For example, the sequence `[1,3,6,15,26,28,51,58,59]` resolves to Windows 10, while `[1,121,3,6,15,119,252]` indicates macOS.

**DHCP Vendor Class Analyzer** -- Extracts the Option 60 string (e.g. `dhcpcd-9.4.1:Linux-6.1.0`, `MSFT 5.0`, `udhcp 1.33.2`) and maps it to a vendor and OS family.

**mDNS Service Classifier** -- Maps announced service types to device categories: `_airplay._tcp` implies an Apple device, `_googlecast._tcp` a Google Nest/Chromecast, `_ipp._tcp` a network printer. Also extracts hostnames from non-service mDNS records (A, AAAA, PTR) for device naming. Certain mDNS services are treated as **exclusive** to a single vendor and produce 97% certainty evidence that overrides any OUI-based guess. Apple-exclusive services include `_apple-mobdev2._tcp` and `_companion-link._tcp`. Similarly, `_googlecast._tcp` is exclusive to Google and `_samsung-osp._tcp` is exclusive to Samsung. When an exclusive service is observed, the resulting evidence weight is high enough to dominate the VerdictEngine fusion, ensuring the correct vendor attribution even when the OUI is ambiguous or the MAC is randomized.

**TCP Stack Fingerprinter** -- Constructs a p0f-style signature from the SYN packet's TTL, window size, MSS, and TCP option order. Matched against 192 p0f signatures using the `type:class:name:flavor` label scheme (for instance, `s:unix:Linux:3.11 and newer`).

**TLS Handshake Analyzer** -- Computes JA3 (MD5 of cipher suites, extensions, curves, point formats) and JA4 (protocol, version, cipher count, extension count, ALPN) hashes from ClientHello messages. These are resolved against the JA3 database (150+ entries) and the JA4+ database (2,000+ entries) to determine the client application and infer the OS.

**DNS Pattern Recognizer** -- Classifies devices by the domains they query: `*.apple.com` traffic points to an Apple device, `connectivitycheck.gstatic.com` to Android, `*windowsupdate.com` to Windows, and `ntp.ubuntu.com` to Ubuntu. DNS queries to vendor-specific domains produce evidence that feeds directly into the VerdictEngine: `icloud.com` and `apple.com` domains generate Apple evidence, `windowsupdate.com` and `microsoft.com` generate Microsoft evidence, `googleapis.com` generates Google evidence, and so on. This DNS vendor evidence is weighted at the behavioral signal tier (0.75--0.80 reliability).

**NetBIOS / LLMNR Extractor** -- Pulls hostnames and workgroup names from legacy Windows name resolution broadcasts.

**SSDP Decoder** -- Parses UPnP NOTIFY announcements and M-SEARCH requests/responses to extract device manufacturer, model, and firmware from the Server header and device description URI.

**ICMPv6 RA/RS Analyzer** -- Reads Router Advertisement flags, hop limits, and prefix information to identify router operating systems. Also handles Router Solicitation messages for IPv6 host detection.

**ServiceProbe Processor** -- When probing is enabled, 300+ `ServiceProbe` plugins connect to discovered endpoints via `ServiceConnection` and call `identify(conn)` to produce a `ServiceIdentity` with service name, version string, and protocol-level metadata (e.g. SMB signing status, SSH key exchange algorithms).

---

## VerdictEngine

The `VerdictEngine` consumes all `Evidence` objects associated with a single host (keyed by MAC address) and produces a `Verdict` -- the final assessment of manufacturer, device_type, os_family, os_version, hostname, and confidence.

### Fusion Algorithm

For each attribute (manufacturer, device_type, os_family), the engine runs a weighted vote:

1. Every `Evidence` contributes a vote equal to `evidence.confidence * source_reliability`.
2. Votes are grouped by candidate value and summed.
3. The candidate with the greatest total becomes the verdict for that attribute.
4. Overall confidence is the weighted average of all contributing evidence.

### Source Reliability Tiers

| Tier | Example Sources | Reliability | Rationale |
|------|----------------|-------------|-----------|
| 1 (highest) | Huginn device profiles, hostname+domain, ServiceProbe results, DHCP vendor, nmap OS, OUI | 0.85 -- 0.92 | Directly identify the device or vendor |
| 2 | ICMPv6, TCP stack, banners, DHCPv6, mDNS, SSDP, DNS patterns, DHCP Option 60, JA3/JA4 | 0.75 -- 0.80 | Behavioral signals with strong correlation |
| 3 | HTTP User-Agent, NetBIOS, hostname alone, DHCP Option 55 | 0.68 -- 0.72 | Useful but less deterministic |
| 4 (lowest) | TTL heuristic | 0.55 | Coarse OS category only |

### Verdict Adjustments

**OUI manufacturer boost**: The OUI-derived manufacturer vote receives a +2.0 additive bonus so that the IEEE-registered vendor dominates over weaker inferences.

**Multi-product vendor filtering**: Vendors that manufacture many product types -- Samsung, Apple, Google, Amazon -- receive special handling. For these vendors, any OUI-based `device_type` guess is dropped entirely. Only protocol-level evidence from mDNS, SSDP, DHCP, and similar sources determines the device type. This prevents a Samsung OUI from guessing "smartphone" when the device is actually a smart TV or refrigerator.

**General-purpose OS suppression**: When non-OUI evidence (DHCP, TCP stack, TLS) confirms a standard OS like Linux, Windows, or macOS, OUI-based consumer device guesses (smart_speaker, media_player) are down-weighted by a 0.15 multiplier. This prevents a "Sonos" OUI from overriding a Linux p0f match with "smart_speaker" when the device might be a general-purpose server.

**OS-to-type inference**: When multiple independent sources agree on a general-purpose OS, the engine injects a synthetic vote for a computing device type (computer, server, workstation).

---

## Store

The `Store` is a facade over async SQLite that provides typed repositories:

- **HostRepository** -- CRUD for discovered devices and their current Verdict
- **FindingRepository** -- Security findings produced by FindingRules
- **EvidenceRepository** -- Raw Evidence records for audit and replay
- **BindingRepository** -- Trusted MAC/IP pairs for spoofing detection

Each `Verdict` is persisted as a host record containing:

| Attribute | Derivation |
|-----------|------------|
| `manufacturer` | OUI (authoritative) + VerdictEngine fusion |
| `device_type` | VerdictEngine fusion across all processors |
| `os_family` | Fusion of DHCP, TCP/p0f, TLS, DNS, and banner evidence |
| `os_version` | Most specific version string from any evidence source |
| `hostname` | DHCP hostname, mDNS instance name, or NetBIOS name |
| `confidence` | Weighted average (0--100) |

---

## MAC Randomization Handling

iOS, Android, and recent Windows releases randomize their Wi-Fi MAC addresses. Leetha flags a MAC as randomized when the locally-administered bit (bit 1 of octet 0) is set, excluding known virtual prefixes (Docker `02:42`, VMware `02:50:56`, QEMU `52:54:00`).

For randomized MACs, a behavioral correlation engine attempts to group multiple addresses that belong to the same physical device:

| Signal | Correlation Weight |
|--------|-------------------|
| Hostname match | 0.35 |
| DHCP Option 60 match | 0.25 |
| DHCP Option 55 match | 0.15 |
| TCP stack signature match | 0.15 |
| mDNS instance name match | 0.10 |

A combined score above 0.40 (at least two matching signals) causes the MACs to be linked under a single device identity in the Store.

---

## OS Intelligence Layer

When a manufacturer is known, Leetha cross-references a built-in vendor-OS database (130+ vendors) to:

- Confirm plausibility (reject a "Windows" verdict for a router OUI)
- Translate kernel strings to distribution names (kernel 6.1 implies Debian 12)
- Map firmware versions to product releases (kernel 5.15 on Ubiquiti maps to UniFi OS 3.x)
- Convert Windows build numbers to marketing names (build 22621 = Windows 11 22H2)

---

## Device Re-evaluation

Sixty seconds after startup, Leetha triggers an automatic re-evaluation pass. All devices that still have an unknown device type, missing manufacturer, or confidence below a minimum threshold are re-fingerprinted using the Huginn databases (devices, DHCP, MAC vendors) that have now fully loaded. During early capture, evidence may arrive before the large Huginn datasets are ready; the re-evaluation pass ensures those devices benefit from the complete reference data. Re-evaluation follows the same VerdictEngine fusion pipeline -- no special logic is involved, just a second pass with the full dataset available.

---

## User-Defined Patterns and Overrides

**Overrides** let you fix any host's attributes permanently:

```bash
leetha override set 00:11:22:33:44:55 --device-type nas --manufacturer Synology --os-family DSM
```

Overrides are stored in the Store and take absolute precedence over the VerdictEngine.

**Custom patterns** extend the PatternLoader with site-specific rules:

```bash
leetha patterns add hostname --pattern "^CAM-\d+" --device-type ip_camera --manufacturer Axis
leetha patterns add dhcp_opt60 --key "Cisco AP" --device-type access_point --os-family IOS
```

These patterns are evaluated by the same processors that handle built-in `patterns/data/` JSON files.
