# Fingerprint Sources

Leetha's device identification accuracy depends on 12 community-maintained reference databases plus built-in JSON pattern files. The `PatternLoader` reads synced databases from the cache directory (`~/.leetha/cache/`) at runtime, loading each source on demand when a lookup is first requested.

---

## Downloading and Updating

```bash
leetha sync                      # refresh every source
leetha sync --list               # print source names, ages, and record counts
leetha sync --source ieee_oui   # update a single source
```

The React dashboard exposes the same functionality at `/sync` with real-time download progress bars.

---

## Database Inventory

### Vendor and OUI Resolution

**IEEE OUI Master Registry** -- 86,000+ records mapping 3-byte MAC prefixes to registered manufacturers. Built from the IEEE MA-L, MA-M, and MA-S registries. This is the authoritative layer for manufacturer attribution.

> **Note:** A separate Huginn-Muninn MAC vendor feed was evaluated and removed. Its upstream export was 99.7% `Unknown MAC Vendor (xxxxxx)` placeholder rows (a full 24-bit prefix enumeration) and contributed only 5 real vendors beyond the IEEE OUI registry, at a 700 MB+ cost. MAC-to-vendor resolution relies solely on the IEEE OUI registry.

*PatternLoader pipeline:* On every observed MAC, the OUI processor first checks the 1,900+ curated vendor entries in `patterns/data/` (which include device type, category, and model hints). If no curated match exists, the IEEE OUI table provides a manufacturer-only fallback.

### DHCPv4 Analysis

**Huginn-Muninn DHCP Signatures** -- 368,000+ fingerprints keyed by the ordered DHCP Option 55 parameter request list. Each entry maps to an OS family and device type.

**Huginn-Muninn DHCP Vendor Strings** -- 425,000+ Option 60 (Vendor Class Identifier) values that directly name the manufacturer, model, or firmware.

*PatternLoader pipeline:* When a DHCPv4 Discover or Request enters the PARSER_CHAIN, the DHCP processor extracts Option 55 and Option 60. The Option 55 sequence acts as a behavioral fingerprint -- Windows, macOS, Linux, and embedded systems each request different parameters in a characteristic order. Option 60 provides an explicit vendor declaration (e.g. `MSFT 5.0`, `udhcp 1.33.2`).

### DHCPv6 Analysis

**Huginn-Muninn DHCPv6 Signatures** -- 1,600+ fingerprints derived from the DHCPv6 Option Request Option (ORO), the IPv6 analog of DHCP Option 55.

**Huginn-Muninn DHCPv6 Enterprise IDs** -- 58,000+ enterprise numbers extracted from vendor-specific DHCPv6 options.

**IANA Private Enterprise Number Registry** -- 65,000+ official IANA enterprise-to-organization mappings used to resolve DUID-EN identifiers and vendor options.

*PatternLoader pipeline:* DHCPv6 Solicit and Request frames carry an ORO that the DHCPv6 processor matches against the Huginn signatures. Enterprise IDs embedded in DUID-EN fields are resolved through both the Huginn enterprise table and the IANA registry.

### Comprehensive Device Profiles

**Huginn-Muninn Device Database** -- 116,000+ hierarchical profiles linking manufacturer, device type, model, and OS family. Used as a cross-referencing layer: once initial signals (OUI + DHCP + mDNS) are collected, the device database narrows identification from a generic vendor to a specific product and firmware revision.

### TCP/IP Stack Identification

**p0f Signature Database** -- 192 passive TCP/IP stack fingerprints capturing IP version, TTL, window size, MSS, window scale, TCP option order, and behavioral quirks. Labels follow the `type:class:name:flavor` convention (e.g. `s:unix:Linux:3.11 and newer`).

*PatternLoader pipeline:* The TCP stack processor constructs a signature from each SYN packet and searches the p0f database. Because TTL, window size, and option ordering are set by the OS kernel, this identification method works even for encrypted traffic.

### TLS Client Identification

**JA3 Fingerprint Database** -- 150+ archived TLS ClientHello fingerprints. JA3 is an MD5 hash over cipher suites, extensions, elliptic curves, and EC point formats.

**JA4+ Fingerprint Database** -- 2,000+ modern TLS fingerprints from FoxIO spanning JA4 (client), JA4S (server), JA4H (HTTP), JA4X (certificate), and JA4T (TCP) variants. More collision-resistant than JA3.

*PatternLoader pipeline:* The TLS processor computes both JA3 and JA4 from each ClientHello and queries both databases. Matches reveal the application (browser, curl, Python requests) and by extension the likely OS.

---

## Sync-to-Lookup Data Flow

```
  Upstream Format              PatternLoader Cache
  ---------------              -------------------
  IEEE OUI CSV          -->    ieee_oui.json
  p0f.fp plaintext      -->    p0f.json
  Huginn devices JSON   -->    huginn_devices.json
  Huginn dhcp JSON      -->    huginn_dhcp.json
  Huginn dhcp_vendor    -->    huginn_dhcp_vendor.json
  Huginn dhcpv6 JSON    -->    huginn_dhcpv6.json
  Huginn dhcpv6_ent     -->    huginn_dhcpv6_enterprise.json
  IANA enterprise-num   -->    iana_enterprise.json
  JA3 CSV               -->    ja3.json
  JA4 API JSON          -->    ja4.json
                                    |
                                    v
                              PatternLoader
                              (lazy init per source)
```

Each upstream format has a dedicated parser in `src/leetha/sync/parsers.py`. Parsers normalize data into a uniform JSON structure: `{"source": "<name>", "entries": {<key>: <value>}}`. The `PatternLoader` in `src/leetha/patterns/loader.py` reads these cached JSON files the first time a lookup is performed.

---

## Built-In JSON Pattern Data

In addition to the synced community databases, Leetha ships with curated JSON pattern files under `patterns/data/`. These files cover multiple protocol categories:

| File Category | Content |
|---------------|---------|
| Hostname patterns | Regex rules mapping hostnames to vendor/device type |
| DNS patterns | Domain-to-vendor mappings for DNS query classification |
| mDNS patterns | Service type to device category mappings, including exclusive services |
| Banner patterns | Service banner strings to application/version mappings |
| DHCP patterns | Option 60 vendor class and Option 55 sequence rules |
| SSDP patterns | Server header and device description patterns |
| ICMPv6 patterns | Router advertisement flag combinations to OS mappings |
| NetBIOS patterns | Workgroup and hostname format rules |

The `PatternLoader` validates each JSON file on load and pre-compiles all regex patterns for efficient matching at capture time. Invalid entries are logged and skipped without halting the loader. Pre-compilation means regex patterns are compiled once at startup rather than on every packet, reducing per-packet processing overhead.

---

## Built-In Pattern Validation

The 1,900+ curated vendor patterns in `patterns/data/` have been verified against the IEEE OUI registry:

- Every prefix is confirmed to match the IEEE registrant
- Corporate acquisitions are mapped (Nest -> Google, Ring -> Amazon, Beats -> Apple)
- Enriched fields (device type, category, model hints) supplement what the IEEE data alone cannot provide
- The IEEE OUI dataset (86K+ entries) serves as a broad catch-all behind the curated layer

Run integrity checks at any time:

```bash
leetha validate                   # all checks
leetha validate --check oui       # OUI accuracy
leetha validate --check stale     # outdated sources
leetha validate --verbose         # per-host detail
```
