# Fingerprint Sources

Leetha syncs community reference feeds into its cache directory (`~/.leetha/cache/`) and loads them for device matching.

---

## Downloading and Updating

```bash
leetha sync                      # refresh every source
leetha sync --list               # print configured source names and descriptions
leetha sync --source ieee_oui   # update a single source
```

The React dashboard exposes the same functionality at `/sync` with real-time download progress bars.

---

## Database Inventory

### Vendor and OUI Resolution

**OUI Master Database** -- one row per assignment block, including MA-L, MA-M, and MA-S prefixes. The cached record retains its canonical manufacturer, curated device type, raw registrant, registration status, deregistration date, and registrant history.

> **Note:** A separate Huginn-Muninn MAC vendor feed was evaluated and removed. Its upstream export was 99.7% `Unknown MAC Vendor (xxxxxx)` placeholder rows (a full 24-bit prefix enumeration) and contributed only 5 real vendors beyond the IEEE OUI registry, at a 700 MB+ cost. MAC-to-vendor resolution relies solely on the IEEE OUI registry.

*Matching:* The OUI table supplies the manufacturer and curated device type. Built-in entries supplement category and model hints. The longest matching block wins.

### DHCPv4 Analysis

**Huginn-Muninn DHCP Vendor Strings** -- Option 60 (Vendor Class Identifier) values. Leetha uses entries whose strings reveal a manufacturer, model, or device type.

*Matching:* The DHCP processor extracts Option 55 and Option 60. Option 55 is matched against annotated Huginn combinations, Satori DHCP, and built-in patterns. Option 60 is matched against the Huginn vendor table and built-in vendor patterns.

### DHCPv6 Analysis

**IANA Private Enterprise Number Registry** -- 67,000+ official enterprise-to-organization mappings used to resolve DUID-EN identifiers and vendor options.

*Matching:* DHCPv6 Solicit and Request frames carry an ORO that the DHCPv6 processor checks against built-in annotated patterns. Enterprise IDs embedded in DUID-EN fields are resolved through IANA.

### Comprehensive Device Profiles

**Huginn-Muninn Device Database** -- 122,000+ hierarchical profiles. Profiles enrich matching DHCP combinations with hierarchy and, when available, a device type.

**DHCP Combinations** -- links Option 55 patterns to device profiles. Where several devices share a pattern, `device_match` ranks exact names ahead of OS names and April mappings. This is still supporting evidence; a shared DHCP option list alone cannot uniquely identify a device.

**AppleDB Models** -- maps model identifiers advertised in mDNS `am=` or `model=` TXT records to product names. This also works with private MAC addresses, where OUI lookup is unavailable.

The lean DHCP signature feed contains only IDs and option strings, with no device attribution; leetha does not sync it. Timestamp sidecars and the full master database are not required for device matching.

### TCP/IP Stack Identification

**p0f Signature Database** -- 192 passive TCP/IP stack fingerprints capturing IP version, TTL, window size, MSS, window scale, TCP option order, and behavioral quirks. Labels follow the `type:class:name:flavor` convention (e.g. `s:unix:Linux:3.11 and newer`).

*PatternLoader pipeline:* The TCP stack processor constructs a signature from each SYN packet and searches the p0f database. Because TTL, window size, and option ordering are set by the OS kernel, this identification method works even for encrypted traffic.

### TLS Client Identification

**JA3 Fingerprint Database** -- 598 TLS ClientHello fingerprints from the Trisul set, covering browsers, mobile apps, and desktop clients. JA3 is an MD5 hash over cipher suites, extensions, elliptic curves, and EC point formats.

Leetha previously used Salesforce's `osx-nix-ja3.csv`, but that repository is archived and the list only covered 157 macOS/Linux **desktop applications**. The Trisul set is actively maintained and a near-superset -- it carries 155 of those 157 hashes plus mobile-app and browser fingerprints. Records identifying malware or scanner traffic are dropped at ingest: they carry no vendor, OS, or device type, and leetha identifies devices rather than threats.

Trisul ships no explicit OS field, so leetha infers one from each description -- 124 entries resolve an OS family, and Android/iOS app fingerprints additionally imply a handset.

**JA4+ Fingerprint Database** -- 70 mappings from FoxIO's `ja4plus-mapping.csv`. More collision-resistant than JA3.

> **Note:** the full JA4 database moved from `ja4db.com/api/read/` to
> `ja4db.foxio.io/api/ja4/` and now requires an account (`403` without
> credentials). The GitHub-hosted CSV is the only unauthenticated JA4 source
> FoxIO publishes, so coverage is limited to what it contains.

*PatternLoader pipeline:* The TLS processor computes both JA3 and JA4 from each ClientHello and queries both databases. Matches reveal the application (browser, curl, Python requests) and by extension the likely OS.

---

## Sync-to-Lookup Data Flow

```
  Upstream Format              Leetha Cache
  ---------------              -------------------
  IEEE OUI CSV          -->    ieee_oui.json
  p0f.fp plaintext      -->    p0f.json
  Huginn devices JSON   -->    huginn_devices.json
  Huginn combinations   -->    huginn_combinations.json
  AppleDB JSON          -->    apple_devices.json
  Huginn dhcp_vendor    -->    huginn_dhcp_vendor.json
  IANA enterprise-num   -->    iana_enterprise.json
  Satori JSON (x7)      -->    satori_*.json
  Recog XML (19 files)  -->    recog.json
  Trisul JA3 JSONL      -->    ja3.json
  JA4 mapping CSV       -->    ja4.json
                                    |
                                    v
                              SignatureMatcher
                              (preloaded or lazy per source)
```

Each upstream format has a parser in `src/leetha/sync/parsers.py`. Parsers normalize data into a JSON cache. `SignatureMatcher` in `src/leetha/fingerprint/lookup.py` reads the caches; the app preloads the larger and commonly used feeds in a background thread.

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
- The OUI Master Database contains roughly 59,000 unique assignment blocks; its canonical registrant takes precedence over built-in vendor names

Run integrity checks at any time:

```bash
leetha validate                   # all checks
leetha validate --check oui       # OUI accuracy
leetha validate --check stale     # outdated sources
leetha validate --verbose         # per-host detail
```

---

## Retired Feeds

Feeds are removed when they cannot pay their way. A retired feed's cache file
is deleted automatically on the next full `leetha sync`, so a dropped source
does not linger on disk.

| Feed | Why it was removed |
|---|---|
| `huginn_mac_vendors` | 99.7% `Unknown MAC Vendor (xxxxxx)` placeholder rows -- a full 24-bit enumeration adding only 5 real vendors beyond the IEEE OUI database, at a 700 MB cost. |
| `huginn_dhcp` | The lean export contains only fingerprint IDs and option strings. Its match supplied no manufacturer, device type, or OS; annotated combinations and Satori DHCP provide usable attribution. |
| `huginn_dhcpv6` | The lean ORO export supplied only a raw fingerprint ID. Built-in annotated DHCPv6 patterns remain. |
| `huginn_dhcpv6_enterprise` | IANA covers every named enterprise ID in the Huginn copy and thousands more; the Huginn copy could also mask an IANA name when its organization field was empty. |
| `satori_ntp` | Its lookup key encodes Satori's own undocumented timestamp heuristics (`set`/`unset`, `current`/`random`) and the field count is inconsistent (7 vs 8), so the key cannot be reconstructed from an observed NTP header. Its 25 identities are covered more reliably by DHCP, mDNS, OUI, and TCP fingerprints. |

Retired caches are pruned only after a **full** sync that completed without
failures -- never after a single-source run, which has no view of the whole
catalogue.
