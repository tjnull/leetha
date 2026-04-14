# Web Dashboard

Leetha ships a React single-page application (built with shadcn/ui and Tailwind CSS) that provides real-time visibility into discovered devices, security findings, and system configuration. The frontend is pre-compiled -- no Node.js installation is necessary.

```bash
leetha start web                        # listen on 0.0.0.0:443
leetha start web --port 9090            # alternative port
leetha start web --host 127.0.0.1       # restrict to loopback
```

---

## Page Guide

### Device Inventory (`/`)

The landing page renders a sortable, searchable table of every host stored in `HostRepository`. Rows update in real time via WebSocket push.

Columns: MAC, IPv4, IPv6, manufacturer, device type, OS, hostname, confidence (0--100%), alert badge, first-seen timestamp, last-seen timestamp. Rows are color-coded by device category.

Key interactions:
- Free-text search spanning MAC, IP, hostname, and manufacturer
- Drop-down filters for manufacturer, device type, OS family, alert state, and adapter
- Column-header sorting (ascending / descending toggle)
- Row click opens a detail drawer with the full Evidence timeline and current Verdict
- CSV or JSON bulk export
- Toggle between identity-grouped view (merges randomized MACs) and raw MAC view

### Alert Center (`/alerts`)

Aggregates all active alerts with severity badges:

- **Critical** -- spoofing confirmed, DHCP anomaly
- **Warning** -- OS family change detected, stale database source
- **Info** -- new host appeared, MAC randomization flagged

Alerts can be acknowledged individually or in batch.

### Attack Surface (`/attack-surface`)

Split-panel layout:

- **Left panel -- Attack Chains**: Multi-step playbooks showing adapter, triggering findings, numbered attack steps, and copy-ready tool commands.
- **Right panel -- Findings**: Individual `FindingRule` results with severity, evidence summary, affected hosts, and tool suggestions.

Filtering by severity or rule category. Full-text search across all findings. One-click command copy. Device or rule exclusion controls.

### Console (`/console`)

Browser-based operational console with four tabs:

- **Live Stream**: Real-time packet feed with protocol filter and full-decode toggle.
- **Network Overview**: Subnet and adapter summary with host counts per CIDR.
- **Filter Builder**: Visual BPF filter constructor for protocol, MAC, and IP criteria.
- **Capture Config**: Adapter selection, mode switching (passive/probe), and runtime tuning.

### Database Sync (`/sync`)

Shows all 12 fingerprint sources with their record counts, last-synced timestamps, and status indicators. Trigger a full refresh or update individual sources with per-source download progress (bytes transferred, files processed, parsing stage).

### Adapter Management (`/interfaces`)

Adapters are grouped into cards by type (physical, tap, tun). Each card displays the adapter's state, classification, MAC address, and IP bindings. Capture can be toggled on or off per adapter with immediate effect. Selections persist across restarts.

### Settings (`/settings`)

Tabbed configuration panel:

- **General**: Dashboard host/port, worker count, database batch options
- **TLS/HTTPS**: TLS certificate and private key selection with a file browser (restricted to `~/`, `/etc/leetha`, `/var/lib/leetha`). Private keys are written with `0o600` permissions.
- **Capture**: Adapter defaults, BPF filter customization, probe parameters
- **Sync**: Auto-sync cadence, source toggles, cache path
- **Advanced**: Debug logging, Store maintenance, configuration import/export

### Pattern Editor (`/patterns`)

CRUD interface for custom fingerprint patterns organized by type (hostname regex, DHCP Option 60 key, MAC prefix). Supports JSON import/export for sharing patterns across deployments.

### Detections (`/detections`)

Split-pane triage interface with a findings list on the left and an inline evidence panel on the right.

- **Findings List** (left, ~40%): Compact cards showing detection subtype, device MAC/IP, alert count, and relative timestamp. Filter by severity (Critical / Suspicious / Informational), search by MAC, IP, or manufacturer, and sort by severity, alert count, or recency.
- **Evidence Panel** (right, ~60%): Selecting a finding loads its full evidence inline — detection context, analyst notes, ARP history, fingerprint history, raw evidence records, and recent observations. Actions include Dismiss All, Suppress, and Mark Known.
- **Config Drawer**: A gear icon in the stats bar opens a slide-out panel for managing Trusted Bindings and Suppression Rules.

All alert types flow into findings: new devices, OS changes, MAC randomization, ARP spoofing subtypes, DHCP anomalies, OUI mismatches, fingerprint drift, and low-confidence identifications.

---

## REST API

### Host Endpoints

| Verb | Path | Returns |
|------|------|---------|
| GET | `/api/devices` | Paginated, filterable, sortable host list |
| GET | `/api/devices/export` | Bulk CSV or JSON export |
| GET | `/api/devices/{mac}` | Single host detail |
| GET | `/api/devices/{mac}/observations` | Evidence timeline for one host |
| POST | `/api/devices/{mac}/acknowledge` | Mark new-host alert as seen |
| POST | `/api/devices/{mac}/override` | Apply a manual Verdict override |

### Alert Endpoints

| Verb | Path | Returns |
|------|------|---------|
| GET | `/api/alerts` | Filterable alert list |
| POST | `/api/alerts/{id}/acknowledge` | Acknowledge a single alert |

### Attack Surface Endpoints

| Verb | Path | Returns |
|------|------|---------|
| GET | `/api/attack-surface` | Complete analysis (findings + chains + summary) |
| GET | `/api/attack-surface/summary` | Aggregate statistics |
| GET | `/api/attack-surface/chains` | Chain list only |
| GET | `/api/attack-surface/export` | JSON finding export |
| GET | `/api/attack-surface/exclusions` | Active exclusion list |
| POST | `/api/attack-surface/exclude` | Create exclusion (ip, mac, or rule) |
| DELETE | `/api/attack-surface/exclude/{type}/{value}` | Remove an exclusion |

### Adapter Endpoints

| Verb | Path | Returns |
|------|------|---------|
| GET | `/api/interfaces` | All detected adapters with capture state |
| POST | `/api/interfaces/{name}/enable` | Begin capture on adapter |
| POST | `/api/interfaces/{name}/disable` | Halt capture on adapter |

### Sync Endpoints

| Verb | Path | Returns |
|------|------|---------|
| GET | `/api/sync/sources` | Source list with status |
| POST | `/api/sync/run` | Initiate sync for a named source |

### Pattern Endpoints

| Verb | Path | Returns |
|------|------|---------|
| GET | `/api/patterns` | All custom patterns |
| POST | `/api/patterns/add` | Register a new pattern |
| POST | `/api/patterns/remove` | Delete a pattern |

---

## Additional Routes

The React frontend includes several additional routes beyond the primary pages described above:

| Route | Purpose |
|-------|---------|
| `/inventory` | Host inventory view (alias for the device table at `/`) |
| `/detections` | Detection findings with split-pane triage view |
| `/exposure` | Attack surface analysis (alias for `/attack-surface`) |
| `/stream` | Live packet stream viewer with protocol filters |
| `/feeds` | Sync source management (alias for `/sync`) |
| `/rules` | Pattern editor and rule browser (alias for `/patterns`) |
| `/adapters` | Interface management (alias for `/interfaces`) |
| `/docs` | Built-in knowledge base with searchable documentation |

### API Rate Limiting

All REST API endpoints are rate-limited to **120 requests per minute per IP address**. Exceeding this limit returns HTTP 429 (Too Many Requests) with a `Retry-After` header. WebSocket connections are not rate-limited.

### MAC Address Validation

API endpoints that accept MAC addresses (e.g. `/api/devices/{mac}`, `/api/trust`) validate the format before processing. Accepted formats: `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, and `AABBCCDDEEFF`. Invalid MAC addresses return HTTP 400 with a descriptive error message.

---

## WebSocket Stream

Connect to `wss://<host>:<port>/ws` using the `leetha-v1` subprotocol to receive push events:

| Event | Payload Summary |
|-------|-----------------|
| `device_added` | Full host record for a newly discovered device |
| `device_updated` | Updated fields after re-identification or new Evidence |
| `device_deleted` | MAC of the removed host |
| `alert` | Alert object with severity, type, and affected host |
| `capture_status` | Adapter name and new state (started / stopped) |

The React frontend subscribes automatically and applies incremental DOM updates -- no polling required.

---

## Security Hardening

- **TLS enabled by default** -- the dashboard serves over HTTPS. Use `--no-tls` to disable TLS if needed for development.
- **CORS** -- restricted to localhost origins only.
- **OpenAPI docs disabled** -- `/api/docs` and `/api/redoc` are not available.
- **`/metrics` requires auth** -- the metrics endpoint is not exempt from authentication.
- **SQL query endpoint** -- uses read-only mode to prevent data modification.
- **PCAP upload** -- filenames are sanitized to prevent path traversal.
- **Filesystem browsing** -- the TLS cert/key file browser is restricted to `~/`, `/etc/leetha`, and `/var/lib/leetha`.
