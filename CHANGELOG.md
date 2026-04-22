# Changelog

All notable changes to Leetha will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-04-22 — Phase A Follow-Ups

Bug fixes, API completeness, and UX polish discovered during live-probe
regression testing after v1.2.0 shipped. 850 backend tests + 40 frontend
tests passing.

### Security
- **Admin-only role gate for all Phase A mutation endpoints.**
  `roles.py` now requires admin role for: `POST /api/devices/{mac}/approve`,
  `/reject`, `/revoke`; `POST /api/devices/bulk/authorization`;
  `POST /api/baseline/set` and `/baseline/reset`; `POST /api/inventory/*`.
  Previously analyst tokens could approve/reject the entire fleet.
- **`authorized_by` now captures the real token id.** The endpoint was
  reading `request.state.token_id`, but the auth middleware publishes the
  id on `request.scope["auth_token_id"]`. Audit trail entries now record
  the actual caller instead of `"anonymous"`.

### Added
- **`GET /api/devices/{mac}/authorization/history`** — per-device audit
  trail newest-first, with `limit` query param (max 1000).
- **`POST /api/baseline/reset`** and **`leetha baseline reset`** — revoke
  every approved/rejected device back to unapproved, logging each
  transition.
- **`authorization` and `is_online` filter params** on `/api/devices`
  (were previously silently ignored by FastAPI).
- **Phase A sort keys** on `/api/devices`: `criticality`, `owner`,
  `location`, `authorization`, `is_online`, `offline_since`,
  `presence_threshold_seconds`. Criticality sorts by level
  (critical > high > medium > low), not alphabetic.
- **Tabbed DeviceDrawer** — Summary / Labels / Activity / Evidence tabs
  with at-a-glance badges (AuthorizationBadge, CriticalityPill,
  PresenceDot) sticky in the header on every tab.

### Fixed
- **Ctrl+C exits instantly** (<1 ms measured over 10 runs, was 2–4 s).
  SIGINT handler calls `os._exit(0)` directly; WAL journaling makes
  this safe. Graceful cleanup remains on the `exit` / Ctrl+D path.
- **Mutation endpoints auto-create a devices row** from the matching
  `hosts` record if one doesn't exist yet. Previously PATCH / approve
  on live-capture-only devices returned 404 because the capture
  pipeline populates `hosts` but not `devices`.
- **`GET /api/devices/{mac}/detail`** now merges Phase A fields
  (owner, criticality, authorization, presence) — was returning the
  pre-Phase-A device shape.
- **CSV + JSON exports** now include all Phase A columns. CSV
  serializes tags as comma-joined; JSON keeps them as an array.
- **Topology nodes** carry Phase A fields (`criticality`,
  `authorization`, `owner`, `location`, `tags`) so the topology UI
  can style nodes by criticality/auth state.
- **Incident detail** device block enriched with Phase A fields.
- **DHCP-imported hostnames are searchable + visible.** `list_devices`
  SELECT now uses `COALESCE(v.hostname, d.hostname)`, and the `q=`
  search LIKE matches `d.hostname` too. Also fixed a related bug where
  DHCP-uploaded devices were invisible in the device list (upload now
  writes to both `hosts` and `devices`).
- **Presence sweeper no longer misses host-only devices.** The sweep
  query now drives off `hosts` LEFT JOIN `devices` (was `devices`-only),
  so live-capture-only hosts are considered. Auto-creates a `devices`
  row on demand so it can record `is_online` / `offline_since` state.
  Uses `COALESCE(h.last_active, d.last_seen)` as the authoritative
  freshness signal (stale `devices.last_seen` no longer flips live
  devices offline).

### Removed
- **Crit / Owner / Location / Tags / Auth columns** from the Devices
  table — mostly empty for typical deployments, wasted horizontal
  space. Replaced by at-a-glance badges in the drawer header; full
  editing still lives in the drawer's Labels tab.

## [1.2.0] - 2026-04-19 — Phase A Foundation

**Breaking behavior change:** newly discovered devices now default to
`authorization=unapproved`. Findings on unapproved devices fire at WARNING
severity (rejected → CRITICAL). To silence this for an existing network,
run `leetha baseline set` once or click "Set baseline" in the Devices page.

### Added — A.1 Custom Properties
- **Custom-property columns on devices** — `owner`, `location`, `criticality`
  (low/medium/high/critical), `tags` (JSON list), `notes`
- **`PATCH /api/devices/{mac}`** — pydantic-validated partial update endpoint
- **`leetha device set <mac>`** and **`leetha device tags add|remove`** CLI commands
- **CustomProperties panel** in the device drawer; **CriticalityPill** component
- **Devices list filters** by criticality / owner / location / tag (query params
  flow through to the store)

### Added — A.2 Tri-state Authorization
- **`authorization` + `authorized_at` + `authorized_by`** columns + `authorization_history` audit table
- **Store mutators** `approve_device` / `reject_device` / `revoke_device` with
  full audit trail; same-state transitions are no-ops
- **`baseline_set`** atomically approves all unapproved devices; **`baseline_status`**
  returns per-state counts and last-baseline timestamp
- **`new_host` rule severity grades by authorization** — approved → INFO,
  unapproved → WARNING, rejected → CRITICAL; approving a device auto-resolves
  pending `new_host` findings for that MAC
- **`POST /api/devices/{mac}/{approve,reject,revoke}`**, **`POST /api/baseline/set`**,
  **`GET /api/baseline/status`**
- **`leetha device {approve,reject,revoke}`** and **`leetha baseline {set,status}`** CLI
- **`AuthorizationBadge`**, **`AuthorizationPanel`**, **`BaselineBanner`** frontend components

### Added — A.3 Inventory Subsystem + DHCP Importer
- **`leetha.inventory` scaffold** — `BaseImporter`, `ImportedDevice`, `TestResult`,
  and a module-level `register_importer("name")` decorator registry
- **`importer_config` table + `ImporterConfigRepository`** — per-importer persistence
  with `get`, `upsert`, `list_all`, `set_status`, `mark_synced`, `schedule_next_sync`
- **AES-GCM credential store** (`leetha/inventory/credentials.py`) with
  `LEETHA_<NAME>_SECRET` environment-variable override; key file chmod 0600;
  random 96-bit nonces
- **`ConfigField` typed config schema** with `string`, `int`, `bool`, `secret`,
  and `select` field types; per-field validators
- **Per-importer scheduler** (`InventoryScheduler`) with ±20% jitter and exponential
  backoff ladder (60s → 120s → 240s → 480s → 960s → 1920s → 3600s cap)
- **Secret-scrubbing log filter** — redacts `Bearer …`, `token=`, `password=`,
  `JSESSIONID=`, `Cookie: …`, HTTP Digest `response="…"`, and `api[_-]?key` patterns
- **`passively_observed` flag** — importer-sourced devices start `False`; flips
  to `True` on first live packet; `new_host` rule is suppressed while `False`
- **DHCP lease file importer** — parses ISC dhcpd.leases and dnsmasq.leases with
  auto-detection; malformed lines logged as warnings instead of aborting
- **`POST /api/inventory/dhcp-leases/upload`** endpoint for in-memory lease-file parsing
- **`leetha dhcp-leases import <path>`** and **`leetha dhcp-leases set-path <path>`** CLI
- **Inventory Sources panel** on the Sync page with DHCP upload button

### Added — A.4 Presence Heartbeat
- **`is_online`, `offline_since`, `presence_threshold_seconds`** columns on devices
- **`PresenceSweeper`** — 60-second async loop; per-device threshold; idempotent
- **`device_went_offline`** (severity grades with criticality) and
  **`device_came_online`** (INFO) rules; coming back online auto-resolves
  the corresponding offline finding
- **PATCH supports `presence_threshold_seconds`** (30–86400s) for per-device override
- **`PresenceDot`** frontend component shown on the device drawer
- **Sweeper wired into `LeethaApp.start()`** and stopped cleanly on shutdown

### Changed
- Version bump `1.0.0` → `1.1.0` (stale baseline correction) → `1.2.0`
  (Phase A release)

## [1.0.0] - 2026-04-10

### Added
- **mDNS SRV target extraction** -- capture device hostnames, service ports, and model names from DNS type-33 SRV records and TXT fields (SYSTYPE, devtype, HAP category)
- **Infrastructure mDNS filtering** -- automatically detect routers/gateways/APs via OUI and DHCP, suppress forwarded multicast traffic that would pollute device identity
- **Cross-device mDNS detection** -- detect AirPlay `<hex>@<name>` patterns and reject hostnames from other devices
- **Hostname coherence validation** -- reject hostnames containing vendor keywords that don't match the resolved device vendor
- **Firmware SDK hostname rejection** -- filter auto-generated hostnames from embedded SDKs (ESDK, ESP, Tasmota, Shelly, Tuya, ewelink, etc.)
- **PCAP import via CLI** -- `leetha import` processes captured traffic through the full fingerprinting pipeline into the hosts table
- **CLI `--version` flag** -- `leetha --version` displays the current version
- **`/api/version` endpoint** -- returns version, Python version, and platform
- **Version display in web UI** -- shown in the sidebar
- **Paginated alerts API** -- `/api/alerts` now accepts `page` and `per_page` parameters
- **Numeric IPv4 sorting** -- inventory sorts IP addresses numerically (192.168.1.2 before 192.168.1.100)
- **All columns sortable** -- added missing sort columns: ip_v4, os_family, alert_status
- **Error banners** -- Dashboard and Devices pages show error messages when API calls fail
- **WebSocket auth rejection handling** -- stops reconnecting on invalid token (close code 1008)
- **LRU eviction for pipeline caches** -- prevents unbounded memory growth on long-running deployments
- **Process thread architecture** -- packet processing runs in a dedicated thread with its own event loop and DB connection, immune to event loop contention
- **Sniff auto-restart** -- capture thread automatically restarts on transient NIC errors
- **Thread-safe event dispatch** -- live packet stream uses `call_soon_threadsafe()` for cross-thread WebSocket events

### Changed
- **Default sort** -- inventory defaults to IP address ascending instead of last-seen descending
- **CI Python version** -- upgraded from 3.11 to 3.13 across all workflows
- **Evidence weights** -- `mdns_exclusive` lowered from 0.96 to 0.80 (below OUI 0.90) to prevent forwarded mDNS from overriding hardware identification
- **Hostname hex regex** -- changed from `{6,}` to `{12,}` to preserve valid names like `DESKTOP-ABC123`
- **`last_active` debouncing** -- only updates when 30+ seconds have passed, preventing constant row shuffling in the UI
- **WebSocket throttle** -- invalidation interval increased from 2s to 10s; polling from 30s to 60s
- **Apprise instance** -- created once in `__init__` instead of per-send

### Fixed
- **Capture pipeline dying after 60-300s** -- caused by event loop contention between packet processing, analysis tasks, and DB queries sharing one aiosqlite connection
- **Missing devices in inventory** -- pipeline early returns bypassed host upsert for packets without a matching processor or when the processor crashed
- **Gateway IP overwriting** -- forwarded multicast traffic from other VLANs overwrote the router's IP with a different subnet's address
- **Tailscale ghost devices** -- TUN interfaces returned IPs as MAC addresses; now rejected by `_is_valid_mac()` validation
- **Lutron/Apple/Google hostname contamination** -- forwarded mDNS services attributed to the router instead of the originating device
- **`dns_answer` hostname leaking** -- DNS PTR responses forwarded by routers attributed to the wrong device; now included in cross-validation source list
- **React table key instability** -- removed array index from key, preventing row remounts on sort changes
- **Device activity endpoint format** -- returned dict instead of array; frontend charts now render correctly
- **Alert delete endpoints** -- returned HTTP 200 on database failure; now returns 500 with error message
- **Identity TOCTOU race** -- `find_or_create` changed from SELECT-then-INSERT to `INSERT OR IGNORE`
- **Notification rate limiter false positive** -- `time.monotonic()` near zero on fresh CI runners blocked first notification
- **CLI `-i` flag override** -- saved interface config no longer overrides explicit `-i` when provided
- **`bytes` serialization crash** -- scapy fields containing raw bytes crashed JSON serialization in WebSocket events and sighting storage
- **`exclusive` variable undefined** -- mDNS processor referenced undefined variable, breaking exclusive service detection
- **Multi-worker pipeline** -- `worker_count > 1` path used incompatible asyncio.Queue after stdlib queue change; all processing now uses thread-based approach
