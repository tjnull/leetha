# Getting Started

This guide walks through installation, initial database sync, launching your first capture, and key configuration options.

---

## 1. Requirements

Leetha needs **Python 3.11+** running on **Linux**. Packet capture relies on scapy's raw socket access; Leetha handles privilege escalation internally, so you do not need to prefix commands with `sudo`.

---

## 2. Install the Package

The recommended approach uses pipx for isolated installation:

```bash
pipx install leetha
```

Alternatively, install with pip into any Python environment:

```bash
pip install leetha
```

Confirm the binary is available:

```bash
leetha --version
```

### Key Dependencies

| Library | Role |
|---------|------|
| scapy (>= 2.5) | Raw packet interception and protocol decoding |
| fastapi (>= 0.104) | Backend REST API |
| uvicorn[standard] (>= 0.24) | ASGI server powering the web interface |
| websockets (>= 12.0) | Push-based device update delivery |
| rich (>= 13.0) | CLI formatting and progress display |
| aiohttp (>= 3.9) | Non-blocking HTTP for database synchronization |
| aiosqlite (>= 0.19) | Async SQLite operations for the Store layer |
| psutil (>= 5.9) | Adapter enumeration via scan_adapters |

The React + shadcn/ui + Tailwind CSS frontend is pre-compiled and bundled in the package -- no Node.js toolchain is required.

---

## 3. Fetch Reference Databases (Optional)

Leetha ships with built-in patterns under `patterns/data/`, but accuracy improves substantially with the full community databases:

```bash
leetha sync
```

This pulls 12 sources (~880 MB) into `~/.leetha/cache/`. View what is available and its freshness:

```bash
leetha sync --list
```

Grab a single source if bandwidth is limited:

```bash
leetha sync --source p0f
```

The first startup without running `sync` will still work -- Leetha uses its built-in pattern data and OUI tables -- but with reduced accuracy for DHCP fingerprinting, TLS identification, and device profile matching. Databases are automatically loaded on startup and available to all processors immediately.

Full details on each source: [Fingerprint Sources](Fingerprint-Sources.md).

### MAC Randomization Note

Modern Apple (iOS 14+) and Android (10+) devices randomize their Wi-Fi MAC addresses by default. This means the OUI prefix no longer reliably identifies the vendor. Leetha handles randomized MACs through multiple strategies:

- **mDNS exclusive services**: Apple-exclusive services like `_apple-mobdev2._tcp` and `_companion-link._tcp` produce 97% certainty evidence that identifies the real vendor despite MAC randomization.
- **DHCP Option 61 (Client-ID)**: Some devices include a stable client identifier in DHCP exchanges that persists across MAC rotations, enabling Leetha to correlate multiple randomized addresses to the same physical device.
- **Behavioral correlation**: Hostname, DHCP options, TCP stack signatures, and mDNS instance names are combined to group randomized MACs belonging to the same device.

No configuration is needed -- randomized MAC handling is automatic.

---

## 4. Launch Leetha

Leetha provides three primary entry points. Pick whichever fits your workflow.

### Web Dashboard (recommended)

```bash
leetha start web
```

Navigates to `https://localhost` -- a React single-page application with live device discovery, alert management, attack surface analysis, and database sync controls.

See [Web Dashboard](Web-Dashboard.md) for a full tour.

### CLI Live Stream

```bash
leetha start cli -i eth0                # observe packets on eth0
leetha start cli --decode -i wlan0      # verbose protocol breakdown
leetha start cli --filter mdns          # show only mDNS frames
leetha start cli --filter mac=DE:AD     # match a MAC prefix
```

### Interactive Console

```bash
leetha -i eth0
```

The console gives you a REPL with tab completion:

```
leetha> help          available commands
leetha> devices       discovered host table
leetha> alerts        active alert list
leetha> start web     spin up the dashboard
leetha> start cli     switch to live stream
leetha> sync          refresh databases
leetha> status        uptime, adapter state, DB stats
leetha> exit          shut down
```

---

## 5. Specify Network Adapters

Pass adapters with the `-i` flag (repeatable):

```bash
leetha start web -i enp3s0                    # one adapter
leetha start web -i enp3s0 -i wlan0           # two adapters
```

Each adapter specification supports an optional classification and display label:

```
<name>[:<classification>[:<label>]]
```

**Supported classifications:**

| Classification | Behavior |
|----------------|----------|
| `local` (default) | Full rule evaluation including Layer 2 |
| `vpn` | Layer 2 rules suppressed -- ARP/NDP over tunnels is not reliable |
| `proxy` | Same suppression as vpn |
| `pivot` | Same suppression as vpn |

```bash
leetha -i tun0:vpn                  # mark tun0 as VPN
leetha -i tun0:vpn:htb-lab          # VPN with a friendly label
leetha -i tap0:pivot:internal-dmz   # pivoted tap adapter
```

### Saving Adapter Preferences

Store adapter selections so they persist between sessions:

```bash
leetha interfaces list                # enumerate system adapters via scan_adapters
leetha interfaces add enp3s0          # remember this adapter
leetha interfaces add tun0:vpn        # remember with classification
leetha interfaces remove enp3s0       # forget it
leetha interfaces show enp3s0         # display adapter details
```

Preferences are written to `~/.leetha/interfaces.json`.

---

## 6. Activate Service Probing (Optional)

Leetha is passive by default. For deeper service enumeration, enable the `ServiceProbe` engine:

```bash
leetha start web --probe -i eth0           # probe while capturing
leetha probe 10.10.14.5:443                # probe a single endpoint
```

The probe system loads 300+ `ServiceProbe` plugins. Each plugin opens a `ServiceConnection` to the target, calls `identify(conn)`, and returns a `ServiceIdentity` containing the service name, version, and protocol metadata. Probes run with rate limiting and a configurable cooldown between repeat visits.

---

## 7. Configuration Reference

Leetha uses two filesystem locations:

| Location | Default Path | Environment Variable | Purpose |
|----------|-------------|----------------------|---------|
| Data directory | `~/.leetha/` | `LEETHA_DATA_DIR` | SQLite store, tokens, settings, custom patterns, overrides |
| Cache directory | `~/.leetha/cache/` | `LEETHA_CACHE_DIR` | Downloaded fingerprint databases |

### Adjustable Settings

| Setting | Default | Purpose |
|---------|---------|---------|
| `web_host` | `0.0.0.0` | Bind address for the React dashboard |
| `web_port` | `443` | Port for the dashboard |
| `web_tls` | `true` | Enable TLS (HTTPS). Use `--no-tls` to disable |
| `worker_count` | `4` | Parallel packet processing workers |
| `db_batch_size` | `50` | Rows buffered before flushing to Store |
| `db_flush_interval` | `0.1` | Flush cadence in seconds |
| `sync_interval_days` | `7` | Days between automatic database refreshes |
| `probe_enabled` | `false` | Whether ServiceProbe plugins run |
| `probe_max_concurrent` | `10` | Simultaneous probe connections |
| `probe_cooldown_seconds` | `3600` | Seconds before re-probing a target |

---

## 8. Running the Test Suite

Leetha's tests live under `spec/`:

```bash
pytest spec/
```

---

## Where to Go Next

- [CLI Reference](CLI-Reference.md) -- complete flag and subcommand documentation
- [How It Works](How-It-Works.md) -- architecture walkthrough: PacketCapture through VerdictEngine to Store
- [Web Dashboard](Web-Dashboard.md) -- page-by-page guide to the React frontend
- [Attack Surface Analysis](Attack-Surface-Analysis.md) -- FindingRules and attack chain playbooks
