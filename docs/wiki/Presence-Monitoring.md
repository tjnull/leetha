# Presence Monitoring

Leetha continuously tracks whether each device is actively sending traffic. A background **presence sweeper** runs every 60 seconds, evaluates each device's `last_seen` timestamp against its per-device **offline threshold**, and emits findings when a device transitions between online and offline.

---

## Why It Exists

Identifying that a device *exists* is one thing; knowing it's *currently operating* is another. Presence monitoring lets you:

- Notice when a critical host stops responding — e.g. a firewall that went dark or an industrial PLC that rebooted.
- Quiet cleanly when a device comes back — the returning-online transition auto-resolves the matching offline finding.
- Scale the sensitivity per-device — a laptop that suspends over lunch shouldn't produce the same alert as a production database that silently disappears.

---

## The Sweeper

Defined in [src/leetha/presence/sweeper.py](../../src/leetha/presence/sweeper.py).

**Frequency:** every 60 s (configurable via `PresenceSweeper(..., period_seconds=...)`).

**Query:** joins `hosts` and `devices` (full outer join on older SQLite falls back to a UNION of two LEFT JOINs). Uses `COALESCE(hosts.last_active, devices.last_seen)` as the authoritative freshness signal — `hosts.last_active` is updated by live capture, `devices.last_seen` is a secondary source (e.g. imported from a DHCP lease file). This is important: live packets update `hosts` but not `devices`, so a sweeper that only read `devices.last_seen` would miss every packet-captured device.

**Auto-materialization:** if a host exists in `hosts` but has no corresponding `devices` row yet (a very common case for live-capture-only devices), the sweeper creates a minimal `devices` row on demand so it can record `is_online` / `offline_since` state.

**Decision:** a device is online when `(now − last_seen) < presence_threshold_seconds`; offline otherwise. Default threshold is 300 s.

**Transitions are idempotent:** re-running the sweep on already-offline devices produces no new transitions and no new findings.

---

## Rules

Two presence rules are driven from the sweeper's callback (not the normal packet-driven rule engine). Both emit Finding rows into the standard findings table.

### `device_went_offline`

Fires when a device transitions online → offline. Severity scales with device criticality:

| `criticality` | Severity |
|---|---|
| `critical`, `high` | WARNING |
| `medium`, `low`, unset | INFO |

The idea: a silent industrial controller deserves your attention more than a laptop that went to sleep.

### `device_came_online`

Fires when a device transitions offline → online. Always INFO. Auto-resolves the matching `device_went_offline` finding for that MAC (`UPDATE findings SET resolved = 1 WHERE hw_addr = ? AND rule = 'device_went_offline' AND resolved = 0`), so your active-findings list stays clean.

---

## Per-device Threshold

The `presence_threshold_seconds` column on `devices` lets you override the default 300 s for any specific host. Bounds: **30 s ≤ n ≤ 86400 s** (24 hours).

Set via API:

```
PATCH /api/devices/{mac}
{"presence_threshold_seconds": 900}
```

Set via the UI — the **Device drawer → Labels tab → Presence panel** has a range slider plus 6 preset buttons (`1m` / `5m` / `15m` / `1h` / `4h` / `24h`). Changes save via PATCH the moment you release the slider or click a preset.

The sticky drawer header shows a PresenceDot (green-online / grey-offline) with a tooltip like "Offline for 12m" — visible on every tab.

---

## Typical Thresholds

| Device class | Suggested threshold | Why |
|---|---|---|
| Industrial controller, HVAC, PLC | 60 s — 2 m | These devices send heartbeat traffic regularly; short dropouts are real. |
| Server, router, firewall | 5 m (default) | Default works for most always-on infrastructure. |
| IoT / cameras / doorbells | 15 m — 1 h | Some chatty, some sleep — tune per device. |
| Laptops, phones, tablets | 4 h — 24 h | Suspend-resume is routine; you only care about multi-hour absences. |

---

## Lifecycle Integration

- **Startup** — `LeethaApp.start()` instantiates a `PresenceSweeper` and calls `.start()` which kicks off the 60 s loop as an `asyncio.create_task`.
- **Shutdown** — `LeethaApp.stop()` calls `sweeper.stop()` with a 1 s timeout. The loop honors the stop event and exits cleanly.
- **Abrupt Ctrl+C** — the REPL signal handler calls `os._exit(0)` without awaiting cleanup. SQLite WAL journaling makes this safe; the next startup picks up where the sweeper left off by examining `last_seen` timestamps.

---

## Direct DB Inspection

For debugging (while leetha is stopped, or via a read-only connection):

```sql
SELECT mac,
       is_online,
       offline_since,
       presence_threshold_seconds,
       last_seen,
       (strftime('%s','now') - strftime('%s', last_seen)) AS seconds_since_seen
FROM devices
ORDER BY seconds_since_seen DESC
LIMIT 20;
```

---

## Known Limitations

- **Discrete-event traffic** — a device that only wakes up to exchange one DHCP handshake every 24 hours looks "offline" 99.99% of the time to the default 300 s threshold. Raise the threshold for these (or approve/acknowledge accordingly).
- **Wired devices that rely on broadcast** — ARP replies, mDNS, IPv6 RA can keep "idle" devices showing traffic even without application-layer activity. This is usually desirable: the network interface is up.
- **Latent packet processing** — if the pipeline is backpressured (rare), `hosts.last_active` may be updated seconds behind the wire. Offline transitions triggered during a backpressure event will self-correct on the next sweep cycle.

---

## Schema

```sql
ALTER TABLE devices ADD COLUMN is_online INTEGER NOT NULL DEFAULT 1;
ALTER TABLE devices ADD COLUMN offline_since TEXT;
ALTER TABLE devices ADD COLUMN presence_threshold_seconds INTEGER NOT NULL DEFAULT 300;
```

`offline_since` is set when a device first goes offline and cleared when it comes back online. Consecutive offline sweeps preserve the original `offline_since` (it's `COALESCE`d, not overwritten).
