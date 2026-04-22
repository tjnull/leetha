# Inventory Sources

Leetha's core identification is **passive** — it only knows about devices whose traffic it has seen. But sometimes you want to pre-populate the inventory with devices that *should* be there, even if they haven't sent a packet yet. The **inventory subsystem** (`src/leetha/inventory/`) is a pluggable importer framework for exactly that — DHCP lease files, router tables, UniFi controllers, Pi-hole logs, etc.

The first importer shipped with leetha reads DHCP lease files (ISC dhcpd and dnsmasq formats).

---

## The `passively_observed` Flag

Imported devices are marked `passively_observed=False`. This matters because:

- Imported rows don't prove a device is actually online — they just say "the DHCP server knows about it."
- The `new_host` rule **suppresses itself** when a device has `passively_observed=False`. Otherwise, importing a 500-host DHCP lease file would fire 500 WARNING findings on import.
- As soon as a real packet arrives for an imported MAC, the capture pipeline upserts the host and flips `passively_observed` to `True` (via `MAX(devices.passively_observed, excluded.passively_observed)` — the flag never regresses). From that point, normal rule evaluation resumes.

Schema:

```sql
ALTER TABLE devices ADD COLUMN passively_observed INTEGER NOT NULL DEFAULT 1;
```

Default `1` (True) so pre-existing rows aren't affected; imported rows explicitly set `0`.

---

## The Framework

### Registry

```python
from leetha.inventory import register_importer, BaseImporter

@register_importer("my_source")
class MySourceImporter(BaseImporter):
    async def sync(self):
        async for device in ...:
            yield device
```

`@register_importer(name)` adds the class to a module-level dict keyed by name. `get_importer(name)` looks it up; `get_all_importers()` returns the whole registry. Built-in importers are imported at module load (see `leetha/inventory/__init__.py`) so their decorators fire unconditionally.

### `BaseImporter` contract

```python
class BaseImporter(ABC):
    @abstractmethod
    async def sync(self) -> AsyncIterator[ImportedDevice]: ...

    async def test_connection(self) -> TestResult: ...
    def configure(self, config: dict) -> None: ...
    @classmethod
    def config_schema(cls) -> list[ConfigField]: ...
```

`ImportedDevice` is a small dataclass with `mac`, `ip`, `hostname`, `source`, `certainty`, and a `metadata` dict.

### Configuration schema

```python
from leetha.inventory.config_schema import ConfigField, validate

schema = [
    ConfigField(name="path", type="string", required=True, help="Path to the lease file"),
    ConfigField(name="flavor", type="select",
                choices=["auto", "isc", "dnsmasq"], default="auto"),
]
validate(schema, {"path": "/var/lib/dhcp/dhcpd.leases"})  # raises ValueError on invalid
```

Supported types: `string`, `int`, `bool`, `secret`, `select` (with `choices`). Custom per-field `validator` callables are supported.

### `importer_config` table

Persistent config and sync-state for each importer instance:

```sql
CREATE TABLE importer_config (
    name                TEXT PRIMARY KEY,
    enabled             INTEGER NOT NULL DEFAULT 0,
    config_json         TEXT NOT NULL DEFAULT '{}',
    interval_seconds    INTEGER NOT NULL DEFAULT 3600,
    last_sync_at        TEXT,
    last_sync_devices   INTEGER,
    last_sync_status    TEXT,
    last_sync_error     TEXT,
    next_sync_at        TEXT,
    backoff_level       INTEGER NOT NULL DEFAULT 0,
    encrypted_secret    BLOB
);
```

Repository API (`ImporterConfigRepository`): `get(name)`, `upsert(cfg)`, `list_all()`, `set_status(name, status, error=None)`, `mark_synced(name, devices_count)`, `schedule_next_sync(name, delay_seconds=None)`, `set_secret(name, plaintext)`, `get_secret(name)`.

### Scheduler

`InventoryScheduler` (`leetha/inventory/scheduler.py`) polls every 30 s (configurable), loads `enabled=1` importer configs, fires any whose `next_sync_at <= now()`. On success: status=`ok`, backoff reset, next sync scheduled at `interval_seconds` ± 20% jitter. On failure: status=`error`, backoff level increments (exponential ladder 60 s → 120 s → 240 s → 480 s → 960 s → 1920 s → 3600 s cap).

### Credentials

`leetha/inventory/credentials.py` — AES-GCM encrypted-at-rest secret store. Secrets live in `<data_dir>/secrets.db` (sqlite), encrypted with a 256-bit key at `<data_dir>/secrets.key` (chmod 600, auto-generated on first use).

**Env-var override:** `LEETHA_<NAME>_SECRET` wins over any stored value. Useful for CI, containers, and ephemeral deployments that shouldn't write secrets to disk.

```python
from leetha.inventory.credentials import store_secret, get_secret

store_secret("unifi", "s3cr3t-password")
# Later:
get_secret("unifi")  # returns "s3cr3t-password" (or env-var override if set)
```

Ciphertext layout: `nonce (12 bytes) || ciphertext || tag (16 bytes)`. Same plaintext produces different ciphertext on every write (random nonce).

### Log scrubber

`leetha/inventory/log_filter.SecretScrubFilter` is a stdlib `logging.Filter` that redacts common credential patterns before they hit stdout/files:

- `Bearer <token>` → `[REDACTED]`
- `token=...`, `password=...`, `passwd=...`
- `JSESSIONID=<session>`, `Cookie: ...`
- HTTP Digest `response="<hex>"`
- `"api_key": "<value>"`, `api_key=<value>`

Install with `install_scrubber("leetha.inventory")` — attaches to the named logger and propagates to children.

---

## Built-in: DHCP Lease File Importer

Located at `src/leetha/inventory/importers/dhcp_leases.py`.

**Auto-detects** ISC dhcpd format (block-style `lease <ip> { hardware ethernet ... ; }`) vs dnsmasq format (line-based `<expiry> <mac> <ip> <hostname> <clientid>`).

**Config schema:**

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `path` | `string` | yes | — | Absolute path to the lease file |
| `flavor` | `select` | no | `auto` | Force a format: `auto` / `isc` / `dnsmasq` |

**Malformed line handling:** logged as `WARNING` and skipped; the rest of the file still parses.

### CLI

One-shot import (loads every lease and returns):

```bash
leetha dhcp-leases import /var/lib/dhcp/dhcpd.leases
# → "Imported 27 device(s) from /var/lib/dhcp/dhcpd.leases"
```

Configure the scheduled importer (re-reads every `interval_seconds`):

```bash
leetha dhcp-leases set-path /var/lib/dhcp/dhcpd.leases
# → "Configured dhcp_leases importer: path=... ok=True message=parsed 27 lease(s) from ..."
```

### REST API

Upload a file from the web UI (admin-only):

```
POST /api/inventory/dhcp-leases/upload
Content-Type: multipart/form-data

file=@/path/to/dhcpd.leases

→ {"imported": 27, "flavor": "isc"}
```

Max upload size 5 MB. Binary/malformed content parses to `imported: 0` (not 500).

### Web UI

**Sync page → Inventory Sources card.** Shows the DHCP lease file importer with a file-upload input and a status line reporting the last upload's result.

---

## Writing a New Importer

1. Create `src/leetha/inventory/importers/my_source.py`.
2. Define a class decorated with `@register_importer("my_source")` inheriting `BaseImporter`.
3. Declare `config_schema()` with `ConfigField` entries.
4. Implement `async def sync()` as an async generator yielding `ImportedDevice`.
5. Optionally override `async def test_connection()` to return a `TestResult(ok, message, device_count)`.
6. Import the module from `leetha/inventory/importers/__init__.py` so the decorator fires on module load.
7. Add tests under `spec/inventory/importers/test_my_source.py`.

The scheduler will pick up any enabled `importer_config` row whose `name` matches the registered name.

---

## Role Enforcement

`POST /api/inventory/*` is **admin-only**. Imports can flood the device inventory, which affects `new_host` alerting posture when combined with `baseline set` — delegating to analyst tokens would be a privilege-escalation risk.

Analysts can still *see* imported devices via the normal `GET /api/devices` endpoint.
