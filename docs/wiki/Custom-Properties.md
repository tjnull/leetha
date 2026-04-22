# Custom Properties

Every device in leetha carries five analyst-editable fields beyond its auto-discovered identity:

| Field | Type | Max | Purpose |
|---|---|---|---|
| `owner` | string | 200 chars | Person / team responsible for the device |
| `location` | string | 200 chars | Physical or logical location (rack, room, VLAN, subnet) |
| `criticality` | enum | — | `low` / `medium` / `high` / `critical` (or unset) |
| `tags` | list of strings | 20 tags | Free-form labels. Non-empty strings only. |
| `notes` | string | 2000 chars | Long-form analyst notes. |

These are curation fields — they don't change how leetha fingerprints a device, but they do feed into alerting (criticality grades presence rules) and filtering (every field is queryable).

---

## CLI

Set multiple fields at once:

```bash
leetha device set bc:df:58:1c:3d:c8 \
    --owner alice \
    --location "rack-03" \
    --criticality high \
    --tags "production,core,ingress" \
    --notes "primary edge router"
```

Tag helpers (idempotent):

```bash
leetha device tags add    bc:df:58:1c:3d:c8 dmz
leetha device tags remove bc:df:58:1c:3d:c8 dmz
```

Unknown MAC returns exit code 1. Invalid `--criticality` value returns exit code 2.

---

## REST API

```
PATCH /api/devices/{mac}
Content-Type: application/json

{
  "owner": "alice",
  "location": "rack-03",
  "criticality": "high",
  "tags": ["production", "core"],
  "notes": "primary edge router",
  "presence_threshold_seconds": 600
}
```

**Validation** — pydantic model `DevicePatch`:

- `owner`, `location`: `str | None`, `max_length=200`
- `criticality`: `Literal["low", "medium", "high", "critical"] | None`
- `tags`: `list[str] | None`, `max_length=20`, each element a non-empty stripped string
- `notes`: `str | None`, `max_length=2000`
- `presence_threshold_seconds`: `int | None`, `30 ≤ n ≤ 86400`

Any validation failure returns HTTP 422 with the offending field(s). Partial updates are supported — omitted fields are unchanged. Tags are stored as a JSON array in the `devices.tags` TEXT column.

**Auto-create** — if the MAC exists in `hosts` but has no `devices` row yet, the PATCH endpoint lazily creates a minimal `devices` row from the host record before applying the update. This makes the UI work seamlessly for live-capture-only devices (which are created in `hosts` by the capture pipeline but never touch `devices` until someone edits them).

---

## Filtering

All five fields are indexed and filterable on `/api/devices`:

```
GET /api/devices?owner=alice
GET /api/devices?location=rack-03
GET /api/devices?criticality=high
GET /api/devices?tag=production               # exact match on any array element
GET /api/devices?criticality=critical&owner=alice&tag=core
```

The tag filter uses SQLite's `json_each()` to test membership without requiring a separate normalized table.

---

## Sorting

```
GET /api/devices?sort=criticality&order=desc
GET /api/devices?sort=owner&order=asc
GET /api/devices?sort=location
```

Criticality sorts by **level**, not alphabet:

```
critical > high > medium > low > (null)
```

Via a `CASE` expression in the query (`critical`→4, `high`→3, `medium`→2, `low`→1, null→0) so sorting by criticality descending actually puts the most-critical devices first, not "critical" lexically before "high" before "low" before "medium."

Other sort keys: `owner`, `location`, `authorization`, `is_online`, `presence_threshold_seconds`, `offline_since` — plus all the legacy sort keys (`last_seen`, `ip_v4`, `mac`, `manufacturer`, etc.).

---

## Web UI

The **Device drawer → Labels tab → Custom Properties panel**:

- Owner and Location are text inputs; save on blur when the value changed.
- Criticality is a dropdown (`—` / low / medium / high / critical); saves on change.
- Tags are chip-style — type a tag and press Enter to add; click the X on a chip to remove. Duplicates are silently ignored.
- Notes is a multi-line textarea; saves on blur.

Every save invalidates the React Query caches for `["device-detail", mac]` and `["devices"]` so the list re-fetches.

**Sticky header** — if `criticality` is set, the drawer's sticky header shows a CriticalityPill (colored by level) that remains visible regardless of the active tab. The Devices list row also shows the criticality pill inline.

---

## Export

CSV and JSON exports (`/api/devices/export?format=csv|json`) include all five fields. Tags are serialized as a comma-separated string in CSV and a proper JSON array in JSON:

```csv
mac,ip_v4,...,owner,location,criticality,tags,notes,authorization,authorized_at,authorized_by,is_online,offline_since,presence_threshold_seconds
bc:df:58:1c:3d:c8,...,alice,rack-03,high,"production,core,ingress",primary edge router,approved,2026-04-20T01:18:21Z,1,true,,900
```

```json
{"mac": "bc:df:58:1c:3d:c8", "owner": "alice", "tags": ["production", "core"], ...}
```

---

## Schema

```sql
ALTER TABLE devices ADD COLUMN owner TEXT;
ALTER TABLE devices ADD COLUMN location TEXT;
ALTER TABLE devices ADD COLUMN criticality TEXT;  -- CHECK on fresh DBs only
ALTER TABLE devices ADD COLUMN tags TEXT;          -- JSON array
ALTER TABLE devices ADD COLUMN notes TEXT;

CREATE INDEX idx_devices_criticality ON devices(criticality);
CREATE INDEX idx_devices_location ON devices(location);
```

The `criticality CHECK (criticality IN ('low','medium','high','critical') OR criticality IS NULL)` constraint is embedded in the fresh-DB `CREATE TABLE`. For DBs that existed before the column was added (via `ALTER TABLE ADD COLUMN`, which can't retroactively add a CHECK), validation is enforced at the application layer via the pydantic `DevicePatch` model — the API returns 422 for invalid values.

---

## Role Enforcement

PATCH `/api/devices/{mac}` is available to **analyst** tokens — custom properties are curation, not security decisions. The authorization state (a separate field — see [Device Authorization](Device-Authorization.md)) is admin-only.
