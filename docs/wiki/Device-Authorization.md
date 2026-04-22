# Device Authorization

Leetha tracks every discovered device through a tri-state **authorization** lifecycle. The state controls how loudly leetha alerts when it sees that device:

| State | `new_host` severity | Meaning |
|---|---|---|
| `approved` | INFO | Known-good. You've confirmed this device belongs on the network. |
| `unapproved` | WARNING | Default. Leetha doesn't know yet and treats it as unknown. |
| `rejected` | CRITICAL | Known-bad. You don't want this device here — escalate every finding. |

The state lives in the `devices.authorization` column. Every transition is recorded in a separate `authorization_history` table as a tamper-resistant audit trail.

---

## Why It Exists

Without authorization, leetha would fire `new_host` for every device it discovers, forever. On an established network with hundreds of existing hosts, that's pure noise. Authorization lets you:

- **Silence a stable network** — run `leetha baseline set` once after deployment and all currently-discovered hosts become approved. Future `new_host` findings only fire for genuinely new arrivals.
- **Escalate known-bad devices** — reject a specific MAC to promote its findings to CRITICAL.
- **Audit who decided what** — every state change records the acting token id and an optional reason.

---

## State Transitions

Valid transitions (any state can move to any other state):

```
                 approve
              ┌────────────►
              │
unapproved ◄──┤                  approved
              │    revoke
              │◄────────────
              │
              │    reject                      approve
              └────────────►  rejected   ◄──────────────
              ◄──────────────            ──────────────►
                   revoke                      reject
```

A same-state transition is a no-op (no history row written).

**Auto-resolve on approve**: when a device transitions to `approved`, leetha's store layer marks any currently-unresolved `new_host` finding for that MAC as `resolved=1`. Approving a device silences the warning it just produced.

---

## CLI

Single device:

```bash
leetha device approve bc:df:58:1c:3d:c8 --reason "onboarded"
leetha device reject  bc:df:58:1c:3d:c8 --reason "not authorized"
leetha device revoke  bc:df:58:1c:3d:c8
```

Bulk:

```bash
leetha baseline set      # approve every currently-unapproved device
leetha baseline reset    # revoke every non-unapproved device back to unapproved
leetha baseline status   # print current counts
```

Sample output of `baseline status`:

```
approved=27 unapproved=3 rejected=0
last_baseline_at=2026-04-20T01:18:21.014426+00:00
```

---

## REST API

### Per-device mutation (admin-only)

| Verb | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/devices/{mac}/approve` | `{"reason": "..."}` (optional) | Updated device JSON |
| POST | `/api/devices/{mac}/reject`  | `{"reason": "..."}` | Updated device JSON |
| POST | `/api/devices/{mac}/revoke`  | `{"reason": "..."}` | Updated device JSON |

The actor recorded in the history row is the authenticated token id pulled from `request.scope["auth_token_id"]`. Unauthenticated calls (auth disabled) record `actor="anonymous"`.

### Bulk mutation (admin-only)

```
POST /api/devices/bulk/authorization
Content-Type: application/json

{
  "action": "approve",        // or "reject" | "revoke"
  "macs": ["aa:bb:...", ...], // 1 ≤ len ≤ 500
  "reason": "..."             // optional
}
```

Returns:

```json
{"updated": 27, "missing": ["ff:ff:ff:ff:ff:ff"], "action": "approve"}
```

`missing` lists MACs not present in either the `hosts` or `devices` tables (a host that exists only in `hosts` but not yet in `devices` is auto-created before the mutation applies).

### Baseline (admin-only)

| Verb | Path | Effect |
|---|---|---|
| POST | `/api/baseline/set`   | `UPDATE devices SET authorization='approved' WHERE authorization='unapproved'`, one history row per touched device with reason `"baseline"` |
| POST | `/api/baseline/reset` | `UPDATE devices SET authorization='unapproved' WHERE authorization != 'unapproved'`, one history row per touched device with reason `"baseline-reset"` |

### Status (analyst)

```
GET /api/baseline/status
→ {"approved": 27, "unapproved": 3, "rejected": 0, "last_baseline_at": "..."}
```

### Audit history (analyst)

```
GET /api/devices/{mac}/authorization/history?limit=100
→ {"mac": "...", "history": [
    {"id": 14, "mac": "...", "previous_state": "unapproved",
     "new_state": "approved", "actor": "1", "reason": "onboarded",
     "timestamp": "2026-04-20T01:18:21Z"},
    ...
  ]}
```

Limit defaults to 100, max 1000. Newest first. Returns 404 if the MAC is unknown in both tables and has no history rows.

---

## Role Enforcement

Per `leetha/auth/roles.py`:

- All authorization-mutating endpoints (`approve`, `reject`, `revoke`, bulk authorization, baseline set/reset) require **admin** role.
- Read endpoints (`baseline/status`, authorization history) are available to **analyst** tokens.

Analyst tokens that hit an admin endpoint get HTTP 403 with `{"error": "Admin access required."}`.

Authorization is orthogonal to the existing `alert_status` (new / known / suspicious / self) which reflects how leetha categorizes a device's *identity*. Both can coexist — a device can be `alert_status=known` and `authorization=rejected`, meaning "I know what this device is, I just don't want it on my network."

---

## Web UI

- **Device drawer → Labels tab → Authorization panel** — the badge shows the current state; the reason textbox + three buttons (Approve / Reject / Revoke) perform the transition. The actor is pulled from your authenticated session.
- **Devices list → row checkboxes** — select one or more rows to reveal the bulk action toolbar with Approve / Reject / Revoke buttons.
- **"Set baseline" banner** — shown above the Devices list when `approved < 5` and no baseline has been set. One click calls `POST /api/baseline/set`.
- **Sticky drawer header** — AuthorizationBadge is always visible at the top of the drawer, regardless of active tab.

---

## Schema

```sql
CREATE TABLE devices (
  mac                TEXT PRIMARY KEY,
  ...
  authorization      TEXT NOT NULL DEFAULT 'unapproved',
  authorized_at      TEXT,
  authorized_by      TEXT,
  ...
);

CREATE TABLE authorization_history (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  mac            TEXT NOT NULL,
  previous_state TEXT NOT NULL,
  new_state      TEXT NOT NULL,
  actor          TEXT NOT NULL,
  reason         TEXT,
  timestamp      TEXT NOT NULL,
  FOREIGN KEY (mac) REFERENCES devices(mac)
);
CREATE INDEX idx_auth_hist_mac ON authorization_history(mac);
CREATE INDEX idx_devices_authorization ON devices(authorization);
```

The `authorization` column is filterable and sortable via `/api/devices?authorization=rejected&sort=authorization`. For rows where the `devices` row doesn't exist yet, the API defaults `authorization` to `unapproved` (via `COALESCE` in the list query) so the state model is consistent regardless of whether a hosts-only device has been materialized into `devices` yet.
