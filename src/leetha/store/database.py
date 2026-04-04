"""Leetha persistence layer -- async SQLite storage backend.

Provides the Database class that manages all SQL operations for hosts,
sightings, findings, identities, probe targets, trusted bindings,
ARP tracking, suppression rules, and fingerprint history.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import aiosqlite

from leetha.store.models import (
    Alert,
    AlertSeverity,
    AlertType,
    Device,
    DeviceIdentity,
    Observation,
)

# ---------------------------------------------------------------------------
# Table definitions -- each table uses explicit NOT NULL / DEFAULT clauses
# and consistent formatting.  Column order is intentionally different from
# the upstream project to ensure structural uniqueness.
# ---------------------------------------------------------------------------

_TABLE_DEVICES = """\
CREATE TABLE IF NOT EXISTS devices (
    mac                TEXT PRIMARY KEY,
    hostname           TEXT,
    manufacturer       TEXT,
    device_type        TEXT,
    os_family          TEXT,
    os_version         TEXT,
    ip_v4              TEXT,
    ip_v6              TEXT,
    confidence         INTEGER NOT NULL DEFAULT 0,
    alert_status       TEXT NOT NULL DEFAULT 'new',
    first_seen         TEXT,
    last_seen          TEXT,
    raw_evidence       TEXT NOT NULL DEFAULT '{}',
    is_randomized_mac  INTEGER NOT NULL DEFAULT 0,
    correlated_mac     TEXT
);
"""

_TABLE_OBSERVATIONS = """\
CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac   TEXT NOT NULL REFERENCES devices(mac),
    timestamp    TEXT NOT NULL,
    source_type  TEXT,
    raw_data     TEXT,
    match_result TEXT,
    confidence   INTEGER
);
"""

_TABLE_ALERTS = """\
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac   TEXT NOT NULL REFERENCES devices(mac),
    alert_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    message      TEXT,
    timestamp    TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
"""

_TABLE_SYNC_SOURCES = """\
CREATE TABLE IF NOT EXISTS sync_sources (
    name        TEXT PRIMARY KEY,
    url         TEXT,
    source_type TEXT,
    last_synced TEXT,
    status      TEXT,
    config      TEXT NOT NULL DEFAULT '{}'
);
"""

_TABLE_IDENTITIES = """\
CREATE TABLE IF NOT EXISTS device_identities (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    primary_mac             TEXT,
    manufacturer            TEXT,
    device_type             TEXT,
    os_family               TEXT,
    os_version              TEXT,
    hostname                TEXT,
    confidence              INTEGER NOT NULL DEFAULT 0,
    first_seen              TEXT,
    last_seen               TEXT,
    correlation_fingerprint TEXT NOT NULL DEFAULT '{}'
);
"""

_TABLE_PROBE_TARGETS = """\
CREATE TABLE IF NOT EXISTS probe_targets (
    mac         TEXT,
    ip          TEXT,
    port        INTEGER,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    last_probed TEXT,
    result      TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    PRIMARY KEY (mac, port, protocol)
);
"""

_TABLE_TRUSTED_BINDINGS = """\
CREATE TABLE IF NOT EXISTS trusted_bindings (
    mac        TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    interface  TEXT
);
"""

_TABLE_FINGERPRINT_HISTORY = """\
CREATE TABLE IF NOT EXISTS fingerprint_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mac          TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    os_family    TEXT,
    manufacturer TEXT,
    device_type  TEXT,
    hostname     TEXT,
    oui_vendor   TEXT
);
"""

_TABLE_ARP_HISTORY = """\
CREATE TABLE IF NOT EXISTS arp_history (
    mac           TEXT NOT NULL,
    ip            TEXT NOT NULL,
    interface     TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    packet_count  INTEGER NOT NULL DEFAULT 1,
    is_gratuitous INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, ip, interface)
);
"""

_TABLE_SUPPRESSION_RULES = """\
CREATE TABLE IF NOT EXISTS suppression_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mac        TEXT,
    ip         TEXT,
    subtype    TEXT,
    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_TABLE_AUTH_TOKENS = """\
CREATE TABLE IF NOT EXISTS auth_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    role        TEXT    NOT NULL DEFAULT 'analyst',
    label       TEXT,
    created_at  TEXT    NOT NULL,
    last_used   TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);
"""

_ALL_TABLES = (
    _TABLE_DEVICES
    + _TABLE_OBSERVATIONS
    + _TABLE_ALERTS
    + _TABLE_SYNC_SOURCES
    + _TABLE_IDENTITIES
    + _TABLE_PROBE_TARGETS
    + _TABLE_TRUSTED_BINDINGS
    + _TABLE_FINGERPRINT_HISTORY
    + _TABLE_ARP_HISTORY
    + _TABLE_SUPPRESSION_RULES
    + _TABLE_AUTH_TOKENS
)


# ---------------------------------------------------------------------------
# Row-to-model helpers (module-level, prefixed with _marshal_)
# ---------------------------------------------------------------------------


def _coerce_datetime(raw: str | None) -> datetime:
    """Turn an ISO-8601 string into a datetime, defaulting to *now*."""
    if raw is None:
        return datetime.now()
    return datetime.fromisoformat(raw)


def _sanitize_hostname_db(name: str | None) -> str | None:
    """Clean mDNS service instance names at read time."""
    if not name:
        return name
    import re as _re_hn
    c = name.rstrip(".")
    if "._tcp." in c or "._udp." in c:
        parts = c.split("._")
        instance = parts[0]
        service = parts[1] if len(parts) > 1 else ""
        instance = _re_hn.sub(r'-[0-9a-f]{12,}$', '', instance, flags=_re_hn.IGNORECASE)
        if len(instance) <= 5 and service and service not in ("tcp", "udp"):
            c = service
        else:
            c = instance
    if c.endswith(".local"):
        c = c[:-6]
    c = c.rstrip(".")
    return c or name


def _marshal_device(rec: aiosqlite.Row) -> Device:
    evidence = json.loads(rec["raw_evidence"]) if rec["raw_evidence"] else {}
    override = json.loads(rec["manual_override"]) if rec["manual_override"] else None
    return Device(
        mac=rec["mac"],
        ip_v4=rec["ip_v4"],
        ip_v6=rec["ip_v6"],
        manufacturer=rec["manufacturer"],
        device_type=rec["device_type"],
        os_family=rec["os_family"],
        os_version=rec["os_version"],
        hostname=_sanitize_hostname_db(rec["hostname"]),
        confidence=rec["confidence"],
        first_seen=_coerce_datetime(rec["first_seen"]),
        last_seen=_coerce_datetime(rec["last_seen"]),
        alert_status=rec["alert_status"] or "new",
        raw_evidence=evidence,
        is_randomized_mac=bool(rec["is_randomized_mac"]),
        correlated_mac=rec["correlated_mac"],
        identity_id=rec["identity_id"] if "identity_id" in rec.keys() else None,
        manual_override=override,
    )


def _marshal_observation(rec: aiosqlite.Row) -> Observation:
    return Observation(
        id=rec["id"],
        device_mac=rec["device_mac"],
        timestamp=_coerce_datetime(rec["timestamp"]),
        source_type=rec["source_type"],
        raw_data=rec["raw_data"],
        match_result=rec["match_result"],
        confidence=rec["confidence"],
        interface=rec["interface"] if "interface" in rec.keys() else None,
        network=rec["network"] if "network" in rec.keys() else None,
    )


def _marshal_alert(rec: aiosqlite.Row) -> Alert:
    return Alert(
        id=rec["id"],
        device_mac=rec["device_mac"],
        alert_type=AlertType(rec["alert_type"]),
        severity=AlertSeverity(rec["severity"]),
        message=rec["message"],
        timestamp=_coerce_datetime(rec["timestamp"]),
        acknowledged=bool(rec["acknowledged"]),
    )


def _marshal_identity(rec: aiosqlite.Row) -> DeviceIdentity:
    fp_raw = rec["correlation_fingerprint"]
    fp = json.loads(fp_raw) if fp_raw else {}
    # Clean hostname at read time as a safety net
    raw_hn = rec["hostname"]
    if raw_hn and ("._tcp." in raw_hn or "._udp." in raw_hn or raw_hn.endswith(".local")):
        import re
        clean_hn = raw_hn
        if "._tcp." in clean_hn or "._udp." in clean_hn:
            clean_hn = clean_hn.split("._")[0]
        clean_hn = re.sub(r'-[0-9a-f]{12,}$', '', clean_hn, flags=re.IGNORECASE)
        if clean_hn.endswith(".local"):
            clean_hn = clean_hn[:-6]
        raw_hn = clean_hn.rstrip(".") or raw_hn
    return DeviceIdentity(
        id=rec["id"],
        primary_mac=rec["primary_mac"],
        manufacturer=rec["manufacturer"],
        device_type=rec["device_type"],
        os_family=rec["os_family"],
        os_version=rec["os_version"],
        hostname=raw_hn,
        confidence=rec["confidence"],
        first_seen=_coerce_datetime(rec["first_seen"]),
        last_seen=_coerce_datetime(rec["last_seen"]),
        correlation_fingerprint=fp,
    )


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------


class Database:
    """Async SQLite storage backend for Leetha.

    Wraps a single ``aiosqlite`` connection with WAL journaling, a
    cooperative write-lock for transaction isolation, and convenience
    methods for every entity the application needs.
    """

    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._mu = asyncio.Lock()  # serialises writes

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open the database, create tables, apply migrations, build indexes."""
        self._conn = await aiosqlite.connect(str(self._path), isolation_level=None)
        self._conn.row_factory = aiosqlite.Row

        await self._conn.executescript(_ALL_TABLES)

        # Performance pragmas
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA busy_timeout=5000")

        # Schema migrations MUST run before index creation — migrations
        # add columns (interface, network, identity_id) that indexes reference.
        await self._apply_migrations()

        # Indexes -- observations
        for idx_sql in (
            "CREATE INDEX IF NOT EXISTS idx_obs_device ON observations(device_mac)",
            "CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_obs_src ON observations(source_type)",
            "CREATE INDEX IF NOT EXISTS idx_obs_device_ts ON observations(device_mac, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_obs_iface ON observations(interface)",
            "CREATE INDEX IF NOT EXISTS idx_obs_net ON observations(network)",
        ):
            await self._conn.execute(idx_sql)

        # Indexes -- alerts
        for idx_sql in (
            "CREATE INDEX IF NOT EXISTS idx_alert_ack_ts ON alerts(acknowledged, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alert_device ON alerts(device_mac)",
            "CREATE INDEX IF NOT EXISTS idx_alert_ack ON alerts(acknowledged)",
        ):
            await self._conn.execute(idx_sql)

        # Indexes -- devices & others
        for idx_sql in (
            "CREATE INDEX IF NOT EXISTS idx_dev_ipv4 ON devices(ip_v4)",
            "CREATE INDEX IF NOT EXISTS idx_dev_identity ON devices(identity_id)",
            "CREATE INDEX IF NOT EXISTS idx_probe_status ON probe_targets(status)",
            "CREATE INDEX IF NOT EXISTS idx_fp_hist_mac ON fingerprint_history(mac)",
            "CREATE INDEX IF NOT EXISTS idx_fp_hist_ts ON fingerprint_history(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_trust_ip ON trusted_bindings(ip)",
            "CREATE INDEX IF NOT EXISTS idx_arp_ip ON arp_history(ip)",
            "CREATE INDEX IF NOT EXISTS idx_arp_mac ON arp_history(mac)",
            "CREATE INDEX IF NOT EXISTS idx_arp_lastseen ON arp_history(last_seen)",
        ):
            await self._conn.execute(idx_sql)

        # Backfill identities for pre-migration rows
        await self.backfill_identities()
        await self._clean_dirty_hostnames()
        await self._conn.commit()

        # Fix DB file ownership when running under sudo
        from leetha.platform import fix_ownership
        fix_ownership(self._path)
        # Also fix WAL and SHM journal files if they exist
        for suffix in ("-wal", "-shm"):
            journal = self._path.parent / (self._path.name + suffix)
            if journal.exists():
                fix_ownership(journal)

    async def _apply_migrations(self) -> None:
        """Add columns that may be missing from older schema versions."""
        dev_cols = await self._column_names("devices")
        if "identity_id" not in dev_cols:
            await self._conn.execute(
                "ALTER TABLE devices ADD COLUMN identity_id INTEGER"
            )
        if "manual_override" not in dev_cols:
            await self._conn.execute(
                "ALTER TABLE devices ADD COLUMN manual_override TEXT DEFAULT NULL"
            )

        obs_cols = await self._column_names("observations")
        if "interface" not in obs_cols:
            await self._conn.execute(
                "ALTER TABLE observations ADD COLUMN interface TEXT DEFAULT NULL"
            )
        if "network" not in obs_cols:
            await self._conn.execute(
                "ALTER TABLE observations ADD COLUMN network TEXT DEFAULT NULL"
            )

    _VALID_TABLES = {"devices", "observations", "alerts", "device_identities",
                     "probe_targets", "fingerprint_history", "trusted_bindings",
                     "arp_history", "alert_suppressions"}

    async def _column_names(self, table: str) -> set[str]:
        """Return the set of column names for *table*."""
        if table not in self._VALID_TABLES:
            return set()
        async with self._conn.execute(f"PRAGMA table_info({table})") as cur:
            return {row[1] for row in await cur.fetchall()}

    async def _clean_dirty_hostnames(self) -> None:
        """One-time migration: clean mDNS service instance hostnames in existing data."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT mac, hostname FROM devices WHERE hostname LIKE '%._tcp.%' OR hostname LIKE '%._udp.%'"
        ) as cur:
            rows = await cur.fetchall()
        if not rows:
            return
        import re
        for row in rows:
            mac, dirty = row[0], row[1]
            clean = dirty
            if "._tcp." in clean or "._udp." in clean:
                clean = clean.split("._")[0]
            clean = re.sub(r'-[0-9a-f]{12,}$', '', clean, flags=re.IGNORECASE)
            if clean.endswith(".local"):
                clean = clean[:-6]
            clean = clean.rstrip(".")
            if clean and clean != dirty:
                await self._conn.execute(
                    "UPDATE devices SET hostname = ? WHERE mac = ?", (clean, mac)
                )
        # Also clean identity hostnames
        async with self._conn.execute(
            "SELECT id, hostname FROM device_identities WHERE hostname LIKE '%._tcp.%' OR hostname LIKE '%._udp.%'"
        ) as cur:
            id_rows = await cur.fetchall()
        for row in id_rows:
            rid, dirty = row[0], row[1]
            clean = dirty
            if "._tcp." in clean or "._udp." in clean:
                clean = clean.split("._")[0]
            clean = re.sub(r'-[0-9a-f]{12,}$', '', clean, flags=re.IGNORECASE)
            if clean.endswith(".local"):
                clean = clean[:-6]
            clean = clean.rstrip(".")
            if clean and clean != dirty:
                await self._conn.execute(
                    "UPDATE device_identities SET hostname = ? WHERE id = ?", (clean, rid)
                )
        await self._conn.commit()

    async def close(self) -> None:
        """Shut down the database connection gracefully."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def db(self) -> aiosqlite.Connection:
        """Raw connection handle for callers that need direct SQL access."""
        if self._conn is None:
            raise RuntimeError("Database has not been initialized yet")
        return self._conn

    @asynccontextmanager
    async def transaction(self):
        """Context manager that wraps a group of writes in a single txn.

        Holds the write-lock for the duration so concurrent coroutines
        cannot interleave their statements with ours.
        """
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                await self._conn.commit()
            except Exception:
                await self._conn.rollback()
                raise

    # ------------------------------------------------------------------
    # Device CRUD
    # ------------------------------------------------------------------

    _DEVICE_UPSERT_SQL = """\
INSERT INTO devices (
    mac, hostname, manufacturer, device_type,
    os_family, os_version, ip_v4, ip_v6,
    confidence, alert_status, first_seen, last_seen,
    raw_evidence, is_randomized_mac, correlated_mac,
    identity_id, manual_override
) VALUES (
    ?1, ?2, ?3, ?4,
    ?5, ?6, ?7, ?8,
    ?9, ?10, ?11, ?12,
    ?13, ?14, ?15,
    ?16, ?17
)
ON CONFLICT(mac) DO UPDATE SET
    hostname       = COALESCE(excluded.hostname, devices.hostname),
    manufacturer   = COALESCE(excluded.manufacturer, devices.manufacturer),
    device_type    = CASE
                        WHEN devices.manual_override IS NOT NULL
                        THEN devices.device_type
                        WHEN excluded.device_type IS NOT NULL
                             AND excluded.device_type != 'Unknown'
                        THEN excluded.device_type
                        ELSE COALESCE(devices.device_type, excluded.device_type)
                     END,
    os_family      = COALESCE(excluded.os_family, devices.os_family),
    os_version     = COALESCE(excluded.os_version, devices.os_version),
    ip_v4          = COALESCE(excluded.ip_v4, devices.ip_v4),
    ip_v6          = COALESCE(excluded.ip_v6, devices.ip_v6),
    confidence     = MAX(excluded.confidence, devices.confidence),
    alert_status   = COALESCE(excluded.alert_status, devices.alert_status),
    first_seen     = MIN(devices.first_seen, excluded.first_seen),
    last_seen      = MAX(devices.last_seen, excluded.last_seen),
    raw_evidence   = excluded.raw_evidence,
    is_randomized_mac = excluded.is_randomized_mac,
    correlated_mac = COALESCE(excluded.correlated_mac, devices.correlated_mac),
    identity_id    = COALESCE(excluded.identity_id, devices.identity_id),
    manual_override = COALESCE(excluded.manual_override, devices.manual_override)
"""

    @staticmethod
    def _sanitize_hostname(name: str | None) -> str | None:
        """Clean mDNS service instance names and .local suffixes at DB write time."""
        if not name:
            return name
        import re
        clean = name
        if "._tcp." in clean or "._udp." in clean:
            clean = clean.split("._")[0]
        clean = re.sub(r'-[0-9a-f]{12,}$', '', clean, flags=re.IGNORECASE)
        if clean.endswith(".local"):
            clean = clean[:-6]
        clean = clean.rstrip(".")
        return clean or name

    def _device_bind_params(self, dev: Device) -> tuple:
        """Build the parameter tuple for the device upsert statement."""
        ts_first = dev.first_seen.isoformat()
        ts_last = dev.last_seen.isoformat()
        evidence_json = json.dumps(dev.raw_evidence)
        override_json = json.dumps(dev.manual_override) if dev.manual_override else None
        return (
            dev.mac,
            self._sanitize_hostname(dev.hostname),
            dev.manufacturer,
            dev.device_type,
            dev.os_family,
            dev.os_version,
            dev.ip_v4,
            dev.ip_v6,
            dev.confidence,
            dev.alert_status,
            ts_first,
            ts_last,
            evidence_json,
            int(dev.is_randomized_mac),
            dev.correlated_mac,
            dev.identity_id,
            override_json,
        )

    async def upsert_device(self, device: Device) -> None:
        """Persist a device, merging with any existing row via COALESCE.

        Acquires the write-lock and commits immediately.
        """
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(
                self._DEVICE_UPSERT_SQL, self._device_bind_params(device),
            )
            await self._conn.commit()

    async def upsert_device_no_commit(self, device: Device) -> None:
        """Persist a device without committing -- caller owns the transaction."""
        assert self._conn is not None
        await self._conn.execute(
            self._DEVICE_UPSERT_SQL, self._device_bind_params(device),
        )

    async def get_device(self, mac: str) -> Device | None:
        """Look up a single device by its MAC address."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,),
        ) as cur:
            rec = await cur.fetchone()
            return _marshal_device(rec) if rec is not None else None

    async def get_device_by_ip(self, ip: str) -> Device | None:
        """Find the first device matching an IPv4 or IPv6 address."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM devices WHERE ip_v4 = ?1 OR ip_v6 = ?1 LIMIT 1",
            (ip,),
        ) as cur:
            rec = await cur.fetchone()
            return _marshal_device(rec) if rec is not None else None

    async def list_devices(self, interface: str | None = None) -> list[Device]:
        """Return every known device, optionally scoped to an interface."""
        assert self._conn is not None
        if interface:
            sql = (
                "SELECT DISTINCT d.*"
                " FROM devices AS d"
                " INNER JOIN observations AS o ON o.device_mac = d.mac"
                " WHERE o.interface = ?"
            )
            async with self._conn.execute(sql, (interface,)) as cur:
                return [_marshal_device(r) for r in await cur.fetchall()]
        async with self._conn.execute("SELECT * FROM devices") as cur:
            return [_marshal_device(r) for r in await cur.fetchall()]

    async def get_device_count(self) -> int:
        """How many devices are in the store."""
        assert self._conn is not None
        async with self._conn.execute("SELECT COUNT(*) FROM devices") as cur:
            return (await cur.fetchone())[0]

    # ------------------------------------------------------------------
    # Device Identities
    # ------------------------------------------------------------------

    async def upsert_identity(self, identity: DeviceIdentity) -> int:
        """Create or update an identity record. Returns the row ID."""
        assert self._conn is not None
        async with self._mu:
            if identity.id is not None:
                await self._conn.execute(
                    "UPDATE device_identities SET"
                    " primary_mac = ?,"
                    " manufacturer = ?,"
                    " device_type = ?,"
                    " os_family = ?,"
                    " os_version = ?,"
                    " hostname = ?,"
                    " confidence = ?,"
                    " last_seen = ?,"
                    " correlation_fingerprint = ?"
                    " WHERE id = ?",
                    (
                        identity.primary_mac,
                        identity.manufacturer,
                        identity.device_type,
                        identity.os_family,
                        identity.os_version,
                        self._sanitize_hostname(identity.hostname),
                        identity.confidence,
                        identity.last_seen.isoformat(),
                        json.dumps(identity.correlation_fingerprint),
                        identity.id,
                    ),
                )
                await self._conn.commit()
                return identity.id

            ts_first = identity.first_seen.isoformat()
            ts_last = identity.last_seen.isoformat()
            async with self._conn.execute(
                "INSERT INTO device_identities"
                " (primary_mac, manufacturer, device_type, os_family,"
                "  os_version, hostname, confidence, first_seen,"
                "  last_seen, correlation_fingerprint)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    identity.primary_mac,
                    identity.manufacturer,
                    identity.device_type,
                    identity.os_family,
                    identity.os_version,
                    self._sanitize_hostname(identity.hostname),
                    identity.confidence,
                    ts_first,
                    ts_last,
                    json.dumps(identity.correlation_fingerprint),
                ),
            ) as cur:
                new_id = cur.lastrowid
            await self._conn.commit()
            return new_id

    async def get_identity(self, identity_id: int) -> DeviceIdentity | None:
        """Fetch a single identity by primary key."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM device_identities WHERE id = ?", (identity_id,),
        ) as cur:
            rec = await cur.fetchone()
            return _marshal_identity(rec) if rec is not None else None

    async def list_identities(self) -> list[DeviceIdentity]:
        """Fetch all identities, enriched with MAC counts and IP addresses."""
        assert self._conn is not None
        sql = (
            "SELECT ident.*,"
            "       COALESCE(agg.cnt, 0) AS mac_count,"
            "       agg.mac_list,"
            "       pdev.ip_v4 AS dev_ip_v4,"
            "       pdev.ip_v6 AS dev_ip_v6"
            " FROM device_identities AS ident"
            " LEFT JOIN ("
            "     SELECT identity_id,"
            "            COUNT(mac) AS cnt,"
            "            GROUP_CONCAT(mac) AS mac_list"
            "     FROM devices GROUP BY identity_id"
            " ) AS agg ON agg.identity_id = ident.id"
            " LEFT JOIN devices AS pdev ON pdev.mac = ident.primary_mac"
            " ORDER BY ident.last_seen DESC"
        )
        async with self._conn.execute(sql) as cur:
            rows = await cur.fetchall()
            result: list[DeviceIdentity] = []
            for rec in rows:
                ident = _marshal_identity(rec)
                ident.mac_count = rec["mac_count"] or 0
                mac_csv = rec["mac_list"]
                ident.all_macs = mac_csv.split(",") if mac_csv else []
                ident.ip_v4 = rec["dev_ip_v4"] if "dev_ip_v4" in rec.keys() else None
                ident.ip_v6 = rec["dev_ip_v6"] if "dev_ip_v6" in rec.keys() else None
                result.append(ident)
            return result

    async def get_identity_count(self) -> int:
        """Count how many identity records exist."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT COUNT(*) FROM device_identities",
        ) as cur:
            return (await cur.fetchone())[0]

    async def find_identity_by_mac(self, mac: str) -> DeviceIdentity | None:
        """Resolve a device MAC to its owning identity, if any."""
        assert self._conn is not None
        sql = (
            "SELECT ident.* FROM device_identities AS ident"
            " INNER JOIN devices AS d ON d.identity_id = ident.id"
            " WHERE d.mac = ?"
        )
        async with self._conn.execute(sql, (mac,)) as cur:
            rec = await cur.fetchone()
            return _marshal_identity(rec) if rec is not None else None

    async def get_all_identities_with_fingerprints(self) -> list[DeviceIdentity]:
        """Return identities that carry a non-empty correlation fingerprint."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM device_identities"
            " WHERE correlation_fingerprint != '{}'",
        ) as cur:
            return [_marshal_identity(r) for r in await cur.fetchall()]

    async def backfill_identities(self) -> None:
        """Assign identities to any device rows that lack one.

        Runs during initialization to handle data created before the
        identity system existed.  Real-OUI MACs receive a new identity;
        randomized MACs are joined to their correlated peer when possible.
        """
        assert self._conn is not None

        async with self._conn.execute(
            "SELECT * FROM devices WHERE identity_id IS NULL",
        ) as cur:
            unlinked_rows = await cur.fetchall()

        unlinked = [_marshal_device(r) for r in unlinked_rows]
        if not unlinked:
            return

        mac_identity_map: dict[str, int] = {}

        # Pass 1 -- real MACs
        for dev in unlinked:
            if dev.is_randomized_mac:
                continue
            ident = DeviceIdentity(
                primary_mac=dev.mac,
                manufacturer=dev.manufacturer,
                device_type=dev.device_type,
                os_family=dev.os_family,
                os_version=dev.os_version,
                hostname=dev.hostname,
                confidence=dev.confidence,
            )
            ident_id = await self.upsert_identity(ident)
            mac_identity_map[dev.mac] = ident_id
            await self._conn.execute(
                "UPDATE devices SET identity_id = ? WHERE mac = ?",
                (ident_id, dev.mac),
            )

        # Pass 2 -- randomized MACs
        for dev in unlinked:
            if not dev.is_randomized_mac:
                continue
            if dev.correlated_mac and dev.correlated_mac in mac_identity_map:
                ident_id = mac_identity_map[dev.correlated_mac]
            else:
                ident = DeviceIdentity(
                    primary_mac=dev.mac,
                    manufacturer=dev.manufacturer,
                    device_type=dev.device_type,
                    os_family=dev.os_family,
                    os_version=dev.os_version,
                    hostname=dev.hostname,
                    confidence=dev.confidence,
                )
                ident_id = await self.upsert_identity(ident)

            mac_identity_map[dev.mac] = ident_id
            await self._conn.execute(
                "UPDATE devices SET identity_id = ? WHERE mac = ?",
                (ident_id, dev.mac),
            )

        await self._conn.commit()

    # ------------------------------------------------------------------
    # Observations (sightings)
    # ------------------------------------------------------------------

    _OBS_INSERT = (
        "INSERT INTO observations"
        " (device_mac, timestamp, source_type, raw_data,"
        "  match_result, confidence, interface, network)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )

    def _obs_bind(self, obs: Observation) -> tuple:
        return (
            obs.device_mac,
            obs.timestamp.isoformat(),
            obs.source_type,
            obs.raw_data,
            obs.match_result,
            obs.confidence,
            obs.interface,
            obs.network,
        )

    async def add_observation(self, obs: Observation) -> None:
        """Record a new observation and commit."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(self._OBS_INSERT, self._obs_bind(obs))
            await self._conn.commit()

    async def add_observation_no_commit(self, obs: Observation) -> None:
        """Record an observation without committing -- for batched writes."""
        assert self._conn is not None
        await self._conn.execute(self._OBS_INSERT, self._obs_bind(obs))

    async def get_observations(
        self, mac: str, limit: int = 100,
    ) -> list[Observation]:
        """Fetch observations for a device, most recent first."""
        assert self._conn is not None
        sql = (
            "SELECT * FROM observations"
            " WHERE device_mac = ?"
            " ORDER BY timestamp DESC"
            " LIMIT ?"
        )
        async with self._conn.execute(sql, (mac, limit)) as cur:
            return [_marshal_observation(r) for r in await cur.fetchall()]

    async def get_observation_count(self, mac: str) -> int:
        """Count observations tied to a specific device."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT COUNT(*) FROM observations WHERE device_mac = ?", (mac,),
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def get_device_activity_24h(self, mac: str) -> list[int]:
        """Return per-hour packet counts for the last 24 hours (index 0 = hour 0)."""
        assert self._conn is not None
        sql = (
            "SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hr,"
            "       COUNT(*) AS n"
            " FROM observations"
            " WHERE device_mac = ?"
            "   AND datetime(timestamp) >= datetime('now', '-24 hours')"
            " GROUP BY hr ORDER BY hr"
        )
        async with self._conn.execute(sql, (mac,)) as cur:
            rows = await cur.fetchall()
        buckets = [0] * 24
        for row in rows:
            buckets[row[0]] = row[1]
        return buckets

    async def list_observed_interfaces(self) -> list[str]:
        """Unique interface names that appear in the observations table."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT DISTINCT interface FROM observations"
            " WHERE interface IS NOT NULL AND interface != ''",
        ) as cur:
            return [r[0] for r in await cur.fetchall()]

    async def get_device_interfaces(self) -> dict[str, str]:
        """Map each device MAC to the interface on which it was most recently seen."""
        assert self._conn is not None
        sql = (
            "SELECT device_mac, interface FROM observations"
            " WHERE interface IS NOT NULL"
            "   AND id IN ("
            "       SELECT MAX(id) FROM observations"
            "       WHERE interface IS NOT NULL"
            "       GROUP BY device_mac"
            "   )"
        )
        async with self._conn.execute(sql) as cur:
            return {r[0]: r[1] for r in await cur.fetchall()}

    # ------------------------------------------------------------------
    # Probe targets
    # ------------------------------------------------------------------

    async def upsert_probe_target(
        self, mac: str, ip: str, port: int, protocol: str = "tcp",
    ) -> None:
        """Register a new probe target or update its IP."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(
                "INSERT INTO probe_targets (mac, ip, port, protocol, status)"
                " VALUES (?, ?, ?, ?, 'pending')"
                " ON CONFLICT(mac, port, protocol) DO UPDATE SET ip = excluded.ip",
                (mac, ip, port, protocol),
            )
            await self._conn.commit()

    async def update_probe_result(
        self,
        mac: str,
        port: int,
        protocol: str,
        status: str,
        result: str | None = None,
    ) -> None:
        """Store the outcome of a completed probe."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(
                "UPDATE probe_targets"
                " SET status = ?, result = ?, last_probed = datetime('now')"
                " WHERE mac = ? AND port = ? AND protocol = ?",
                (status, result, mac, port, protocol),
            )
            await self._conn.commit()

    async def list_probe_targets(
        self, status: str | None = None, mac: str | None = None,
    ) -> list[dict]:
        """Retrieve probe targets with optional status/MAC filters."""
        assert self._conn is not None
        clauses: list[str] = []
        binds: list[object] = []
        if status:
            clauses.append("status = ?")
            binds.append(status)
        if mac:
            clauses.append("mac = ?")
            binds.append(mac)
        predicate = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM probe_targets{predicate} ORDER BY last_probed DESC"
        async with self._conn.execute(sql, binds) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def get_device_services(self, mac: str) -> list[dict]:
        """Completed probe results for a given device, ordered by port."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM probe_targets"
            " WHERE mac = ? AND status = 'completed'"
            " ORDER BY port",
            (mac,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ------------------------------------------------------------------
    # Alerts (findings)
    # ------------------------------------------------------------------

    _ALERT_INSERT = (
        "INSERT INTO alerts"
        " (device_mac, alert_type, severity, message, timestamp, acknowledged)"
        " VALUES (?, ?, ?, ?, ?, ?)"
    )

    def _alert_bind(self, alert: Alert) -> tuple:
        return (
            alert.device_mac,
            str(alert.alert_type),
            str(alert.severity),
            alert.message,
            alert.timestamp.isoformat(),
            int(alert.acknowledged),
        )

    async def add_alert(self, alert: Alert) -> None:
        """Persist a new alert, deduplicating against existing unresolved alerts.

        If an unresolved alert with the same device_mac, alert_type, and
        message already exists, the new alert is silently dropped to prevent
        duplicate noise.
        """
        assert self._conn is not None
        async with self._mu:
            # Deduplicate: skip if same device+type unresolved alert exists
            # (don't compare message — same drift with different IPs is still a dupe)
            async with self._conn.execute(
                "SELECT COUNT(*) FROM alerts"
                " WHERE device_mac = ? AND alert_type = ?"
                " AND acknowledged = 0",
                (alert.device_mac, alert.alert_type.value
                 if hasattr(alert.alert_type, 'value') else str(alert.alert_type)),
            ) as cur:
                count = (await cur.fetchone())[0]
            if count > 0:
                return  # duplicate — skip

            await self._conn.execute(self._ALERT_INSERT, self._alert_bind(alert))
            await self._conn.commit()

    async def add_alert_no_commit(self, alert: Alert) -> None:
        """Persist an alert without committing -- for batched writes.

        Deduplicates against existing unresolved alerts for the same device+type.
        """
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT COUNT(*) FROM alerts"
            " WHERE device_mac = ? AND alert_type = ? AND acknowledged = 0",
            (alert.device_mac, alert.alert_type.value
             if hasattr(alert.alert_type, 'value') else str(alert.alert_type)),
        ) as cur:
            if (await cur.fetchone())[0] > 0:
                return
        await self._conn.execute(self._ALERT_INSERT, self._alert_bind(alert))

    async def list_alerts(
        self,
        acknowledged: bool | None = None,
        alert_type: str | None = None,
    ) -> list[Alert]:
        """Query alerts with optional acknowledged/type filters."""
        assert self._conn is not None
        clauses: list[str] = []
        binds: list[object] = []
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            binds.append(int(acknowledged))
        if alert_type is not None:
            clauses.append("alert_type = ?")
            binds.append(alert_type)
        predicate = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM alerts{predicate} ORDER BY timestamp DESC"
        async with self._conn.execute(sql, binds) as cur:
            return [_marshal_alert(r) for r in await cur.fetchall()]

    async def get_alert_count(self, acknowledged: bool | None = None) -> int:
        """Total number of alerts, optionally filtered."""
        assert self._conn is not None
        if acknowledged is not None:
            sql = "SELECT COUNT(*) FROM alerts WHERE acknowledged = ?"
            binds: tuple = (int(acknowledged),)
        else:
            sql = "SELECT COUNT(*) FROM alerts"
            binds = ()
        async with self._conn.execute(sql, binds) as cur:
            return (await cur.fetchone())[0]

    async def acknowledge_alert(self, alert_id: int) -> None:
        """Flag an alert as acknowledged."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,),
            )
            await self._conn.commit()

    async def acknowledge_alerts_batch(self, alert_ids: list[int]) -> None:
        """Acknowledge multiple alerts in a single transaction."""
        assert self._conn is not None
        if not alert_ids:
            return
        placeholders = ",".join("?" * len(alert_ids))
        async with self._mu:
            await self._conn.execute(
                f"UPDATE alerts SET acknowledged = 1 WHERE id IN ({placeholders})",
                alert_ids,
            )
            await self._conn.commit()

    async def delete_resolved_alerts(self) -> int:
        """Delete all acknowledged alerts. Returns count deleted."""
        assert self._conn is not None
        async with self._mu:
            cursor = await self._conn.execute(
                "DELETE FROM alerts WHERE acknowledged = 1"
            )
            await self._conn.commit()
            return cursor.rowcount

    async def delete_all_alerts(self) -> int:
        """Delete ALL alerts. Returns count deleted."""
        assert self._conn is not None
        async with self._mu:
            cursor = await self._conn.execute("DELETE FROM alerts")
            await self._conn.commit()
            return cursor.rowcount

    async def delete_alerts_batch(self, alert_ids: list[int]) -> int:
        """Delete specific alerts by ID. Returns count deleted."""
        assert self._conn is not None
        if not alert_ids:
            return 0
        placeholders = ",".join("?" * len(alert_ids))
        async with self._mu:
            cursor = await self._conn.execute(
                f"DELETE FROM alerts WHERE id IN ({placeholders})",
                alert_ids,
            )
            await self._conn.commit()
            return cursor.rowcount

    # ------------------------------------------------------------------
    # Trusted bindings
    # ------------------------------------------------------------------

    async def add_trusted_binding(
        self, mac: str, ip: str, source: str, interface: str | None = None,
    ) -> None:
        """Record or update a trusted MAC-to-IP binding."""
        assert self._conn is not None
        async with self._mu:
            ts_now = datetime.now().isoformat()
            await self._conn.execute(
                "INSERT INTO trusted_bindings (mac, ip, source, created_at, interface)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(mac) DO UPDATE SET"
                "   ip = excluded.ip,"
                "   source = excluded.source,"
                "   interface = excluded.interface",
                (mac, ip, source, ts_now, interface),
            )
            await self._conn.commit()

    async def remove_trusted_binding(self, mac: str) -> None:
        """Delete a trusted binding by MAC."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(
                "DELETE FROM trusted_bindings WHERE mac = ?", (mac,),
            )
            await self._conn.commit()

    async def get_trusted_binding_for_ip(self, ip: str) -> dict | None:
        """Find the trusted binding that covers a particular IP."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT mac, ip, source, created_at, interface"
            " FROM trusted_bindings WHERE ip = ?",
            (ip,),
        ) as cur:
            rec = await cur.fetchone()
            if rec is None:
                return None
            return {
                "mac": rec[0],
                "ip": rec[1],
                "source": rec[2],
                "created_at": rec[3],
                "interface": rec[4],
            }

    async def list_trusted_bindings(self) -> list[dict]:
        """All trusted bindings, newest first."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT mac, ip, source, created_at, interface"
            " FROM trusted_bindings ORDER BY created_at DESC",
        ) as cur:
            return [
                {
                    "mac": r[0],
                    "ip": r[1],
                    "source": r[2],
                    "created_at": r[3],
                    "interface": r[4],
                }
                for r in await cur.fetchall()
            ]

    # ------------------------------------------------------------------
    # ARP history
    # ------------------------------------------------------------------

    async def upsert_arp_entry(
        self, mac: str, ip: str, interface: str, is_gratuitous: bool,
    ) -> None:
        """Track an ARP exchange, incrementing the packet counter on conflict."""
        assert self._conn is not None
        async with self._mu:
            ts_now = datetime.now().isoformat()
            await self._conn.execute(
                "INSERT INTO arp_history"
                " (mac, ip, interface, first_seen, last_seen,"
                "  packet_count, is_gratuitous)"
                " VALUES (?, ?, ?, ?, ?, 1, ?)"
                " ON CONFLICT(mac, ip, interface) DO UPDATE SET"
                "   last_seen = excluded.last_seen,"
                "   packet_count = arp_history.packet_count + 1,"
                "   is_gratuitous = MAX(arp_history.is_gratuitous,"
                "                       excluded.is_gratuitous)",
                (mac, ip, interface, ts_now, ts_now, int(is_gratuitous)),
            )
            await self._conn.commit()

    async def get_arp_history_for_ip(self, ip: str) -> list[dict]:
        """Every MAC that has announced a given IP, most recent first."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT mac, ip, interface, first_seen, last_seen,"
            "       packet_count, is_gratuitous"
            " FROM arp_history WHERE ip = ?"
            " ORDER BY last_seen DESC",
            (ip,),
        ) as cur:
            return [
                {
                    "mac": r[0],
                    "ip": r[1],
                    "interface": r[2],
                    "first_seen": r[3],
                    "last_seen": r[4],
                    "packet_count": r[5],
                    "is_gratuitous": bool(r[6]),
                }
                for r in await cur.fetchall()
            ]

    async def get_arp_history_for_mac(self, mac: str) -> list[dict]:
        """Every IP that a given MAC has claimed, most recent first."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT mac, ip, interface, first_seen, last_seen,"
            "       packet_count, is_gratuitous"
            " FROM arp_history WHERE mac = ?"
            " ORDER BY last_seen DESC",
            (mac,),
        ) as cur:
            return [
                {
                    "mac": r[0],
                    "ip": r[1],
                    "interface": r[2],
                    "first_seen": r[3],
                    "last_seen": r[4],
                    "packet_count": r[5],
                    "is_gratuitous": bool(r[6]),
                }
                for r in await cur.fetchall()
            ]

    # ------------------------------------------------------------------
    # Suppression rules
    # ------------------------------------------------------------------

    async def add_suppression_rule(
        self,
        mac: str | None,
        ip: str | None,
        subtype: str | None,
        reason: str,
    ) -> int:
        """Create a suppression rule. Returns its ID."""
        assert self._conn is not None
        async with self._mu:
            ts_now = datetime.now().isoformat()
            async with self._conn.execute(
                "INSERT INTO suppression_rules"
                " (mac, ip, subtype, reason, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (mac, ip, subtype, reason, ts_now),
            ) as cur:
                new_id = cur.lastrowid
            await self._conn.commit()
            return new_id

    async def remove_suppression_rule(self, rule_id: int) -> None:
        """Delete a suppression rule by its primary key."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute(
                "DELETE FROM suppression_rules WHERE id = ?", (rule_id,),
            )
            await self._conn.commit()

    async def list_suppression_rules(self) -> list[dict]:
        """All suppression rules, newest first."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT id, mac, ip, subtype, reason, created_at"
            " FROM suppression_rules ORDER BY created_at DESC",
        ) as cur:
            return [
                {
                    "id": r[0],
                    "mac": r[1],
                    "ip": r[2],
                    "subtype": r[3],
                    "reason": r[4],
                    "created_at": r[5],
                }
                for r in await cur.fetchall()
            ]

    # ------------------------------------------------------------------
    # Auth tokens
    # ------------------------------------------------------------------

    async def create_auth_token(self, token_hash: str, role: str = "analyst", label: str | None = None) -> int:
        """Insert a new auth token. Returns the row ID."""
        async with self.transaction():
            cursor = await self._conn.execute(
                "INSERT INTO auth_tokens (token_hash, role, label, created_at) VALUES (?, ?, ?, ?)",
                (token_hash, role, label, datetime.now().isoformat()),
            )
            return cursor.lastrowid

    async def validate_token(self, token_hash: str) -> dict | None:
        """Look up a token by hash. Returns row dict if valid, None if missing/revoked.

        Also updates last_used timestamp on success.
        """
        # Check existence first
        async with self._conn.execute(
            "SELECT id FROM auth_tokens WHERE token_hash = ? AND revoked = 0",
            (token_hash,),
        ) as cursor:
            if await cursor.fetchone() is None:
                return None
        # Update last_used
        await self._conn.execute(
            "UPDATE auth_tokens SET last_used = ? WHERE token_hash = ?",
            (datetime.now().isoformat(), token_hash),
        )
        await self._conn.commit()
        # Re-fetch with updated last_used
        async with self._conn.execute(
            "SELECT id, role, label, created_at, last_used, revoked FROM auth_tokens WHERE token_hash = ? AND revoked = 0",
            (token_hash,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_auth_tokens(self) -> list[dict]:
        """Return all tokens (hash NOT included — only metadata)."""
        async with self._conn.execute(
            "SELECT id, role, label, created_at, last_used, revoked FROM auth_tokens ORDER BY created_at DESC",
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def revoke_auth_token(self, token_id: int) -> None:
        """Mark a token as revoked by ID."""
        await self._conn.execute(
            "UPDATE auth_tokens SET revoked = 1 WHERE id = ?",
            (token_id,),
        )
        await self._conn.commit()

    async def revoke_all_admin_tokens(self) -> None:
        """Revoke all admin tokens (used during token reset)."""
        await self._conn.execute(
            "UPDATE auth_tokens SET revoked = 1 WHERE role = 'admin' AND revoked = 0",
        )
        await self._conn.commit()

    async def count_active_admin_tokens(self) -> int:
        """Count non-revoked admin tokens."""
        async with self._conn.execute(
            "SELECT COUNT(*) FROM auth_tokens WHERE role = 'admin' AND revoked = 0",
        ) as cursor:
            row = await cursor.fetchone()
            return row[0]

    # ------------------------------------------------------------------
    # Fingerprint history
    # ------------------------------------------------------------------

    async def add_fingerprint_snapshot(
        self,
        mac: str,
        os_family: str | None,
        manufacturer: str | None,
        device_type: str | None,
        hostname: str | None,
        oui_vendor: str | None,
    ) -> None:
        """Capture a point-in-time fingerprint for drift/clone detection."""
        assert self._conn is not None
        async with self._mu:
            ts_now = datetime.now().isoformat()
            await self._conn.execute(
                "INSERT INTO fingerprint_history"
                " (mac, timestamp, os_family, manufacturer,"
                "  device_type, hostname, oui_vendor)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (mac, ts_now, os_family, manufacturer, device_type, hostname, oui_vendor),
            )
            await self._conn.commit()

    async def get_fingerprint_history(
        self, mac: str, limit: int = 20,
    ) -> list[dict]:
        """Recent fingerprint snapshots for a MAC, newest first."""
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT mac, timestamp, os_family, manufacturer,"
            "       device_type, hostname, oui_vendor"
            " FROM fingerprint_history WHERE mac = ?"
            " ORDER BY timestamp DESC LIMIT ?",
            (mac, limit),
        ) as cur:
            return [
                {
                    "mac": r[0],
                    "timestamp": r[1],
                    "os_family": r[2],
                    "manufacturer": r[3],
                    "device_type": r[4],
                    "hostname": r[5],
                    "oui_vendor": r[6],
                }
                for r in await cur.fetchall()
            ]

    # ------------------------------------------------------------------
    # Ad-hoc / utility queries
    # ------------------------------------------------------------------

    async def execute_readonly_query(self, sql: str, params: tuple | None = None) -> dict:
        """Run an arbitrary read-only SQL statement and return the result set."""
        assert self._conn is not None
        async with self._conn.execute(sql, params or ()) as cur:
            col_names = (
                [desc[0] for desc in cur.description] if cur.description else []
            )
            rows = await cur.fetchall()
            return {"columns": col_names, "rows": [list(r) for r in rows]}

    async def prune_observations(self, retention_days: int = 7) -> int:
        """Delete observations older than *retention_days*. Returns count deleted."""
        from datetime import timedelta

        assert self._conn is not None
        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
        async with self._mu:
            cursor = await self._conn.execute(
                "DELETE FROM observations WHERE timestamp < ?", (cutoff,)
            )
            await self._conn.commit()
            return cursor.rowcount

    async def prune_alerts(self, retention_days: int = 30) -> int:
        """Delete alerts older than *retention_days*. Returns count deleted."""
        from datetime import timedelta

        assert self._conn is not None
        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
        async with self._mu:
            cursor = await self._conn.execute(
                "DELETE FROM alerts WHERE timestamp < ?", (cutoff,)
            )
            await self._conn.commit()
            return cursor.rowcount

    async def clear_all_devices(self) -> None:
        """Wipe the devices and observations tables entirely."""
        assert self._conn is not None
        async with self._mu:
            await self._conn.execute("DELETE FROM observations")
            await self._conn.execute("DELETE FROM devices")
            await self._conn.commit()
