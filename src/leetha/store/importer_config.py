"""Phase A.3 — importer_config table + repository."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


_TABLE_IMPORTER_CONFIG = """\
CREATE TABLE IF NOT EXISTS importer_config (
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
"""


@dataclass
class ImporterConfig:
    name: str
    enabled: bool = False
    config: dict = field(default_factory=dict)
    interval_seconds: int = 3600
    last_sync_at: datetime | None = None
    last_sync_devices: int | None = None
    last_sync_status: str | None = None
    last_sync_error: str | None = None
    next_sync_at: datetime | None = None
    backoff_level: int = 0


class ImporterConfigRepository:
    """CRUD for importer_config rows. Uses the shared aiosqlite connection."""

    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute(_TABLE_IMPORTER_CONFIG)
        await self._conn.commit()

    async def upsert(self, cfg: ImporterConfig) -> None:
        await self._conn.execute(
            """
            INSERT INTO importer_config
                (name, enabled, config_json, interval_seconds,
                 last_sync_at, last_sync_devices, last_sync_status,
                 last_sync_error, next_sync_at, backoff_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                enabled          = excluded.enabled,
                config_json      = excluded.config_json,
                interval_seconds = excluded.interval_seconds,
                last_sync_at     = COALESCE(excluded.last_sync_at, importer_config.last_sync_at),
                last_sync_devices= COALESCE(excluded.last_sync_devices, importer_config.last_sync_devices),
                last_sync_status = COALESCE(excluded.last_sync_status, importer_config.last_sync_status),
                last_sync_error  = excluded.last_sync_error,
                next_sync_at     = COALESCE(excluded.next_sync_at, importer_config.next_sync_at),
                backoff_level    = excluded.backoff_level
            """,
            (
                cfg.name,
                int(cfg.enabled),
                json.dumps(cfg.config),
                cfg.interval_seconds,
                cfg.last_sync_at.isoformat() if cfg.last_sync_at else None,
                cfg.last_sync_devices,
                cfg.last_sync_status,
                cfg.last_sync_error,
                cfg.next_sync_at.isoformat() if cfg.next_sync_at else None,
                cfg.backoff_level,
            ),
        )
        await self._conn.commit()

    async def get(self, name: str) -> ImporterConfig | None:
        async with self._conn.execute(
            "SELECT * FROM importer_config WHERE name = ?", (name,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return self._row_to_cfg(row)

    async def list_all(self) -> list[ImporterConfig]:
        async with self._conn.execute("SELECT * FROM importer_config") as cur:
            rows = await cur.fetchall()
        return [self._row_to_cfg(r) for r in rows]

    async def set_status(self, name: str, status: str, error: str | None = None) -> None:
        await self._conn.execute(
            "UPDATE importer_config SET last_sync_status = ?, last_sync_error = ? "
            "WHERE name = ?",
            (status, error, name),
        )
        await self._conn.commit()

    async def mark_synced(self, name: str, devices_count: int) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        await self._conn.execute(
            "UPDATE importer_config SET last_sync_at = ?, last_sync_devices = ?, "
            "last_sync_status = 'ok', last_sync_error = NULL, backoff_level = 0 "
            "WHERE name = ?",
            (now_iso, devices_count, name),
        )
        await self._conn.commit()

    async def set_secret(self, name: str, plaintext: str, *, data_dir=None) -> None:
        """Persist a secret for this importer via the AES-GCM credential store."""
        from leetha.inventory.credentials import store_secret
        store_secret(name, plaintext, data_dir=data_dir)

    async def get_secret(self, name: str, *, data_dir=None) -> str | None:
        """Return the plaintext secret (env-var override wins)."""
        from leetha.inventory.credentials import get_secret as _g
        return _g(name, data_dir=data_dir)

    async def schedule_next_sync(self, name: str, delay_seconds: int | None = None) -> None:
        cfg = await self.get(name)
        if cfg is None:
            return
        d = delay_seconds if delay_seconds is not None else cfg.interval_seconds
        next_at = datetime.now(timezone.utc) + timedelta(seconds=d)
        await self._conn.execute(
            "UPDATE importer_config SET next_sync_at = ? WHERE name = ?",
            (next_at.isoformat(), name),
        )
        await self._conn.commit()

    @staticmethod
    def _row_to_cfg(row) -> ImporterConfig:
        def _dt(val):
            if not val:
                return None
            try:
                return datetime.fromisoformat(val)
            except (ValueError, TypeError):
                return None

        cfg_raw = row["config_json"]
        try:
            config = json.loads(cfg_raw) if cfg_raw else {}
        except (ValueError, TypeError):
            config = {}

        return ImporterConfig(
            name=row["name"],
            enabled=bool(row["enabled"]),
            config=config,
            interval_seconds=row["interval_seconds"] or 3600,
            last_sync_at=_dt(row["last_sync_at"]),
            last_sync_devices=row["last_sync_devices"],
            last_sync_status=row["last_sync_status"],
            last_sync_error=row["last_sync_error"],
            next_sync_at=_dt(row["next_sync_at"]),
            backoff_level=row["backoff_level"] or 0,
        )
