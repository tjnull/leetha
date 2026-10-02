"""Override repository -- CRUD operations for manual device overrides."""
from __future__ import annotations

import json
import asyncio
from datetime import datetime, timezone
from pathlib import Path


ALLOWED_FIELDS: frozenset[str] = frozenset({
    "hostname",
    "device_type",
    "manufacturer",
    "os_family",
    "os_version",
    "model",
    "connection_type",
    "disposition",
    "notes",
})


class OverrideRepository:
    def __init__(self, conn, write_lock=None):
        self._conn = conn
        self._mu = write_lock or asyncio.Lock()

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS device_overrides (
                hw_addr         TEXT PRIMARY KEY,
                hostname        TEXT,
                device_type     TEXT,
                manufacturer    TEXT,
                os_family       TEXT,
                os_version      TEXT,
                model           TEXT,
                connection_type TEXT,
                disposition     TEXT,
                notes           TEXT,
                updated_at      TEXT NOT NULL
            )
        """)
        await self._conn.commit()

    async def upsert(self, hw_addr: str, fields: dict) -> dict:
        """Insert or update an override. Merges new values into existing.

        Uses a single atomic INSERT ... ON CONFLICT DO UPDATE with COALESCE
        to preserve existing values for fields not provided in this call.
        """
        filtered = {k: v for k, v in fields.items() if k in ALLOWED_FIELDS}
        now = datetime.now(timezone.utc).isoformat()

        # Build values: use provided value or NULL for each allowed field
        vals = {k: filtered.get(k) for k in ALLOWED_FIELDS}

        async with self._mu:
            await self._upsert_locked(hw_addr, vals, now)
        return await self.find_by_addr(hw_addr)

    async def _upsert_locked(self, hw_addr, vals, now):
        await self._conn.execute("""
            INSERT INTO device_overrides
                (hw_addr, hostname, device_type, manufacturer, os_family,
                 os_version, model, connection_type, disposition, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hw_addr) DO UPDATE SET
                hostname        = COALESCE(excluded.hostname, device_overrides.hostname),
                device_type     = COALESCE(excluded.device_type, device_overrides.device_type),
                manufacturer    = COALESCE(excluded.manufacturer, device_overrides.manufacturer),
                os_family       = COALESCE(excluded.os_family, device_overrides.os_family),
                os_version      = COALESCE(excluded.os_version, device_overrides.os_version),
                model           = COALESCE(excluded.model, device_overrides.model),
                connection_type = COALESCE(excluded.connection_type, device_overrides.connection_type),
                disposition     = COALESCE(excluded.disposition, device_overrides.disposition),
                notes           = COALESCE(excluded.notes, device_overrides.notes),
                updated_at      = excluded.updated_at
        """, (hw_addr, vals["hostname"], vals["device_type"], vals["manufacturer"],
              vals["os_family"], vals["os_version"], vals["model"],
              vals["connection_type"], vals["disposition"], vals["notes"], now))
        await self._conn.commit()

    async def find_by_addr(self, hw_addr: str) -> dict | None:
        cursor = await self._conn.execute(
            "SELECT * FROM device_overrides WHERE hw_addr = ?", (hw_addr,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    async def delete(self, hw_addr: str) -> None:
        async with self._mu:
            await self._conn.execute(
                "DELETE FROM device_overrides WHERE hw_addr = ?", (hw_addr,)
            )
            await self._conn.commit()

    async def find_all(self) -> list[dict]:
        cursor = await self._conn.execute("SELECT * FROM device_overrides")
        rows = await cursor.fetchall()
        return [self._row_to_dict(r) for r in rows]

    async def migrate_from_json(self, json_path: str | Path) -> int:
        """Migrate file-based overrides into the DB. Returns count migrated."""
        json_path = Path(json_path)
        if not json_path.exists():
            return 0
        data = json.loads(json_path.read_text())
        count = 0
        for mac, fields in data.items():
            await self.upsert(mac, fields)
            count += 1
        json_path.rename(json_path.with_suffix(".json.bak"))
        return count

    def _row_to_dict(self, row) -> dict:
        return {
            "hw_addr": row["hw_addr"],
            "hostname": row["hostname"],
            "device_type": row["device_type"],
            "manufacturer": row["manufacturer"],
            "os_family": row["os_family"],
            "os_version": row["os_version"],
            "model": row["model"],
            "connection_type": row["connection_type"],
            "disposition": row["disposition"],
            "notes": row["notes"],
            "updated_at": row["updated_at"],
        }
