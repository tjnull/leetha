"""Override repository -- CRUD operations for manual device overrides."""
from __future__ import annotations

import json
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
    def __init__(self, conn):
        self._conn = conn

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
        """Insert or update an override. Merges new values into existing."""
        filtered = {k: v for k, v in fields.items() if k in ALLOWED_FIELDS}
        now = datetime.now(timezone.utc).isoformat()

        existing = await self.find_by_addr(hw_addr)
        if existing is None:
            # Insert new row
            cols = ["hw_addr", "updated_at"] + list(filtered.keys())
            vals = [hw_addr, now] + list(filtered.values())
            placeholders = ", ".join("?" for _ in cols)
            col_str = ", ".join(cols)
            await self._conn.execute(
                f"INSERT INTO device_overrides ({col_str}) VALUES ({placeholders})",
                vals,
            )
        else:
            # Merge: only overwrite fields that are provided
            if filtered:
                set_clause = ", ".join(f"{k} = ?" for k in filtered)
                vals = list(filtered.values()) + [now, hw_addr]
                await self._conn.execute(
                    f"UPDATE device_overrides SET {set_clause}, updated_at = ? "
                    f"WHERE hw_addr = ?",
                    vals,
                )
            else:
                # No valid fields, just touch updated_at
                await self._conn.execute(
                    "UPDATE device_overrides SET updated_at = ? WHERE hw_addr = ?",
                    (now, hw_addr),
                )
        await self._conn.commit()
        return await self.find_by_addr(hw_addr)

    async def find_by_addr(self, hw_addr: str) -> dict | None:
        cursor = await self._conn.execute(
            "SELECT * FROM device_overrides WHERE hw_addr = ?", (hw_addr,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    async def delete(self, hw_addr: str) -> None:
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
