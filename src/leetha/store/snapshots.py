"""Fingerprint snapshot repository -- point-in-time device fingerprints."""
from __future__ import annotations

from datetime import datetime


class SnapshotRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hw_addr TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                os_family TEXT,
                manufacturer TEXT,
                device_type TEXT,
                hostname TEXT,
                oui_vendor TEXT
            )
        """)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_snapshots_hw ON fingerprint_snapshots(hw_addr)")
        await self._conn.commit()

    async def add(self, hw_addr: str, *, os_family: str | None = None,
                  manufacturer: str | None = None, device_type: str | None = None,
                  hostname: str | None = None, oui_vendor: str | None = None) -> None:
        now = datetime.now()
        await self._conn.execute("""
            INSERT INTO fingerprint_snapshots
                (hw_addr, timestamp, os_family, manufacturer, device_type, hostname, oui_vendor)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (hw_addr, now.isoformat(), os_family, manufacturer,
              device_type, hostname, oui_vendor))
        await self._conn.commit()

    async def get_latest(self, hw_addr: str, limit: int = 1) -> list[dict]:
        cursor = await self._conn.execute("""
            SELECT * FROM fingerprint_snapshots
            WHERE hw_addr = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (hw_addr, limit))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def prune(self, max_per_mac: int = 50) -> int:
        cursor = await self._conn.execute("""
            DELETE FROM fingerprint_snapshots
            WHERE id IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY hw_addr ORDER BY timestamp DESC
                    ) AS rn
                    FROM fingerprint_snapshots
                ) ranked
                WHERE rn > ?
            )
        """, (max_per_mac,))
        await self._conn.commit()
        return cursor.rowcount
