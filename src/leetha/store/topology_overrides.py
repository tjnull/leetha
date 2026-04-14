"""Topology override repository -- manual parent connection overrides."""
from __future__ import annotations

from datetime import datetime, timezone


class TopologyOverrideRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS topology_overrides (
                child_mac TEXT PRIMARY KEY,
                parent_mac TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        await self._conn.commit()

    async def upsert(self, child_mac: str, parent_mac: str) -> None:
        await self._conn.execute("""
            INSERT INTO topology_overrides (child_mac, parent_mac, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(child_mac) DO UPDATE SET
                parent_mac = excluded.parent_mac,
                created_at = excluded.created_at
        """, (child_mac, parent_mac, datetime.now(timezone.utc).isoformat()))
        await self._conn.commit()

    async def delete(self, child_mac: str) -> bool:
        cursor = await self._conn.execute(
            "DELETE FROM topology_overrides WHERE child_mac = ?", (child_mac,))
        await self._conn.commit()
        return cursor.rowcount > 0

    async def find_all(self) -> dict[str, str]:
        """Return {child_mac: parent_mac} for all overrides."""
        cursor = await self._conn.execute(
            "SELECT child_mac, parent_mac FROM topology_overrides")
        rows = await cursor.fetchall()
        return {r["child_mac"]: r["parent_mac"] for r in rows}
