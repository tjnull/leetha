"""Host repository -- CRUD operations for network hosts."""
from __future__ import annotations

import json
from datetime import datetime
from leetha.store.models import Host


class HostRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                hw_addr TEXT PRIMARY KEY,
                ip_addr TEXT,
                ip_v6 TEXT,
                discovered_at TEXT NOT NULL,
                last_active TEXT NOT NULL,
                mac_randomized INTEGER DEFAULT 0,
                real_hw_addr TEXT,
                disposition TEXT DEFAULT 'new'
            )
        """)
        # Migration: add identity_id column for existing databases
        try:
            await self._conn.execute(
                "ALTER TABLE hosts ADD COLUMN identity_id INTEGER")
            await self._conn.commit()
        except Exception:
            pass  # column already exists
        await self._conn.commit()

    async def upsert(self, host: Host) -> None:
        await self._conn.execute("""
            INSERT INTO hosts (hw_addr, ip_addr, ip_v6, discovered_at, last_active,
                               mac_randomized, real_hw_addr, disposition)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hw_addr) DO UPDATE SET
                ip_addr = COALESCE(excluded.ip_addr, hosts.ip_addr),
                ip_v6 = COALESCE(excluded.ip_v6, hosts.ip_v6),
                last_active = excluded.last_active,
                mac_randomized = MAX(hosts.mac_randomized, excluded.mac_randomized),
                real_hw_addr = COALESCE(excluded.real_hw_addr, hosts.real_hw_addr),
                disposition = CASE WHEN hosts.disposition = 'self' THEN 'self'
                              ELSE excluded.disposition END
        """, (host.hw_addr, host.ip_addr, host.ip_v6,
              host.discovered_at.isoformat(), host.last_active.isoformat(),
              int(host.mac_randomized), host.real_hw_addr, host.disposition))
        await self._conn.commit()

    async def find_by_addr(self, hw_addr: str) -> Host | None:
        cursor = await self._conn.execute(
            "SELECT * FROM hosts WHERE hw_addr = ?", (hw_addr,))
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_host(row)

    async def find_all(self, limit: int = 500, offset: int = 0) -> list[Host]:
        cursor = await self._conn.execute(
            "SELECT * FROM hosts ORDER BY last_active DESC LIMIT ? OFFSET ?",
            (limit, offset))
        rows = await cursor.fetchall()
        return [self._row_to_host(r) for r in rows]

    async def count(self) -> int:
        cursor = await self._conn.execute("SELECT COUNT(*) FROM hosts")
        row = await cursor.fetchone()
        return row[0]

    def _row_to_host(self, row) -> Host:
        # identity_id may be missing on old databases before migration
        try:
            identity_id = row["identity_id"]
        except (KeyError, IndexError):
            identity_id = None
        return Host(
            hw_addr=row["hw_addr"],
            ip_addr=row["ip_addr"],
            ip_v6=row["ip_v6"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            last_active=datetime.fromisoformat(row["last_active"]),
            mac_randomized=bool(row["mac_randomized"]),
            real_hw_addr=row["real_hw_addr"],
            disposition=row["disposition"],
            identity_id=identity_id,
        )
