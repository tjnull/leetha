"""Sighting repository -- protocol observation storage."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from leetha.store.models import Sighting

log = logging.getLogger(__name__)


class SightingRepository:
    def __init__(self, conn, write_lock=None, *, batch_size=1):
        self._conn = conn
        self._mu = write_lock or asyncio.Lock()
        self._batch_size = batch_size
        self._pending: list[tuple] = []
        self._last_flush = time.monotonic()

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sightings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hw_addr TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT DEFAULT '{}',
                analysis TEXT DEFAULT '{}',
                certainty REAL DEFAULT 0.0,
                interface TEXT,
                network TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sightings_hw ON sightings(hw_addr)")
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sightings_ts ON sightings(timestamp)")
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sightings_source ON sightings(source)")
        await self._conn.commit()

    async def record(self, sighting: Sighting) -> None:
        if len(self._pending) >= 256:
            self._pending.pop(0)
            log.warning("sighting batch full after database write failure; discarding oldest sighting")
        self._pending.append((sighting.hw_addr, sighting.source,
                              json.dumps(sighting.payload), json.dumps(sighting.analysis),
                              sighting.certainty, sighting.interface, sighting.network,
                              sighting.timestamp.isoformat()))
        if len(self._pending) >= self._batch_size or time.monotonic() - self._last_flush >= 1:
            await self.flush()

    async def flush(self) -> None:
        if not self._pending:
            return
        async with self._mu:
            if not self._pending:
                return
            batch = self._pending[:]
            try:
                await self._conn.execute("BEGIN IMMEDIATE")
                await self._conn.executemany("""
                    INSERT INTO sightings (hw_addr, source, payload, analysis,
                                           certainty, interface, network, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, batch)
                await self._conn.commit()
            except Exception:
                await self._conn.rollback()
                raise
            del self._pending[:len(batch)]
            self._last_flush = time.monotonic()

    async def for_host(self, hw_addr: str, limit: int = 50) -> list[Sighting]:
        cursor = await self._conn.execute(
            "SELECT * FROM sightings WHERE hw_addr = ? ORDER BY timestamp DESC LIMIT ?",
            (hw_addr, limit))
        rows = await cursor.fetchall()
        return [self._row_to_sighting(r) for r in rows]

    async def prune(self, max_per_mac: int = 100) -> int:
        """Delete old sightings per host, keeping the most recent *max_per_mac*."""
        sql = """
        DELETE FROM sightings WHERE rowid IN (
            SELECT rowid FROM (
                SELECT rowid, ROW_NUMBER() OVER (
                    PARTITION BY hw_addr ORDER BY timestamp DESC
                ) AS rn FROM sightings
            ) WHERE rn > ?
        )
        """
        async with self._mu:
            cursor = await self._conn.execute(sql, (max_per_mac,))
            await self._conn.commit()
            return cursor.rowcount

    def _row_to_sighting(self, row) -> Sighting:
        return Sighting(
            hw_addr=row["hw_addr"],
            source=row["source"],
            payload=json.loads(row["payload"]) if row["payload"] else {},
            analysis=json.loads(row["analysis"]) if row["analysis"] else {},
            certainty=row["certainty"],
            interface=row["interface"],
            network=row["network"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
        )
