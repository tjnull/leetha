"""Unified store wrapping per-entity repositories.

Replaces the monolithic Database class with focused repositories,
each managing its own SQL operations.
"""
from __future__ import annotations

import asyncio

import aiosqlite
from pathlib import Path

from leetha.store.hosts import HostRepository
from leetha.store.findings import FindingRepository
from leetha.store.sightings import SightingRepository
from leetha.store.verdicts import VerdictRepository
from leetha.store.identities import IdentityRepository
from leetha.store.snapshots import SnapshotRepository
from leetha.store.overrides import OverrideRepository
from leetha.store.topology_overrides import TopologyOverrideRepository
from leetha.store.write_lock import write_lock_for


class Store:
    """Central data store with repository-per-entity pattern."""

    def __init__(self, db_path: str | Path, *, batch_sightings: bool = False):
        self.db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._write_lock = write_lock_for(db_path)
        self._batch_sightings = batch_sightings
        self.hosts: HostRepository | None = None
        self.findings: FindingRepository | None = None
        self.sightings: SightingRepository | None = None
        self.verdicts: VerdictRepository | None = None
        self.identities: IdentityRepository | None = None
        self.snapshots: SnapshotRepository | None = None
        self.overrides: OverrideRepository | None = None
        self.topology_overrides: TopologyOverrideRepository | None = None

    async def initialize(self):
        """Open connection and create all tables."""
        self._conn = await aiosqlite.connect(self.db_path, isolation_level=None)
        self._conn.row_factory = aiosqlite.Row
        # Match the legacy Database's performance pragmas
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA busy_timeout=30000")
        self.hosts = HostRepository(self._conn, self._write_lock)
        self.findings = FindingRepository(self._conn, self._write_lock)
        self.sightings = SightingRepository(
            self._conn, self._write_lock,
            batch_size=64 if self._batch_sightings else 1,
        )
        self.verdicts = VerdictRepository(self._conn, self._write_lock)
        self.identities = IdentityRepository(self._conn, self._write_lock)
        self.snapshots = SnapshotRepository(self._conn, self._write_lock)
        await self.hosts.create_tables()
        await self._conn.execute(
            "CREATE TABLE IF NOT EXISTS leetha_migrations (name TEXT PRIMARY KEY)"
        )
        async with self._conn.execute(
            "SELECT 1 FROM leetha_migrations WHERE name = 'randomized_hosts_v1'"
        ) as cur:
            done = await cur.fetchone()
        if not done:
            from leetha.fingerprint.mac_intel import is_randomized_mac
            async with self._conn.execute(
                "SELECT hw_addr FROM hosts WHERE mac_randomized = 0"
            ) as cur:
                old_macs = await cur.fetchall()
            randomized = [(row[0],) for row in old_macs if is_randomized_mac(row[0])]
            if randomized:
                await self._conn.executemany(
                    "UPDATE hosts SET mac_randomized = 1 WHERE hw_addr = ?",
                    randomized,
                )
            await self._conn.execute(
                "INSERT INTO leetha_migrations(name) VALUES ('randomized_hosts_v1')"
            )
        await self.findings.create_tables()
        await self.sightings.create_tables()
        await self.verdicts.create_tables()
        await self.identities.create_tables()
        await self.snapshots.create_tables()
        # Phase A.1: ensure devices table exists so verdicts.list_devices's
        # LEFT JOIN to custom-property columns works even when Store is used
        # without a parallel Database().initialize().
        from leetha.store.database import _TABLE_DEVICES
        await self._conn.executescript(_TABLE_DEVICES)
        self.overrides = OverrideRepository(self._conn, self._write_lock)
        await self.overrides.create_tables()
        self.topology_overrides = TopologyOverrideRepository(self._conn, self._write_lock)
        await self.topology_overrides.create_tables()

        # One-time migration from file-based overrides
        data_dir = Path(self.db_path).parent
        json_overrides = data_dir / "device_overrides.json"
        await self.overrides.migrate_from_json(json_overrides)

        # Fix DB file ownership when running under sudo
        from leetha.platform import fix_ownership
        db_file = Path(self.db_path)
        fix_ownership(db_file)
        for suffix in ("-wal", "-shm"):
            journal = db_file.parent / (db_file.name + suffix)
            if journal.exists():
                fix_ownership(journal)

    async def close(self):
        if self._conn:
            try:
                if self.sightings:
                    await self.sightings.flush()
            finally:
                await self._conn.close()
                self._conn = None

    @property
    def connection(self) -> aiosqlite.Connection:
        assert self._conn is not None, "Store not initialized"
        return self._conn
