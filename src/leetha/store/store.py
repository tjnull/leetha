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


class Store:
    """Central data store with repository-per-entity pattern."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()
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
        self.sightings = SightingRepository(self._conn, self._write_lock)
        self.verdicts = VerdictRepository(self._conn, self._write_lock)
        self.identities = IdentityRepository(self._conn)
        self.snapshots = SnapshotRepository(self._conn)
        await self.hosts.create_tables()
        await self.findings.create_tables()
        await self.sightings.create_tables()
        await self.verdicts.create_tables()
        await self.identities.create_tables()
        await self.snapshots.create_tables()
        self.overrides = OverrideRepository(self._conn)
        await self.overrides.create_tables()
        self.topology_overrides = TopologyOverrideRepository(self._conn)
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
            await self._conn.close()
            self._conn = None

    @property
    def connection(self) -> aiosqlite.Connection:
        assert self._conn is not None, "Store not initialized"
        return self._conn
