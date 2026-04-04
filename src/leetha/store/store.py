"""Unified store wrapping per-entity repositories.

Replaces the monolithic Database class with focused repositories,
each managing its own SQL operations.
"""
from __future__ import annotations

import aiosqlite
from pathlib import Path

from leetha.store.hosts import HostRepository
from leetha.store.findings import FindingRepository
from leetha.store.sightings import SightingRepository
from leetha.store.verdicts import VerdictRepository


class Store:
    """Central data store with repository-per-entity pattern."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None
        self.hosts: HostRepository | None = None
        self.findings: FindingRepository | None = None
        self.sightings: SightingRepository | None = None
        self.verdicts: VerdictRepository | None = None

    async def initialize(self):
        """Open connection and create all tables."""
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        self.hosts = HostRepository(self._conn)
        self.findings = FindingRepository(self._conn)
        self.sightings = SightingRepository(self._conn)
        self.verdicts = VerdictRepository(self._conn)
        await self.hosts.create_tables()
        await self.findings.create_tables()
        await self.sightings.create_tables()
        await self.verdicts.create_tables()

        # Fix DB file ownership when running under sudo
        from leetha.platform import fix_ownership
        from pathlib import Path
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
