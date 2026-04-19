"""Phase A.2 — tri-state authorization schema (devices + history table)."""

import pytest
from pathlib import Path

from leetha.store.database import Database


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    yield d
    await d.close()


@pytest.mark.asyncio
async def test_devices_has_authorization_columns(db):
    async with db._conn.execute("PRAGMA table_info(devices)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for c in ("authorization", "authorized_at", "authorized_by"):
        assert c in cols, f"missing column: {c}"


@pytest.mark.asyncio
async def test_authorization_default_is_unapproved(db):
    await db._conn.execute(
        "INSERT INTO devices (mac) VALUES ('aa:bb:cc:dd:ee:ff')"
    )
    async with db._conn.execute(
        "SELECT authorization FROM devices WHERE mac = 'aa:bb:cc:dd:ee:ff'"
    ) as cur:
        row = await cur.fetchone()
    assert row[0] == "unapproved"


@pytest.mark.asyncio
async def test_authorization_history_table_exists(db):
    async with db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='authorization_history'"
    ) as cur:
        row = await cur.fetchone()
    assert row is not None


@pytest.mark.asyncio
async def test_authorization_history_columns(db):
    async with db._conn.execute("PRAGMA table_info(authorization_history)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for c in ("id", "mac", "previous_state", "new_state", "actor", "reason", "timestamp"):
        assert c in cols, f"missing column: {c}"


@pytest.mark.asyncio
async def test_authorization_index_exists(db):
    async with db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='devices'"
    ) as cur:
        idx = {r[0] for r in await cur.fetchall()}
    assert "idx_devices_authorization" in idx
