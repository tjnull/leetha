"""Phase A.1 — schema additions for custom device properties."""

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
async def test_devices_table_has_custom_props_columns(db):
    async with db._conn.execute("PRAGMA table_info(devices)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for expected in ("owner", "location", "criticality", "tags", "notes"):
        assert expected in cols, f"missing column: {expected}"


@pytest.mark.asyncio
async def test_criticality_check_constraint_rejects_invalid(db):
    # Valid values pass
    await db._conn.execute(
        "INSERT INTO devices (mac, criticality) VALUES (?, ?)",
        ("aa:bb:cc:dd:ee:01", "high"),
    )
    # NULL passes
    await db._conn.execute(
        "INSERT INTO devices (mac, criticality) VALUES (?, ?)",
        ("aa:bb:cc:dd:ee:02", None),
    )
    # Invalid values raise
    with pytest.raises(Exception):
        await db._conn.execute(
            "INSERT INTO devices (mac, criticality) VALUES (?, ?)",
            ("aa:bb:cc:dd:ee:03", "bogus"),
        )


@pytest.mark.asyncio
async def test_criticality_accepts_all_four_levels(db):
    for i, level in enumerate(("low", "medium", "high", "critical")):
        await db._conn.execute(
            "INSERT INTO devices (mac, criticality) VALUES (?, ?)",
            (f"aa:bb:cc:dd:ee:{i:02x}", level),
        )
    await db._conn.commit()


@pytest.mark.asyncio
async def test_criticality_and_location_indexes_exist(db):
    async with db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='devices'"
    ) as cur:
        idx_names = {row[0] for row in await cur.fetchall()}
    assert "idx_devices_criticality" in idx_names
    assert "idx_devices_location" in idx_names
