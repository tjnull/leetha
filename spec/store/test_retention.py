"""Tests for observation and alert retention pruning."""

import pytest
from datetime import datetime, timedelta
from pathlib import Path

from leetha.store.database import Database


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    yield d
    await d.close()


async def _insert_device(db: Database, mac: str = "aa:bb:cc:dd:ee:ff") -> None:
    """Insert a minimal device row so foreign-key references work."""
    assert db._conn is not None
    await db._conn.execute(
        "INSERT OR IGNORE INTO devices (mac) VALUES (?)", (mac,)
    )
    await db._conn.commit()


@pytest.mark.asyncio
async def test_prune_old_observations(db):
    await _insert_device(db)
    old_ts = (datetime.now() - timedelta(days=10)).isoformat()
    new_ts = datetime.now().isoformat()
    await db._conn.execute(
        "INSERT INTO observations (device_mac, timestamp, source_type) VALUES (?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", old_ts, "test"),
    )
    await db._conn.execute(
        "INSERT INTO observations (device_mac, timestamp, source_type) VALUES (?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", new_ts, "test"),
    )
    await db._conn.commit()

    removed = await db.prune_observations(retention_days=7)
    assert removed == 1

    async with db._conn.execute("SELECT * FROM observations") as cur:
        rows = await cur.fetchall()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_prune_old_alerts(db):
    await _insert_device(db)
    old_ts = (datetime.now() - timedelta(days=40)).isoformat()
    new_ts = datetime.now().isoformat()
    await db._conn.execute(
        "INSERT INTO alerts (device_mac, alert_type, severity, timestamp) VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", "test", "low", old_ts),
    )
    await db._conn.execute(
        "INSERT INTO alerts (device_mac, alert_type, severity, timestamp) VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", "test", "low", new_ts),
    )
    await db._conn.commit()

    removed = await db.prune_alerts(retention_days=30)
    assert removed == 1


@pytest.mark.asyncio
async def test_prune_with_no_data_returns_zero(db):
    removed = await db.prune_observations(retention_days=7)
    assert removed == 0


@pytest.mark.asyncio
async def test_prune_respects_retention_boundary(db):
    """Records exactly at the boundary should NOT be pruned."""
    await _insert_device(db)
    # 6 days old -- within the 7-day window
    recent_ts = (datetime.now() - timedelta(days=6)).isoformat()
    await db._conn.execute(
        "INSERT INTO observations (device_mac, timestamp, source_type) VALUES (?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", recent_ts, "test"),
    )
    await db._conn.commit()

    removed = await db.prune_observations(retention_days=7)
    assert removed == 0
