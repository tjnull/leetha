"""Phase A.4 Task 28-29 — presence schema + Device model + helpers."""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    yield d
    await d.close()


@pytest.mark.asyncio
async def test_presence_columns_exist(db):
    async with db._conn.execute("PRAGMA table_info(devices)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for c in ("is_online", "offline_since", "presence_threshold_seconds"):
        assert c in cols


@pytest.mark.asyncio
async def test_presence_defaults(db):
    await db._conn.execute("INSERT INTO devices (mac) VALUES ('aa:bb:cc:dd:ee:ff')")
    async with db._conn.execute(
        "SELECT is_online, offline_since, presence_threshold_seconds "
        "FROM devices WHERE mac='aa:bb:cc:dd:ee:ff'"
    ) as cur:
        row = await cur.fetchone()
    assert row[0] == 1
    assert row[1] is None
    assert row[2] == 300


def test_device_model_presence_defaults():
    d = Device(mac="aa:bb:cc:dd:ee:ff")
    assert d.is_online is True
    assert d.offline_since is None
    assert d.presence_threshold_seconds == 300


@pytest.mark.asyncio
async def test_set_online_offline_helpers(db):
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await db.set_device_offline("aa:bb:cc:dd:ee:01")
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.is_online is False
    assert dev.offline_since is not None

    await db.set_device_online("aa:bb:cc:dd:ee:01")
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.is_online is True
    assert dev.offline_since is None


@pytest.mark.asyncio
async def test_set_offline_preserves_existing_timestamp(db):
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:02", first_seen=ts, last_seen=ts,
    ))
    await db.set_device_offline("aa:bb:cc:dd:ee:02")
    dev1 = await db.get_device("aa:bb:cc:dd:ee:02")
    # Second call must not clobber offline_since
    await db.set_device_offline("aa:bb:cc:dd:ee:02")
    dev2 = await db.get_device("aa:bb:cc:dd:ee:02")
    assert dev1.offline_since == dev2.offline_since


@pytest.mark.asyncio
async def test_get_presence_threshold(db):
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:03", first_seen=ts, last_seen=ts,
    ))
    thresh = await db.get_presence_threshold("aa:bb:cc:dd:ee:03")
    assert thresh == 300
    await db._conn.execute(
        "UPDATE devices SET presence_threshold_seconds = 900 WHERE mac = ?",
        ("aa:bb:cc:dd:ee:03",),
    )
    await db._conn.commit()
    assert await db.get_presence_threshold("aa:bb:cc:dd:ee:03") == 900
