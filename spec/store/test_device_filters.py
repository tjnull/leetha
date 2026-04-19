"""Phase A.1 — Database.list_devices() filter helpers."""

import json
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


def _make(mac: str, **kw) -> Device:
    ts = datetime.now(timezone.utc)
    return Device(mac=mac, first_seen=ts, last_seen=ts, **kw)


@pytest.mark.asyncio
async def test_upsert_persists_custom_props(db):
    await db.upsert_device(_make(
        "aa:bb:cc:dd:ee:01",
        owner="alice",
        location="room-101",
        criticality="high",
        tags=["prod", "core"],
        notes="edge router",
    ))
    row = await db.get_device("aa:bb:cc:dd:ee:01")
    assert row.owner == "alice"
    assert row.location == "room-101"
    assert row.criticality == "high"
    assert row.tags == ["prod", "core"]
    assert row.notes == "edge router"


@pytest.mark.asyncio
async def test_list_devices_filter_by_criticality(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:01", criticality="high"))
    await db.upsert_device(_make("aa:bb:cc:dd:ee:02", criticality="low"))
    results = await db.list_devices(criticality="high")
    assert len(results) == 1
    assert results[0].mac == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_list_devices_filter_by_owner(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:01", owner="alice"))
    await db.upsert_device(_make("aa:bb:cc:dd:ee:02", owner="bob"))
    results = await db.list_devices(owner="alice")
    assert len(results) == 1
    assert results[0].mac == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_list_devices_filter_by_location(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:01", location="room-101"))
    await db.upsert_device(_make("aa:bb:cc:dd:ee:02", location="room-202"))
    results = await db.list_devices(location="room-101")
    assert len(results) == 1
    assert results[0].mac == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_list_devices_filter_by_tag(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:01", tags=["prod", "core"]))
    await db.upsert_device(_make("aa:bb:cc:dd:ee:02", tags=["dev"]))
    results = await db.list_devices(tag="prod")
    assert len(results) == 1
    assert results[0].mac == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_list_devices_combined_filters(db):
    await db.upsert_device(_make(
        "aa:bb:cc:dd:ee:01", criticality="high", owner="alice", tags=["prod"]
    ))
    await db.upsert_device(_make(
        "aa:bb:cc:dd:ee:02", criticality="high", owner="bob", tags=["prod"]
    ))
    await db.upsert_device(_make(
        "aa:bb:cc:dd:ee:03", criticality="low", owner="alice", tags=["prod"]
    ))
    results = await db.list_devices(criticality="high", owner="alice")
    assert len(results) == 1
    assert results[0].mac == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_list_devices_no_filters_returns_all(db):
    for i in range(3):
        await db.upsert_device(_make(f"aa:bb:cc:dd:ee:{i:02x}", criticality="low"))
    results = await db.list_devices()
    assert len(results) == 3


@pytest.mark.asyncio
async def test_list_devices_interface_filter_still_works(db):
    """Regression: existing interface filter must not break."""
    await db.upsert_device(_make("aa:bb:cc:dd:ee:01"))
    # interface filter requires observation records; with none, result is empty
    results = await db.list_devices(interface="eth0")
    assert results == []
