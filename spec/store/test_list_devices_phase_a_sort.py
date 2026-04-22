"""Regression — list_devices sorts by Phase A columns.

Live probe caught ``?sort=criticality`` silently falling back to
``discovered_at``. The verdicts.sort_col_map had no entry for criticality,
authorization, owner, etc. This test pins each supported sort key.
"""

import pytest
from datetime import datetime, timezone, timedelta

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Device, Host


@pytest.fixture
async def env(tmp_path):
    db_path = tmp_path / "sort.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


async def _seed(db, store, mac, **device_kw):
    ts = device_kw.pop("last_seen", None) or datetime.now(timezone.utc)
    await store.hosts.upsert(Host(
        hw_addr=mac, disposition="new",
        discovered_at=ts, last_active=ts,
    ))
    await db.upsert_device(Device(mac=mac, first_seen=ts, last_seen=ts, **device_kw))


@pytest.mark.asyncio
async def test_sort_by_criticality_respects_level_order(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01", criticality="low")
    await _seed(db, store, "aa:bb:cc:dd:ee:02", criticality="critical")
    await _seed(db, store, "aa:bb:cc:dd:ee:03", criticality="medium")
    await _seed(db, store, "aa:bb:cc:dd:ee:04", criticality="high")

    found, _ = await store.verdicts.list_devices(sort="criticality", order="desc")
    order = [d["criticality"] for d in found]
    # critical > high > medium > low (NOT alphabetic which would put critical
    # first coincidentally but low before medium)
    assert order == ["critical", "high", "medium", "low"], order


@pytest.mark.asyncio
async def test_sort_by_owner_ascending(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01", owner="charlie")
    await _seed(db, store, "aa:bb:cc:dd:ee:02", owner="alice")
    await _seed(db, store, "aa:bb:cc:dd:ee:03", owner="bob")
    found, _ = await store.verdicts.list_devices(sort="owner", order="asc")
    owners = [d["owner"] for d in found]
    assert owners == ["alice", "bob", "charlie"], owners


@pytest.mark.asyncio
async def test_sort_by_authorization(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01")  # unapproved
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await _seed(db, store, "aa:bb:cc:dd:ee:03")
    await db.approve_device("aa:bb:cc:dd:ee:02", actor="x")
    await db.reject_device("aa:bb:cc:dd:ee:03", actor="x")
    found, _ = await store.verdicts.list_devices(sort="authorization", order="asc")
    auths = [d["authorization"] for d in found]
    # alphabetic: approved < rejected < unapproved
    assert auths == ["approved", "rejected", "unapproved"]


@pytest.mark.asyncio
async def test_sort_by_presence_threshold(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01", presence_threshold_seconds=900)
    await _seed(db, store, "aa:bb:cc:dd:ee:02", presence_threshold_seconds=60)
    await _seed(db, store, "aa:bb:cc:dd:ee:03", presence_threshold_seconds=300)
    found, _ = await store.verdicts.list_devices(
        sort="presence_threshold_seconds", order="asc",
    )
    thresholds = [d["presence_threshold_seconds"] for d in found]
    assert thresholds == [60, 300, 900]


@pytest.mark.asyncio
async def test_sort_by_is_online(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01")  # online
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await db.set_device_offline("aa:bb:cc:dd:ee:02")
    found, _ = await store.verdicts.list_devices(sort="is_online", order="desc")
    online = [d["is_online"] for d in found]
    assert online == [True, False]
