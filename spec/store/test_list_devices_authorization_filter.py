"""Regression — list_devices supports authorization + is_online filters.

Live probe caught that ``?authorization=approved`` was silently ignored:
the /api/devices endpoint did not declare the param, so FastAPI accepted it
as noise. Likewise for ``is_online``.
"""

import pytest
from datetime import datetime, timezone

from leetha.store.store import Store
from leetha.store.database import Database
from leetha.store.models import Device, Host


@pytest.fixture
async def env(tmp_path):
    db_path = tmp_path / "f.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


async def _seed(db, store, mac, **device_kw):
    ts = datetime.now(timezone.utc)
    await store.hosts.upsert(Host(hw_addr=mac, disposition="new",
                                  discovered_at=ts, last_active=ts))
    await db.upsert_device(Device(mac=mac, first_seen=ts, last_seen=ts, **device_kw))


@pytest.mark.asyncio
async def test_filter_by_authorization_approved(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01")
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="a")
    found, total = await store.verdicts.list_devices(authorization="approved")
    assert total == 1
    assert found[0]["mac"] == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_filter_by_authorization_rejected(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01")
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await db.reject_device("aa:bb:cc:dd:ee:02", actor="a")
    found, total = await store.verdicts.list_devices(authorization="rejected")
    assert total == 1
    assert found[0]["mac"] == "aa:bb:cc:dd:ee:02"


@pytest.mark.asyncio
async def test_filter_by_authorization_unapproved_includes_null(env):
    """A host without a devices row is effectively 'unapproved'."""
    db, store = env
    # Only a host, no devices row
    ts = datetime.now(timezone.utc)
    await store.hosts.upsert(Host(
        hw_addr="aa:bb:cc:dd:ee:03", disposition="new",
        discovered_at=ts, last_active=ts,
    ))
    # And one explicitly approved
    await _seed(db, store, "aa:bb:cc:dd:ee:04")
    await db.approve_device("aa:bb:cc:dd:ee:04", actor="a")

    found, total = await store.verdicts.list_devices(authorization="unapproved")
    macs = {d["mac"] for d in found}
    assert "aa:bb:cc:dd:ee:03" in macs  # host-only counts as unapproved
    assert "aa:bb:cc:dd:ee:04" not in macs
    assert total == 1


@pytest.mark.asyncio
async def test_filter_by_is_online_true(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01")
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await db.set_device_offline("aa:bb:cc:dd:ee:02")
    found, total = await store.verdicts.list_devices(is_online=True)
    assert total == 1
    assert found[0]["mac"] == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_filter_by_is_online_false(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01")
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await db.set_device_offline("aa:bb:cc:dd:ee:02")
    found, total = await store.verdicts.list_devices(is_online=False)
    assert total == 1
    assert found[0]["mac"] == "aa:bb:cc:dd:ee:02"


@pytest.mark.asyncio
async def test_combined_authorization_plus_criticality(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:10", criticality="high")
    await _seed(db, store, "aa:bb:cc:dd:ee:11", criticality="high")
    await _seed(db, store, "aa:bb:cc:dd:ee:12", criticality="low")
    await db.approve_device("aa:bb:cc:dd:ee:10", actor="a")
    await db.approve_device("aa:bb:cc:dd:ee:12", actor="a")
    found, total = await store.verdicts.list_devices(
        authorization="approved", criticality="high",
    )
    assert total == 1
    assert found[0]["mac"] == "aa:bb:cc:dd:ee:10"
