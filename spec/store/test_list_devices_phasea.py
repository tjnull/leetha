"""Phase A follow-up — VerdictRepository.list_devices returns auth + presence fields."""

import pytest
from datetime import datetime, timezone

from leetha.store.store import Store
from leetha.store.database import Database
from leetha.store.models import Device, Host
from leetha.evidence.models import Verdict


@pytest.fixture
async def env(tmp_path):
    db_path = tmp_path / "x.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


async def _seed(db, store, mac, **device_kw):
    ts = datetime.now(timezone.utc)
    await store.hosts.upsert(Host(hw_addr=mac, ip_addr="10.0.0.1", disposition="new"))
    await store.verdicts.upsert(Verdict(
        hw_addr=mac, category="laptop", vendor="Apple",
        platform=None, platform_version=None, model=None, hostname=None,
        certainty=80, evidence_chain=[], computed_at=ts,
    ))
    await db.upsert_device(Device(mac=mac, first_seen=ts, last_seen=ts, **device_kw))


@pytest.mark.asyncio
async def test_list_devices_returns_custom_props(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:01",
                owner="alice", location="room-101",
                criticality="high", tags=["prod", "core"], notes="edge")
    devices, _ = await store.verdicts.list_devices()
    assert len(devices) == 1
    d = devices[0]
    assert d["owner"] == "alice"
    assert d["location"] == "room-101"
    assert d["criticality"] == "high"
    assert d["tags"] == ["prod", "core"]
    assert d["notes"] == "edge"


@pytest.mark.asyncio
async def test_list_devices_returns_authorization_fields(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:02")
    await db.approve_device("aa:bb:cc:dd:ee:02", actor="alice")

    devices, _ = await store.verdicts.list_devices()
    d = devices[0]
    assert d["authorization"] == "approved"
    assert d["authorized_by"] == "alice"
    assert d["authorized_at"] is not None


@pytest.mark.asyncio
async def test_list_devices_defaults_authorization_to_unapproved(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:03")
    devices, _ = await store.verdicts.list_devices()
    d = devices[0]
    assert d["authorization"] == "unapproved"


@pytest.mark.asyncio
async def test_list_devices_returns_presence_fields(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:04", presence_threshold_seconds=900)
    devices, _ = await store.verdicts.list_devices()
    d = devices[0]
    assert d["is_online"] is True
    assert d["offline_since"] is None
    assert d["presence_threshold_seconds"] == 900


@pytest.mark.asyncio
async def test_list_devices_reflects_offline_state(env):
    db, store = env
    await _seed(db, store, "aa:bb:cc:dd:ee:05")
    await db.set_device_offline("aa:bb:cc:dd:ee:05")
    devices, _ = await store.verdicts.list_devices()
    d = devices[0]
    assert d["is_online"] is False
    assert d["offline_since"] is not None


@pytest.mark.asyncio
async def test_list_devices_host_only_gets_defaults(env):
    """A host in hosts table with no devices row should still return sane defaults."""
    _db, store = env
    ts = datetime.now(timezone.utc)
    await store.hosts.upsert(Host(hw_addr="aa:bb:cc:dd:ee:06", disposition="new"))
    # No upsert_device() call — no row in devices
    devices, _ = await store.verdicts.list_devices()
    d = devices[0]
    assert d["authorization"] == "unapproved"
    assert d["is_online"] is True
    assert d["presence_threshold_seconds"] == 300
    assert d["tags"] == []
    assert d["owner"] is None
