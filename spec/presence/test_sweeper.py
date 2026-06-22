"""Phase A.4 Task 30 — presence sweeper tests."""

import pytest
from datetime import datetime, timedelta, timezone

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Device, Host
from leetha.presence.sweeper import PresenceSweeper, PresenceTransition


@pytest.fixture
async def env(tmp_path):
    """Production-shaped fixture: both Database and Store on the same file,
    so the sweeper's join across hosts + devices works.
    """
    db_path = tmp_path / "sw.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


def _dev(mac: str, last_seen: datetime, **kw) -> Device:
    return Device(mac=mac, first_seen=last_seen, last_seen=last_seen, **kw)


def _host(mac: str, last_active: datetime) -> Host:
    return Host(
        hw_addr=mac, discovered_at=last_active, last_active=last_active,
        disposition="new",
    )


@pytest.mark.asyncio
async def test_stale_device_goes_offline(env):
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:01", stale))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:01", stale))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].mac == "aa:bb:cc:dd:ee:01"
    assert trans[0].new_state == "offline"
    d = await db.get_device("aa:bb:cc:dd:ee:01")
    assert d.is_online is False
    assert d.offline_since is not None


@pytest.mark.asyncio
async def test_fresh_device_stays_online(env):
    db, store = env
    now = datetime.now(timezone.utc)
    fresh = now - timedelta(seconds=30)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:02", fresh))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:02", fresh))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert trans == []
    d = await db.get_device("aa:bb:cc:dd:ee:02")
    assert d.is_online is True


@pytest.mark.asyncio
async def test_returning_device_goes_back_online(env):
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:03", stale))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:03", stale))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    await sweeper.sweep_once()  # -> offline

    # New packet bumps hosts.last_active (the authoritative freshness source)
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:03", now))

    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].new_state == "online"
    d = await db.get_device("aa:bb:cc:dd:ee:03")
    assert d.is_online is True
    assert d.offline_since is None


@pytest.mark.asyncio
async def test_idempotent_sweep_no_transitions_second_time(env):
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:04", stale))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:04", stale))
    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    first = await sweeper.sweep_once()
    second = await sweeper.sweep_once()
    assert len(first) == 1
    assert second == []


@pytest.mark.asyncio
async def test_callback_invoked_on_transition(env):
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:05", stale))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:05", stale))
    calls: list[PresenceTransition] = []

    async def _cb(t): calls.append(t)

    sweeper = PresenceSweeper(db, now_fn=lambda: now, on_transition=_cb)
    await sweeper.sweep_once()
    assert len(calls) == 1
    assert calls[0].new_state == "offline"


@pytest.mark.asyncio
async def test_per_device_threshold_respected(env):
    db, store = env
    now = datetime.now(timezone.utc)
    last_seen = now - timedelta(seconds=90)
    await db.upsert_device(_dev(
        "aa:bb:cc:dd:ee:06", last_seen,
        presence_threshold_seconds=60,
    ))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:06", last_seen))
    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].new_state == "offline"


@pytest.mark.asyncio
async def test_host_only_device_gets_devices_row_auto_created(env):
    """Regression for the live-probe finding: a host in ``hosts`` with no
    ``devices`` row must still be swept. The sweeper auto-creates a minimal
    devices row so it can record is_online/offline_since.
    """
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:07", stale))
    # No upsert_device — this is the scenario the live probe caught.
    assert await db.get_device("aa:bb:cc:dd:ee:07") is None

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].new_state == "offline"
    d = await db.get_device("aa:bb:cc:dd:ee:07")
    assert d is not None
    assert d.is_online is False
    assert d.offline_since is not None


@pytest.mark.asyncio
async def test_host_fresh_packet_keeps_device_online_despite_stale_device_row(env):
    """Regression: devices.last_seen never gets updated by live capture, so if
    we used only devices.last_seen, a live device would look stale. The
    sweeper must prefer hosts.last_active when available.
    """
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(hours=24)
    fresh = now - timedelta(seconds=10)
    # devices.last_seen is a day old (frozen at _ensure_device_row time)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:08", stale))
    # but hosts.last_active was updated a moment ago (live capture in action)
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:08", fresh))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert trans == [], "sweeper should use hosts.last_active, not stale devices.last_seen"
    d = await db.get_device("aa:bb:cc:dd:ee:08")
    assert d.is_online is True


@pytest.mark.asyncio
async def test_devices_only_still_swept_when_no_host_row(env):
    """A DHCP-imported device has hosts + devices rows, but the test exercises
    the code path where only devices exists (e.g. legacy DB)."""
    db, _store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:09", stale))
    # No host row at all
    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].new_state == "offline"


# ---------------------------------------------------------------------------
# Per-device-type + randomized-MAC presence thresholds (audit fix)
# ---------------------------------------------------------------------------

from leetha.presence.sweeper import _effective_threshold, DEFAULT_PRESENCE_THRESHOLD


def test_effective_threshold_type_default():
    # Sleepy device type widens the default 300s window.
    assert _effective_threshold(DEFAULT_PRESENCE_THRESHOLD, "media_device", 0) == 1800


def test_effective_threshold_randomized_floor():
    # A randomized-MAC device never uses less than the randomized minimum.
    assert _effective_threshold(DEFAULT_PRESENCE_THRESHOLD, "computer", 1) >= 1800


def test_effective_threshold_operator_override_wins():
    # A non-default per-device value is an explicit operator choice — respect it.
    assert _effective_threshold(120, "media_device", 1) == 120


@pytest.mark.asyncio
async def test_sleepy_device_does_not_flap_within_type_window(env):
    db, store = env
    now = datetime.now(timezone.utc)
    quiet = now - timedelta(seconds=600)  # > 300 default, < 1800 media default
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:42", quiet, device_type="media_device"))
    await store.hosts.upsert(_host("aa:bb:cc:dd:ee:42", quiet))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert trans == []  # still within the media_device window → no offline flap


@pytest.mark.asyncio
async def test_randomized_mac_device_does_not_flap(env):
    db, store = env
    now = datetime.now(timezone.utc)
    quiet = now - timedelta(seconds=600)
    await db.upsert_device(_dev("fa:7c:26:59:f1:09", quiet, is_randomized_mac=True))
    h = Host(hw_addr="fa:7c:26:59:f1:09", discovered_at=quiet, last_active=quiet,
             disposition="new", mac_randomized=True)
    await store.hosts.upsert(h)

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert trans == []  # randomized-MAC consumer device → no 5-minute flap
