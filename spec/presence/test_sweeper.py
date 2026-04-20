"""Phase A.4 Task 30 — presence sweeper tests."""

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from leetha.store.database import Database
from leetha.store.models import Device
from leetha.presence.sweeper import PresenceSweeper, PresenceTransition


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    yield d
    await d.close()


def _dev(mac: str, last_seen: datetime, **kw) -> Device:
    return Device(
        mac=mac,
        first_seen=last_seen, last_seen=last_seen,
        **kw,
    )


@pytest.mark.asyncio
async def test_stale_device_goes_offline(db):
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)  # well past default 300s threshold
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:01", stale))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].mac == "aa:bb:cc:dd:ee:01"
    assert trans[0].new_state == "offline"
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.is_online is False
    assert dev.offline_since is not None


@pytest.mark.asyncio
async def test_fresh_device_stays_online(db):
    now = datetime.now(timezone.utc)
    fresh = now - timedelta(seconds=30)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:02", fresh))

    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert trans == []
    dev = await db.get_device("aa:bb:cc:dd:ee:02")
    assert dev.is_online is True


@pytest.mark.asyncio
async def test_returning_device_goes_back_online(db):
    now = datetime.now(timezone.utc)
    # Start offline via direct set
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:03", now - timedelta(seconds=600)))
    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    await sweeper.sweep_once()  # goes offline

    # New packet arrives; bump last_seen
    await db._conn.execute(
        "UPDATE devices SET last_seen = ? WHERE mac = ?",
        (now.isoformat(), "aa:bb:cc:dd:ee:03"),
    )
    await db._conn.commit()

    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].new_state == "online"
    dev = await db.get_device("aa:bb:cc:dd:ee:03")
    assert dev.is_online is True
    assert dev.offline_since is None


@pytest.mark.asyncio
async def test_idempotent_sweep_no_transitions_second_time(db):
    now = datetime.now(timezone.utc)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:04", now - timedelta(seconds=600)))
    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    first = await sweeper.sweep_once()
    second = await sweeper.sweep_once()
    assert len(first) == 1
    assert second == []


@pytest.mark.asyncio
async def test_callback_invoked_on_transition(db):
    now = datetime.now(timezone.utc)
    await db.upsert_device(_dev("aa:bb:cc:dd:ee:05", now - timedelta(seconds=600)))

    calls: list[PresenceTransition] = []

    async def _cb(t):
        calls.append(t)

    sweeper = PresenceSweeper(db, now_fn=lambda: now, on_transition=_cb)
    await sweeper.sweep_once()
    assert len(calls) == 1
    assert calls[0].new_state == "offline"


@pytest.mark.asyncio
async def test_per_device_threshold_respected(db):
    now = datetime.now(timezone.utc)
    # Custom threshold = 60s; last_seen 90s ago ⇒ should go offline
    await db.upsert_device(_dev(
        "aa:bb:cc:dd:ee:06",
        now - timedelta(seconds=90),
        presence_threshold_seconds=60,
    ))
    sweeper = PresenceSweeper(db, now_fn=lambda: now)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    assert trans[0].new_state == "offline"
