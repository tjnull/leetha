"""Phase A follow-up — Database.baseline_reset()."""

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


def _now():
    return datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_reset_touches_only_non_unapproved(db):
    for i in range(3):
        await db.upsert_device(Device(
            mac=f"aa:bb:cc:dd:ee:{i:02x}", first_seen=_now(), last_seen=_now(),
        ))
    await db.approve_device("aa:bb:cc:dd:ee:00", actor="a")
    await db.reject_device("aa:bb:cc:dd:ee:01", actor="a")
    # aa:bb:cc:dd:ee:02 remains unapproved

    touched = await db.baseline_reset(actor="baseline-reset")
    assert touched == 2

    for i in range(3):
        dev = await db.get_device(f"aa:bb:cc:dd:ee:{i:02x}")
        assert dev.authorization == "unapproved"
        assert dev.authorized_at is None
        assert dev.authorized_by is None


@pytest.mark.asyncio
async def test_reset_writes_history_rows(db):
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:10", first_seen=_now(), last_seen=_now(),
    ))
    await db.approve_device("aa:bb:cc:dd:ee:10", actor="alice")
    await db.baseline_reset()

    async with db._conn.execute(
        "SELECT previous_state, new_state, reason FROM authorization_history "
        "WHERE mac = 'aa:bb:cc:dd:ee:10' ORDER BY id"
    ) as cur:
        rows = [tuple(r) for r in await cur.fetchall()]
    assert rows == [
        ("unapproved", "approved", None),
        ("approved", "unapproved", "baseline-reset"),
    ]


@pytest.mark.asyncio
async def test_reset_noop_when_all_already_unapproved(db):
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:20", first_seen=_now(), last_seen=_now(),
    ))
    touched = await db.baseline_reset()
    assert touched == 0
