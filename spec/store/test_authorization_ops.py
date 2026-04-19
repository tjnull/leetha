"""Phase A.2 — store-level approve/reject/revoke/baseline_set with audit trail."""

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


async def _history(db: Database, mac: str) -> list[dict]:
    async with db._conn.execute(
        "SELECT previous_state, new_state, actor, reason FROM "
        "authorization_history WHERE mac = ? ORDER BY id",
        (mac,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


@pytest.mark.asyncio
async def test_approve_device_transitions_and_writes_history(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:01"))
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="alice")
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.authorization == "approved"
    assert dev.authorized_by == "alice"
    assert dev.authorized_at is not None

    hist = await _history(db, "aa:bb:cc:dd:ee:01")
    assert len(hist) == 1
    assert hist[0]["previous_state"] == "unapproved"
    assert hist[0]["new_state"] == "approved"
    assert hist[0]["actor"] == "alice"


@pytest.mark.asyncio
async def test_reject_device_transitions_and_writes_history(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:02"))
    await db.reject_device("aa:bb:cc:dd:ee:02", actor="bob", reason="unrecognized")
    dev = await db.get_device("aa:bb:cc:dd:ee:02")
    assert dev.authorization == "rejected"
    assert dev.authorized_by == "bob"

    hist = await _history(db, "aa:bb:cc:dd:ee:02")
    assert hist[0]["reason"] == "unrecognized"


@pytest.mark.asyncio
async def test_revoke_device_returns_to_unapproved(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:03"))
    await db.approve_device("aa:bb:cc:dd:ee:03", actor="alice")
    await db.revoke_device("aa:bb:cc:dd:ee:03", actor="alice")
    dev = await db.get_device("aa:bb:cc:dd:ee:03")
    assert dev.authorization == "unapproved"
    assert dev.authorized_at is None
    assert dev.authorized_by is None

    hist = await _history(db, "aa:bb:cc:dd:ee:03")
    assert len(hist) == 2
    assert hist[-1]["new_state"] == "unapproved"


@pytest.mark.asyncio
async def test_same_state_transition_is_noop_no_history(db):
    """Approving an already-approved device writes no history row."""
    await db.upsert_device(_make("aa:bb:cc:dd:ee:04"))
    await db.approve_device("aa:bb:cc:dd:ee:04", actor="alice")
    await db.approve_device("aa:bb:cc:dd:ee:04", actor="alice")
    hist = await _history(db, "aa:bb:cc:dd:ee:04")
    assert len(hist) == 1


@pytest.mark.asyncio
async def test_baseline_set_only_touches_unapproved(db):
    """baseline_set approves unapproved devices, leaves rejected alone."""
    await db.upsert_device(_make("aa:bb:cc:dd:ee:10"))  # unapproved
    await db.upsert_device(_make("aa:bb:cc:dd:ee:11"))  # unapproved
    await db.upsert_device(_make("aa:bb:cc:dd:ee:12"))
    await db.reject_device("aa:bb:cc:dd:ee:12", actor="alice")

    touched = await db.baseline_set()
    assert touched == 2

    a10 = await db.get_device("aa:bb:cc:dd:ee:10")
    a11 = await db.get_device("aa:bb:cc:dd:ee:11")
    a12 = await db.get_device("aa:bb:cc:dd:ee:12")
    assert a10.authorization == "approved"
    assert a11.authorization == "approved"
    assert a12.authorization == "rejected"
    assert a10.authorized_by == "baseline"


@pytest.mark.asyncio
async def test_baseline_status_counts(db):
    await db.upsert_device(_make("aa:bb:cc:dd:ee:20"))
    await db.upsert_device(_make("aa:bb:cc:dd:ee:21"))
    await db.approve_device("aa:bb:cc:dd:ee:20", actor="x")
    await db.reject_device("aa:bb:cc:dd:ee:21", actor="x")
    await db.upsert_device(_make("aa:bb:cc:dd:ee:22"))

    status = await db.baseline_status()
    assert status["approved"] == 1
    assert status["unapproved"] == 1
    assert status["rejected"] == 1
