"""Phase A.4 Task 31 — presence rule tests."""

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Device, Finding, FindingRule, AlertSeverity
from leetha.presence.sweeper import PresenceSweeper, PresenceTransition
from leetha.rules.presence import handle_presence_transition, severity_for_offline


@pytest.fixture
async def env(tmp_path):
    db_path = tmp_path / "p.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


def test_severity_scales_with_criticality():
    assert severity_for_offline(None) == AlertSeverity.INFO
    assert severity_for_offline("low") == AlertSeverity.INFO
    assert severity_for_offline("medium") == AlertSeverity.INFO
    assert severity_for_offline("high") == AlertSeverity.WARNING
    assert severity_for_offline("critical") == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_offline_transition_emits_went_offline_finding(env):
    db, store = env
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
        criticality="critical",
    ))
    t = PresenceTransition(
        mac="aa:bb:cc:dd:ee:01",
        previous_state="online", new_state="offline",
        last_seen=ts - timedelta(seconds=600),
        threshold_seconds=300,
        criticality="critical",
    )
    f = await handle_presence_transition(store, t)
    assert f is not None
    assert f.rule == FindingRule.DEVICE_WENT_OFFLINE
    assert f.severity == AlertSeverity.WARNING

    async with store.connection.execute(
        "SELECT COUNT(*) FROM findings WHERE rule = 'device_went_offline'"
    ) as cur:
        row = await cur.fetchone()
    assert row[0] == 1


@pytest.mark.asyncio
async def test_online_transition_resolves_went_offline(env):
    db, store = env
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:02", first_seen=ts, last_seen=ts,
    ))
    # Pre-seed an unresolved went_offline finding
    await store.findings.add(Finding(
        hw_addr="aa:bb:cc:dd:ee:02",
        rule=FindingRule.DEVICE_WENT_OFFLINE,
        severity=AlertSeverity.INFO,
        message="gone",
    ))

    t = PresenceTransition(
        mac="aa:bb:cc:dd:ee:02",
        previous_state="offline", new_state="online",
        last_seen=ts, threshold_seconds=300,
    )
    f = await handle_presence_transition(store, t)
    assert f is not None
    assert f.rule == FindingRule.DEVICE_CAME_ONLINE

    async with store.connection.execute(
        "SELECT resolved FROM findings WHERE hw_addr = ? AND rule = ?",
        ("aa:bb:cc:dd:ee:02", "device_went_offline"),
    ) as cur:
        rows = await cur.fetchall()
    assert rows
    assert all(bool(r[0]) for r in rows)


@pytest.mark.asyncio
async def test_sweeper_callback_integration(env):
    db, store = env
    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=600)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:03", first_seen=stale, last_seen=stale,
    ))

    async def _cb(t):
        await handle_presence_transition(store, t)

    sweeper = PresenceSweeper(db, now_fn=lambda: now, on_transition=_cb)
    trans = await sweeper.sweep_once()
    assert len(trans) == 1
    # Finding landed in findings table
    async with store.connection.execute(
        "SELECT rule FROM findings WHERE hw_addr = ?", ("aa:bb:cc:dd:ee:03",),
    ) as cur:
        rules = [r[0] for r in await cur.fetchall()]
    assert "device_went_offline" in rules


@pytest.mark.asyncio
async def test_no_duplicate_findings_on_idempotent_sweeps(env):
    db, store = env
    now = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:04",
        first_seen=now - timedelta(seconds=600),
        last_seen=now - timedelta(seconds=600),
    ))

    async def _cb(t):
        await handle_presence_transition(store, t)

    sweeper = PresenceSweeper(db, now_fn=lambda: now, on_transition=_cb)
    await sweeper.sweep_once()
    await sweeper.sweep_once()
    async with store.connection.execute(
        "SELECT COUNT(*) FROM findings WHERE rule = 'device_went_offline' AND hw_addr = ?",
        ("aa:bb:cc:dd:ee:04",),
    ) as cur:
        row = await cur.fetchone()
    assert row[0] == 1
