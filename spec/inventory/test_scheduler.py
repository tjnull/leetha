"""Phase A.3 Task 20 — scheduler tests."""

import pytest
import aiosqlite
import random
from datetime import datetime, timedelta, timezone

from leetha.store.importer_config import ImporterConfig, ImporterConfigRepository
from leetha.inventory.scheduler import (
    InventoryScheduler,
    _compute_next_delay,
    _BACKOFF_SERIES,
)


@pytest.fixture
async def repo():
    conn = await aiosqlite.connect(":memory:", isolation_level=None)
    conn.row_factory = aiosqlite.Row
    r = ImporterConfigRepository(conn)
    await r.create_tables()
    yield r
    await conn.close()


def test_jitter_bounds():
    rng = random.Random(0)
    for _ in range(200):
        delay = _compute_next_delay(100, backoff_level=0, rng=rng)
        assert 80 <= delay <= 120


def test_backoff_uses_series():
    rng = random.Random(0)
    for lvl, base in enumerate(_BACKOFF_SERIES, start=1):
        delay = _compute_next_delay(99999, backoff_level=lvl, rng=rng)
        lower = int(base * 0.8)
        upper = int(base * 1.2)
        assert lower <= delay <= upper


def test_backoff_caps_at_last_series_entry():
    rng = random.Random(0)
    delay = _compute_next_delay(99999, backoff_level=999, rng=rng)
    assert delay <= int(_BACKOFF_SERIES[-1] * 1.2)


@pytest.mark.asyncio
async def test_disabled_importer_not_fired(repo):
    await repo.upsert(ImporterConfig(name="x", enabled=False))
    fired = []

    async def _sync(_cfg):
        fired.append(_cfg.name)
        return 0

    sched = InventoryScheduler(repo, _sync)
    await sched.tick_once()
    assert fired == []


@pytest.mark.asyncio
async def test_enabled_importer_with_no_schedule_fires_immediately(repo):
    await repo.upsert(ImporterConfig(name="dhcp_leases", enabled=True))
    fired = []

    async def _sync(cfg):
        fired.append(cfg.name)
        return 5

    sched = InventoryScheduler(repo, _sync, rng=random.Random(0))
    names = await sched.tick_once()
    assert names == ["dhcp_leases"]
    assert fired == ["dhcp_leases"]

    refreshed = await repo.get("dhcp_leases")
    assert refreshed.last_sync_devices == 5
    assert refreshed.last_sync_status == "ok"
    assert refreshed.backoff_level == 0
    assert refreshed.next_sync_at is not None


@pytest.mark.asyncio
async def test_scheduled_in_future_does_not_fire(repo):
    future = datetime.now(timezone.utc) + timedelta(minutes=30)
    await repo.upsert(ImporterConfig(
        name="later", enabled=True, next_sync_at=future,
    ))

    async def _sync(_cfg):
        raise AssertionError("should not fire")

    sched = InventoryScheduler(repo, _sync)
    names = await sched.tick_once()
    assert names == []


@pytest.mark.asyncio
async def test_error_triggers_backoff(repo):
    await repo.upsert(ImporterConfig(name="x", enabled=True))

    async def _sync(_cfg):
        raise RuntimeError("boom")

    sched = InventoryScheduler(repo, _sync, rng=random.Random(0))
    await sched.tick_once()
    cfg = await repo.get("x")
    assert cfg.last_sync_status == "error"
    assert cfg.last_sync_error == "boom"
    assert cfg.backoff_level == 1


@pytest.mark.asyncio
async def test_success_resets_backoff(repo):
    await repo.upsert(ImporterConfig(
        name="x", enabled=True, backoff_level=3,
    ))

    async def _sync(_cfg):
        return 1

    sched = InventoryScheduler(repo, _sync, rng=random.Random(0))
    await sched.tick_once()
    cfg = await repo.get("x")
    assert cfg.backoff_level == 0
    assert cfg.last_sync_status == "ok"
