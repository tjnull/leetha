"""Phase A.3 — importer_config repository tests."""

import pytest
import aiosqlite
from pathlib import Path

from leetha.store.importer_config import (
    ImporterConfig,
    ImporterConfigRepository,
)


@pytest.fixture
async def repo(tmp_path):
    conn = await aiosqlite.connect(":memory:", isolation_level=None)
    conn.row_factory = aiosqlite.Row
    r = ImporterConfigRepository(conn)
    await r.create_tables()
    yield r
    await conn.close()


@pytest.mark.asyncio
async def test_upsert_and_get(repo):
    await repo.upsert(ImporterConfig(name="dhcp_leases", enabled=True, interval_seconds=600))
    got = await repo.get("dhcp_leases")
    assert got is not None
    assert got.name == "dhcp_leases"
    assert got.enabled is True
    assert got.interval_seconds == 600


@pytest.mark.asyncio
async def test_upsert_updates_existing(repo):
    await repo.upsert(ImporterConfig(name="dhcp_leases", enabled=False))
    await repo.upsert(ImporterConfig(name="dhcp_leases", enabled=True, interval_seconds=120))
    got = await repo.get("dhcp_leases")
    assert got.enabled is True
    assert got.interval_seconds == 120


@pytest.mark.asyncio
async def test_get_unknown_returns_none(repo):
    assert await repo.get("nope") is None


@pytest.mark.asyncio
async def test_list_all(repo):
    await repo.upsert(ImporterConfig(name="a"))
    await repo.upsert(ImporterConfig(name="b"))
    rows = await repo.list_all()
    assert {r.name for r in rows} == {"a", "b"}


@pytest.mark.asyncio
async def test_mark_synced(repo):
    await repo.upsert(ImporterConfig(name="dhcp_leases"))
    await repo.mark_synced("dhcp_leases", devices_count=42)
    got = await repo.get("dhcp_leases")
    assert got.last_sync_devices == 42
    assert got.last_sync_status == "ok"
    assert got.last_sync_at is not None


@pytest.mark.asyncio
async def test_set_status_error(repo):
    await repo.upsert(ImporterConfig(name="dhcp_leases"))
    await repo.set_status("dhcp_leases", "error", error="boom")
    got = await repo.get("dhcp_leases")
    assert got.last_sync_status == "error"
    assert got.last_sync_error == "boom"


@pytest.mark.asyncio
async def test_schedule_next_sync_uses_interval(repo):
    await repo.upsert(ImporterConfig(name="dhcp_leases", interval_seconds=60))
    await repo.schedule_next_sync("dhcp_leases")
    got = await repo.get("dhcp_leases")
    assert got.next_sync_at is not None


@pytest.mark.asyncio
async def test_config_json_roundtrip(repo):
    await repo.upsert(ImporterConfig(
        name="x", config={"path": "/var/dhcp.leases", "flavor": "isc"},
    ))
    got = await repo.get("x")
    assert got.config == {"path": "/var/dhcp.leases", "flavor": "isc"}
