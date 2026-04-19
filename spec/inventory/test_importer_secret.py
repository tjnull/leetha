"""Phase A.3 Task 18 — importer_config secret wrappers."""

import pytest
import aiosqlite

from leetha.store.importer_config import ImporterConfig, ImporterConfigRepository


@pytest.fixture
async def repo():
    conn = await aiosqlite.connect(":memory:", isolation_level=None)
    conn.row_factory = aiosqlite.Row
    r = ImporterConfigRepository(conn)
    await r.create_tables()
    yield r
    await conn.close()


@pytest.mark.asyncio
async def test_set_and_get_secret_via_repo(repo, tmp_path):
    await repo.upsert(ImporterConfig(name="unifi"))
    await repo.set_secret("unifi", "hunter2", data_dir=tmp_path)
    got = await repo.get_secret("unifi", data_dir=tmp_path)
    assert got == "hunter2"


@pytest.mark.asyncio
async def test_get_secret_env_override(repo, tmp_path, monkeypatch):
    await repo.upsert(ImporterConfig(name="unifi"))
    await repo.set_secret("unifi", "disk-value", data_dir=tmp_path)
    monkeypatch.setenv("LEETHA_UNIFI_SECRET", "env-value")
    assert await repo.get_secret("unifi", data_dir=tmp_path) == "env-value"
