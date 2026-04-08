"""Tests for OverrideRepository."""
import json
import pytest
import aiosqlite
from datetime import datetime, timezone

from leetha.store.overrides import OverrideRepository, ALLOWED_FIELDS


@pytest.fixture
async def repo():
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    r = OverrideRepository(conn)
    await r.create_tables()
    yield r
    await conn.close()


@pytest.mark.asyncio
async def test_upsert_and_find(repo):
    result = await repo.upsert("aa:bb:cc:dd:ee:ff", {
        "hostname": "myhost",
        "device_type": "switch",
        "manufacturer": "Cisco",
    })
    assert result["hw_addr"] == "aa:bb:cc:dd:ee:ff"
    assert result["hostname"] == "myhost"
    assert result["device_type"] == "switch"
    assert result["manufacturer"] == "Cisco"

    found = await repo.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found is not None
    assert found["hostname"] == "myhost"
    assert found["device_type"] == "switch"


@pytest.mark.asyncio
async def test_upsert_merges_existing(repo):
    await repo.upsert("aa:bb:cc:dd:ee:ff", {
        "hostname": "myhost",
        "manufacturer": "Cisco",
    })
    await repo.upsert("aa:bb:cc:dd:ee:ff", {
        "device_type": "router",
    })
    found = await repo.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found["hostname"] == "myhost"       # preserved from first upsert
    assert found["manufacturer"] == "Cisco"    # preserved from first upsert
    assert found["device_type"] == "router"    # added by second upsert


@pytest.mark.asyncio
async def test_find_by_addr_returns_none(repo):
    found = await repo.find_by_addr("ff:ff:ff:ff:ff:ff")
    assert found is None


@pytest.mark.asyncio
async def test_delete(repo):
    await repo.upsert("aa:bb:cc:dd:ee:ff", {"hostname": "gone"})
    await repo.delete("aa:bb:cc:dd:ee:ff")
    found = await repo.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found is None


@pytest.mark.asyncio
async def test_find_all(repo):
    await repo.upsert("aa:bb:cc:dd:ee:ff", {"hostname": "host1"})
    await repo.upsert("11:22:33:44:55:66", {"hostname": "host2"})
    all_overrides = await repo.find_all()
    assert len(all_overrides) == 2
    addrs = {o["hw_addr"] for o in all_overrides}
    assert addrs == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}


@pytest.mark.asyncio
async def test_unknown_fields_ignored(repo):
    result = await repo.upsert("aa:bb:cc:dd:ee:ff", {
        "hostname": "valid",
        "bogus_field": "should be ignored",
        "another_bad": 42,
    })
    assert result["hostname"] == "valid"
    assert "bogus_field" not in result
    assert "another_bad" not in result


@pytest.mark.asyncio
async def test_updated_at_set_automatically(repo):
    before = datetime.now(timezone.utc).isoformat()
    result = await repo.upsert("aa:bb:cc:dd:ee:ff", {"hostname": "ts"})
    after = datetime.now(timezone.utc).isoformat()
    assert result["updated_at"] is not None
    assert before <= result["updated_at"] <= after


@pytest.mark.asyncio
async def test_migrate_from_json_file(repo, tmp_path):
    json_path = tmp_path / "device_overrides.json"
    json_path.write_text(json.dumps({
        "aa:bb:cc:dd:ee:ff": {"device_type": "printer", "manufacturer": "HP"},
        "11:22:33:44:55:66": {"os_family": "Linux"},
    }))
    migrated = await repo.migrate_from_json(json_path)
    assert migrated == 2
    assert (tmp_path / "device_overrides.json.bak").exists()
    assert not json_path.exists()
    r1 = await repo.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert r1["device_type"] == "printer"


@pytest.mark.asyncio
async def test_migrate_no_file(repo, tmp_path):
    migrated = await repo.migrate_from_json(tmp_path / "device_overrides.json")
    assert migrated == 0


@pytest.mark.asyncio
async def test_allowed_fields_is_frozenset():
    assert isinstance(ALLOWED_FIELDS, frozenset)
    assert "hostname" in ALLOWED_FIELDS
    assert "hw_addr" not in ALLOWED_FIELDS
