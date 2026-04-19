"""Phase A.1 — leetha device CLI (custom props + tag add/remove)."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def seeded_db(tmp_path, monkeypatch):
    db_path = tmp_path / "leetha.db"
    db = Database(db_path)
    await db.initialize()
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await db.close()

    # Redirect cli_device's get_config() to use this tmp path
    from leetha import cli_device
    import leetha.config as config_mod
    fake_cfg = SimpleNamespace(db_path=db_path)
    monkeypatch.setattr(cli_device, "get_config", lambda: fake_cfg)
    monkeypatch.setattr(config_mod, "get_config", lambda: fake_cfg)
    return db_path


def _ns(**kw) -> SimpleNamespace:
    return SimpleNamespace(**kw)


@pytest.mark.asyncio
async def test_set_all_fields(seeded_db, capsys):
    from leetha.cli_device import handle_device_command

    rc = await handle_device_command(_ns(
        device_action="set",
        mac="aa:bb:cc:dd:ee:01",
        owner="alice",
        location="room-101",
        criticality="high",
        tags="production,core",
        notes="edge router",
    ))
    assert rc == 0
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    await db.close()
    assert dev.owner == "alice"
    assert dev.criticality == "high"
    assert dev.tags == ["production", "core"]


@pytest.mark.asyncio
async def test_set_rejects_invalid_criticality(seeded_db):
    from leetha.cli_device import handle_device_command

    rc = await handle_device_command(_ns(
        device_action="set",
        mac="aa:bb:cc:dd:ee:01",
        owner=None, location=None,
        criticality="bogus",
        tags=None, notes=None,
    ))
    assert rc == 2


@pytest.mark.asyncio
async def test_set_unknown_device_returns_1(seeded_db):
    from leetha.cli_device import handle_device_command

    rc = await handle_device_command(_ns(
        device_action="set",
        mac="aa:bb:cc:dd:ee:ff",
        owner="alice", location=None, criticality=None,
        tags=None, notes=None,
    ))
    assert rc == 1


@pytest.mark.asyncio
async def test_tags_add_is_idempotent(seeded_db):
    from leetha.cli_device import handle_device_command

    await handle_device_command(_ns(
        device_action="tags", tags_action="add",
        mac="aa:bb:cc:dd:ee:01", tag="prod",
    ))
    await handle_device_command(_ns(
        device_action="tags", tags_action="add",
        mac="aa:bb:cc:dd:ee:01", tag="prod",
    ))
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    await db.close()
    assert dev.tags == ["prod"]


@pytest.mark.asyncio
async def test_tags_remove(seeded_db):
    from leetha.cli_device import handle_device_command

    for t in ("prod", "core"):
        await handle_device_command(_ns(
            device_action="tags", tags_action="add",
            mac="aa:bb:cc:dd:ee:01", tag=t,
        ))
    await handle_device_command(_ns(
        device_action="tags", tags_action="remove",
        mac="aa:bb:cc:dd:ee:01", tag="prod",
    ))
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    await db.close()
    assert dev.tags == ["core"]


@pytest.mark.asyncio
async def test_tags_remove_missing_tag_is_noop(seeded_db):
    from leetha.cli_device import handle_device_command

    rc = await handle_device_command(_ns(
        device_action="tags", tags_action="remove",
        mac="aa:bb:cc:dd:ee:01", tag="nope",
    ))
    assert rc == 0
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    await db.close()
    assert dev.tags == []
