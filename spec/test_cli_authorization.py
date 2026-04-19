"""Phase A.2 — leetha device approve/reject/revoke + baseline CLI."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def seeded_db(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    db = Database(db_path)
    await db.initialize()
    ts = datetime.now(timezone.utc)
    for i in range(3):
        await db.upsert_device(Device(
            mac=f"aa:bb:cc:dd:ee:{i:02x}", first_seen=ts, last_seen=ts,
        ))
    await db.close()

    from leetha import cli_device
    import leetha.config as config_mod
    cfg = SimpleNamespace(db_path=db_path)
    monkeypatch.setattr(cli_device, "get_config", lambda: cfg)
    monkeypatch.setattr(config_mod, "get_config", lambda: cfg)
    return db_path


def _ns(**kw) -> SimpleNamespace:
    return SimpleNamespace(**kw)


@pytest.mark.asyncio
async def test_approve_command(seeded_db):
    from leetha.cli_device import handle_device_command
    rc = await handle_device_command(_ns(
        device_action="approve",
        mac="aa:bb:cc:dd:ee:00", actor="alice", reason=None,
    ))
    assert rc == 0
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:00")
    await db.close()
    assert dev.authorization == "approved"


@pytest.mark.asyncio
async def test_reject_command(seeded_db):
    from leetha.cli_device import handle_device_command
    rc = await handle_device_command(_ns(
        device_action="reject",
        mac="aa:bb:cc:dd:ee:01", actor="alice", reason="unrecognized",
    ))
    assert rc == 0
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    await db.close()
    assert dev.authorization == "rejected"


@pytest.mark.asyncio
async def test_revoke_command(seeded_db):
    from leetha.cli_device import handle_device_command
    await handle_device_command(_ns(
        device_action="approve",
        mac="aa:bb:cc:dd:ee:02", actor="alice", reason=None,
    ))
    rc = await handle_device_command(_ns(
        device_action="revoke",
        mac="aa:bb:cc:dd:ee:02", actor="alice", reason=None,
    ))
    assert rc == 0
    db = Database(seeded_db)
    await db.initialize()
    dev = await db.get_device("aa:bb:cc:dd:ee:02")
    await db.close()
    assert dev.authorization == "unapproved"


@pytest.mark.asyncio
async def test_baseline_set_command(seeded_db, capsys):
    from leetha.cli_device import handle_baseline_command
    rc = await handle_baseline_command(_ns(baseline_action="set"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "3" in out  # 3 seeded devices


@pytest.mark.asyncio
async def test_baseline_status_command(seeded_db, capsys):
    from leetha.cli_device import handle_baseline_command
    rc = await handle_baseline_command(_ns(baseline_action="status"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "unapproved=3" in out
