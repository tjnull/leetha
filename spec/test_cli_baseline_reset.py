"""Phase A follow-up — leetha baseline reset CLI."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def cfg(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    db = Database(db_path)
    await db.initialize()
    ts = datetime.now(timezone.utc)
    for i in range(2):
        await db.upsert_device(Device(
            mac=f"aa:bb:cc:dd:ee:{i:02x}", first_seen=ts, last_seen=ts,
        ))
    await db.approve_device("aa:bb:cc:dd:ee:00", actor="alice")
    await db.close()

    cfg_ns = SimpleNamespace(db_path=db_path, data_dir=tmp_path)
    from leetha import cli_device
    import leetha.config as config_mod
    monkeypatch.setattr(cli_device, "get_config", lambda: cfg_ns)
    monkeypatch.setattr(config_mod, "get_config", lambda: cfg_ns)
    return cfg_ns


@pytest.mark.asyncio
async def test_baseline_reset_command(cfg, capsys):
    from leetha.cli_device import handle_baseline_command
    rc = await handle_baseline_command(SimpleNamespace(baseline_action="reset"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "1" in out  # 1 device was approved before reset

    db = Database(cfg.db_path)
    await db.initialize()
    try:
        dev = await db.get_device("aa:bb:cc:dd:ee:00")
        assert dev.authorization == "unapproved"
    finally:
        await db.close()
