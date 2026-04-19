"""Phase A.3 Task 26 — leetha dhcp-leases CLI."""

import pytest
from pathlib import Path
from types import SimpleNamespace


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dhcp_leases"


@pytest.fixture
async def cfg(tmp_path, monkeypatch):
    db_path = tmp_path / "leetha.db"
    cfg_ns = SimpleNamespace(db_path=db_path, data_dir=tmp_path)
    from leetha import cli_dhcp
    import leetha.config as config_mod
    monkeypatch.setattr(cli_dhcp, "get_config", lambda: cfg_ns)
    monkeypatch.setattr(config_mod, "get_config", lambda: cfg_ns)
    return cfg_ns


@pytest.mark.asyncio
async def test_dhcp_import_command_loads_fixture(cfg, capsys):
    from leetha.cli_dhcp import handle_dhcp_command
    rc = await handle_dhcp_command(SimpleNamespace(
        dhcp_action="import", path=str(FIXTURES / "isc_dhcpd.leases"),
    ))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Imported 3" in out

    from leetha.store.database import Database
    db = Database(cfg.db_path)
    await db.initialize()
    try:
        dev = await db.get_device("aa:bb:cc:dd:ee:01")
        assert dev is not None
        assert dev.passively_observed is False
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_dhcp_set_path_configures_scheduler(cfg, capsys):
    from leetha.cli_dhcp import handle_dhcp_command
    rc = await handle_dhcp_command(SimpleNamespace(
        dhcp_action="set-path", path=str(FIXTURES / "dnsmasq.leases"),
    ))
    assert rc == 0

    # importer_config row exists
    import aiosqlite
    from leetha.store.importer_config import ImporterConfigRepository
    conn = await aiosqlite.connect(str(cfg.db_path), isolation_level=None)
    conn.row_factory = aiosqlite.Row
    try:
        repo = ImporterConfigRepository(conn)
        got = await repo.get("dhcp_leases")
        assert got is not None
        assert got.enabled is True
        assert "dnsmasq.leases" in got.config["path"]
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_dhcp_import_missing_file_returns_1(cfg):
    from leetha.cli_dhcp import handle_dhcp_command
    rc = await handle_dhcp_command(SimpleNamespace(
        dhcp_action="import", path=str(FIXTURES / "nope"),
    ))
    assert rc == 1
