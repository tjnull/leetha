"""Phase A.3 Task 24 — DHCP importer integration with scheduler + store."""

import pytest
import aiosqlite
import random
from datetime import datetime, timezone
from pathlib import Path

from leetha.inventory import get_importer
from leetha.inventory.scheduler import InventoryScheduler
from leetha.store.database import Database
from leetha.store.importer_config import ImporterConfig, ImporterConfigRepository
from leetha.store.models import Device


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "dhcp_leases"


def test_registry_has_dhcp_leases_after_import():
    cls = get_importer("dhcp_leases")
    assert cls is not None
    assert cls._importer_name == "dhcp_leases"


@pytest.mark.asyncio
async def test_scheduler_triggers_dhcp_import_into_store(tmp_path):
    db = Database(tmp_path / "x.db")
    await db.initialize()

    conn = await aiosqlite.connect(":memory:", isolation_level=None)
    conn.row_factory = aiosqlite.Row
    repo = ImporterConfigRepository(conn)
    await repo.create_tables()
    try:
        await repo.upsert(ImporterConfig(
            name="dhcp_leases",
            enabled=True,
            config={"path": str(FIXTURES / "isc_dhcpd.leases"), "flavor": "isc"},
        ))

        async def _sync(cfg):
            importer_cls = get_importer(cfg.name)
            assert importer_cls is not None
            imp = importer_cls()
            imp.configure(cfg.config)
            count = 0
            ts = datetime.now(timezone.utc)
            async for dev in imp.sync():
                await db.upsert_device(Device(
                    mac=dev.mac,
                    ip_v4=dev.ip,
                    hostname=dev.hostname,
                    first_seen=ts, last_seen=ts,
                    passively_observed=False,
                ))
                count += 1
            return count

        sched = InventoryScheduler(repo, _sync, rng=random.Random(0))
        fired = await sched.tick_once()
        assert fired == ["dhcp_leases"]

        # 3 devices from the fixture, all passively_observed=False
        for mac in ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"):
            d = await db.get_device(mac)
            assert d is not None, f"missing {mac}"
            assert d.passively_observed is False
            assert d.ip_v4 is not None

        cfg = await repo.get("dhcp_leases")
        assert cfg.last_sync_status == "ok"
        assert cfg.last_sync_devices == 3
    finally:
        await conn.close()
        await db.close()
