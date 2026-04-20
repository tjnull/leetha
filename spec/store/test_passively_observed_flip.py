"""Phase A follow-up — end-to-end test of passively_observed flip
when a live-capture upsert arrives for an importer-sourced device.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    yield d
    await d.close()


def _now():
    return datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_importer_device_flips_when_live_packet_arrives(db):
    """Importer writes a device with passively_observed=False. A packet-driven
    upsert (which defaults to passively_observed=True) must flip it to True."""
    mac = "aa:bb:cc:dd:ee:01"

    # 1) Importer writes the initial row, not yet observed
    await db.upsert_device(Device(
        mac=mac, first_seen=_now(), last_seen=_now(),
        passively_observed=False,
    ))
    dev = await db.get_device(mac)
    assert dev.passively_observed is False

    # 2) Live packet pipeline upsert — Device() defaults to passively_observed=True
    await db.upsert_device(Device(
        mac=mac, ip_v4="10.0.0.1", first_seen=_now(), last_seen=_now(),
    ))
    dev = await db.get_device(mac)
    assert dev.passively_observed is True, "live packet should flip the flag"


@pytest.mark.asyncio
async def test_flag_does_not_regress_on_second_importer_run(db):
    """Once True, even if the importer re-runs with False, the flag stays True.
    This matches the SQL MAX() semantics and prevents data loss."""
    mac = "aa:bb:cc:dd:ee:02"

    await db.upsert_device(Device(
        mac=mac, first_seen=_now(), last_seen=_now(),
        passively_observed=True,  # live-first path
    ))
    # Importer upserts the same device later
    await db.upsert_device(Device(
        mac=mac, hostname="alice-box",
        first_seen=_now(), last_seen=_now(),
        passively_observed=False,
    ))
    dev = await db.get_device(mac)
    assert dev.passively_observed is True


@pytest.mark.asyncio
async def test_purely_importer_device_stays_false_until_packet(db):
    """A device that never receives a live packet stays passively_observed=False
    across multiple importer refreshes."""
    mac = "aa:bb:cc:dd:ee:03"
    for _ in range(3):
        await db.upsert_device(Device(
            mac=mac, first_seen=_now(), last_seen=_now(),
            passively_observed=False,
        ))
    dev = await db.get_device(mac)
    assert dev.passively_observed is False


@pytest.mark.asyncio
async def test_new_host_rule_unsuppressed_after_flip(db, tmp_path):
    """After the flag flips to True, new_host should no longer be suppressed."""
    from leetha.store.store import Store
    from leetha.store.models import Host
    from leetha.evidence.models import Verdict
    from leetha.rules.discovery import NewHostRule

    # Use the same DB file so rule's store.connection sees the devices row
    db_path = tmp_path / "p.db"
    db2 = Database(db_path)
    await db2.initialize()
    store = Store(str(db_path))
    await store.initialize()
    try:
        mac = "aa:bb:cc:dd:ee:04"
        # Importer adds the row
        await db2.upsert_device(Device(
            mac=mac, first_seen=_now(), last_seen=_now(),
            passively_observed=False,
        ))
        # Rule fires BEFORE packet: suppressed
        host = Host(hw_addr=mac, ip_addr="10.0.0.4", disposition="new")
        verdict = Verdict(
            hw_addr=mac, category="laptop", vendor="Apple",
            platform=None, platform_version=None, model=None, hostname=None,
            certainty=80, evidence_chain=[], computed_at=_now(),
        )
        assert await NewHostRule().evaluate(host, verdict, store) is None

        # Packet arrives → flag flips via pipeline upsert
        await db2.upsert_device(Device(
            mac=mac, ip_v4="10.0.0.4",
            first_seen=_now(), last_seen=_now(),
        ))
        # Now the rule should fire
        finding = await NewHostRule().evaluate(host, verdict, store)
        assert finding is not None
    finally:
        await store.close()
        await db2.close()
