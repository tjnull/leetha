"""Regression — list_devices returns devices.hostname when verdicts.hostname is null,
and the ``q`` search matches devices.hostname too.

DHCP-imported devices populate ``devices.hostname`` (via the pipeline's Device
upsert) but have no verdicts row yet. Without the COALESCE + search fix,
those devices showed no hostname in the list and could not be searched by
hostname until the fingerprint pipeline later produced a verdict.
"""

import pytest
from datetime import datetime, timezone

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Host, Device


@pytest.fixture
async def env(tmp_path):
    db_path = tmp_path / "x.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


@pytest.mark.asyncio
async def test_list_hostname_falls_back_to_devices_hostname(env):
    db, store = env
    ts = datetime.now(timezone.utc)
    mac = "aa:bb:cc:dd:ee:01"
    # Live-import flow: both hosts and devices get the record, no verdict exists.
    await store.hosts.upsert(Host(
        hw_addr=mac, ip_addr="10.0.0.1",
        discovered_at=ts, last_active=ts,
        disposition="new",
    ))
    await db.upsert_device(Device(
        mac=mac, ip_v4="10.0.0.1", hostname="printer-01",
        first_seen=ts, last_seen=ts,
        passively_observed=False,
    ))

    devices, _ = await store.verdicts.list_devices()
    assert len(devices) == 1
    assert devices[0]["hostname"] == "printer-01"


@pytest.mark.asyncio
async def test_search_matches_devices_hostname(env):
    db, store = env
    ts = datetime.now(timezone.utc)
    await store.hosts.upsert(Host(
        hw_addr="aa:bb:cc:dd:ee:02", ip_addr=None,
        discovered_at=ts, last_active=ts, disposition="new",
    ))
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:02", hostname="probe-host-xyz",
        first_seen=ts, last_seen=ts,
    ))

    found, total = await store.verdicts.list_devices(q="probe-host-xyz")
    assert total == 1
    assert found[0]["mac"] == "aa:bb:cc:dd:ee:02"
    assert found[0]["hostname"] == "probe-host-xyz"


@pytest.mark.asyncio
async def test_verdict_hostname_still_wins_when_present(env):
    """If a verdict has been computed, its hostname remains authoritative."""
    from leetha.evidence.models import Verdict
    db, store = env
    ts = datetime.now(timezone.utc)
    mac = "aa:bb:cc:dd:ee:03"
    await store.hosts.upsert(Host(
        hw_addr=mac, ip_addr=None,
        discovered_at=ts, last_active=ts, disposition="new",
    ))
    await store.verdicts.upsert(Verdict(
        hw_addr=mac, category=None, vendor=None, platform=None,
        platform_version=None, model=None,
        hostname="pipeline-polished",
        certainty=80, evidence_chain=[], computed_at=ts,
    ))
    await db.upsert_device(Device(
        mac=mac, hostname="raw-dhcp-name",
        first_seen=ts, last_seen=ts,
    ))

    devices, _ = await store.verdicts.list_devices()
    assert devices[0]["hostname"] == "pipeline-polished"
