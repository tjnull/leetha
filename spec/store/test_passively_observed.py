"""Phase A.3 Task 22 — passively_observed column + rule suppression."""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from leetha.store.database import Database
from leetha.store.models import Device, Host, FindingRule
from leetha.evidence.models import Verdict
from leetha.rules.discovery import NewHostRule


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    yield d
    await d.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_default_is_passively_observed_true(db):
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=_now(), last_seen=_now(),
    ))
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.passively_observed is True


@pytest.mark.asyncio
async def test_importer_device_can_set_passively_false(db):
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:02",
        first_seen=_now(), last_seen=_now(),
        passively_observed=False,
    ))
    dev = await db.get_device("aa:bb:cc:dd:ee:02")
    assert dev.passively_observed is False


@pytest.mark.asyncio
async def test_passively_observed_never_flips_back_to_false(db):
    """Once we've seen a packet, passively_observed stays True even if the
    importer upserts the row again with passively_observed=False."""
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:03",
        first_seen=_now(), last_seen=_now(),
        passively_observed=True,
    ))
    # Importer re-upserts with flag=False; existing True must win
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:03",
        first_seen=_now(), last_seen=_now(),
        passively_observed=False,
    ))
    dev = await db.get_device("aa:bb:cc:dd:ee:03")
    assert dev.passively_observed is True


@pytest.mark.asyncio
async def test_new_host_rule_suppressed_when_not_passively_observed(tmp_path):
    from leetha.store.store import Store
    db_path = tmp_path / "p.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    try:
        await db.upsert_device(Device(
            mac="aa:bb:cc:dd:ee:10",
            first_seen=_now(), last_seen=_now(),
            passively_observed=False,
        ))
        host = Host(hw_addr="aa:bb:cc:dd:ee:10", ip_addr="10.0.0.10", disposition="new")
        verdict = Verdict(
            hw_addr="aa:bb:cc:dd:ee:10",
            category="laptop", vendor="Apple", platform=None,
            platform_version=None, model=None, hostname=None,
            certainty=80, evidence_chain=[], computed_at=_now(),
        )
        finding = await NewHostRule().evaluate(host, verdict, store)
        assert finding is None  # suppressed
    finally:
        await store.close()
        await db.close()
