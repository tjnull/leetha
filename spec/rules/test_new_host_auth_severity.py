"""Phase A.2 — new_host rule severity graded by device authorization."""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from leetha.rules.discovery import NewHostRule
from leetha.store.database import Database
from leetha.store.models import Host, Device, AlertSeverity, FindingRule
from leetha.evidence.models import Verdict


@pytest.fixture
async def db_and_store(tmp_path):
    from leetha.store.store import Store
    db_path = tmp_path / "auth.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    yield db, store
    await store.close()
    await db.close()


def _host() -> Host:
    return Host(hw_addr="aa:bb:cc:dd:ee:01", ip_addr="10.0.0.1", disposition="new")


def _verdict() -> Verdict:
    return Verdict(
        hw_addr="aa:bb:cc:dd:ee:01",
        category="laptop",
        vendor="Apple",
        platform="macOS",
        platform_version=None,
        model=None,
        hostname=None,
        certainty=80,
        evidence_chain=[],
        computed_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_new_host_unapproved_fires_warning(db_and_store):
    db, store = db_and_store
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    # default authorization = 'unapproved'

    rule = NewHostRule()
    finding = await rule.evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.severity == AlertSeverity.WARNING
    assert finding.rule == FindingRule.NEW_HOST


@pytest.mark.asyncio
async def test_new_host_approved_fires_info(db_and_store):
    db, store = db_and_store
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="alice")

    rule = NewHostRule()
    finding = await rule.evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.severity == AlertSeverity.INFO


@pytest.mark.asyncio
async def test_new_host_rejected_fires_critical(db_and_store):
    db, store = db_and_store
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await db.reject_device("aa:bb:cc:dd:ee:01", actor="alice")

    rule = NewHostRule()
    finding = await rule.evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_new_host_no_device_row_defaults_to_warning(db_and_store):
    """If device row hasn't been created yet, treat as unapproved (WARNING)."""
    _db, store = db_and_store
    rule = NewHostRule()
    finding = await rule.evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_approve_resolves_pending_new_host_finding(db_and_store):
    """Approving a device resolves any unresolved new_host findings for that MAC."""
    db, store = db_and_store
    ts = datetime.now(timezone.utc)
    from leetha.store.models import Finding
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await store.findings.add(Finding(
        hw_addr="aa:bb:cc:dd:ee:01",
        rule=FindingRule.NEW_HOST,
        severity=AlertSeverity.WARNING,
        message="New host discovered",
    ))

    await db.approve_device("aa:bb:cc:dd:ee:01", actor="alice")

    async with store.connection.execute(
        "SELECT resolved FROM findings WHERE hw_addr = ? AND rule = 'new_host'",
        ("aa:bb:cc:dd:ee:01",),
    ) as cur:
        rows = await cur.fetchall()
    assert rows
    assert all(bool(r[0]) for r in rows)
