"""Phase A follow-up — POST /api/devices/bulk/authorization."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def client():
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db = Database(Path(":memory:"))
    await db.initialize()
    ts = datetime.now(timezone.utc)
    for i in range(3):
        await db.upsert_device(Device(
            mac=f"aa:bb:cc:dd:ee:{i:02x}", first_seen=ts, last_seen=ts,
        ))

    mock_app = MagicMock()
    mock_app.db = db
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db
    await db.close()


@pytest.mark.asyncio
async def test_bulk_approve_many_devices(client):
    c, db = client
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "approve",
        "macs": ["aa:bb:cc:dd:ee:00", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] == 3
    assert body["missing"] == []

    for i in range(3):
        dev = await db.get_device(f"aa:bb:cc:dd:ee:{i:02x}")
        assert dev.authorization == "approved"


@pytest.mark.asyncio
async def test_bulk_reject_with_reason(client):
    c, db = client
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "reject",
        "macs": ["aa:bb:cc:dd:ee:00"],
        "reason": "spam",
    })
    assert r.status_code == 200
    dev = await db.get_device("aa:bb:cc:dd:ee:00")
    assert dev.authorization == "rejected"


@pytest.mark.asyncio
async def test_bulk_revoke(client):
    c, db = client
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="a")
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "revoke",
        "macs": ["aa:bb:cc:dd:ee:01"],
    })
    assert r.status_code == 200
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.authorization == "unapproved"


@pytest.mark.asyncio
async def test_bulk_partial_missing(client):
    c, _ = client
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "approve",
        "macs": ["aa:bb:cc:dd:ee:00", "aa:bb:cc:dd:ee:fe"],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["updated"] == 1
    assert body["missing"] == ["aa:bb:cc:dd:ee:fe"]


@pytest.mark.asyncio
async def test_bulk_rejects_invalid_action(client):
    c, _ = client
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "delete",  # not allowed
        "macs": ["aa:bb:cc:dd:ee:00"],
    })
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_bulk_rejects_empty_mac_list(client):
    c, _ = client
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "approve",
        "macs": [],
    })
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_bulk_enforces_upper_bound(client):
    c, _ = client
    r = c.post("/api/devices/bulk/authorization", json={
        "action": "approve",
        "macs": [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(501)],
    })
    assert r.status_code == 422
