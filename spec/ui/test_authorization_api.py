"""Phase A.2 — authorization REST endpoints."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def seeded_app(tmp_path):
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db = Database(Path(":memory:"))
    await db.initialize()
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01",
        first_seen=ts, last_seen=ts,
    ))
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:02",
        first_seen=ts, last_seen=ts,
    ))

    mock_app = MagicMock()
    mock_app.db = db
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db
    await db.close()


@pytest.mark.asyncio
async def test_approve_endpoint(seeded_app):
    client, db = seeded_app
    r = client.post("/api/devices/aa:bb:cc:dd:ee:01/approve", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authorization"] == "approved"
    # DB reflects change
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.authorization == "approved"


@pytest.mark.asyncio
async def test_reject_endpoint_with_reason(seeded_app):
    client, db = seeded_app
    r = client.post(
        "/api/devices/aa:bb:cc:dd:ee:01/reject",
        json={"reason": "unrecognized"},
    )
    assert r.status_code == 200
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.authorization == "rejected"


@pytest.mark.asyncio
async def test_revoke_endpoint(seeded_app):
    client, db = seeded_app
    client.post("/api/devices/aa:bb:cc:dd:ee:01/approve", json={})
    r = client.post("/api/devices/aa:bb:cc:dd:ee:01/revoke", json={})
    assert r.status_code == 200
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.authorization == "unapproved"


@pytest.mark.asyncio
async def test_approve_unknown_device_returns_404(seeded_app):
    client, _ = seeded_app
    r = client.post("/api/devices/aa:bb:cc:dd:ee:ff/approve", json={})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_baseline_set_endpoint(seeded_app):
    client, db = seeded_app
    r = client.post("/api/baseline/set", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["touched"] == 2


@pytest.mark.asyncio
async def test_baseline_status_endpoint(seeded_app):
    client, db = seeded_app
    r = client.get("/api/baseline/status")
    assert r.status_code == 200
    body = r.json()
    assert body["unapproved"] == 2
    assert body["approved"] == 0
    assert body["rejected"] == 0
