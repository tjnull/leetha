"""Regression — GET /api/devices/{mac}/authorization/history."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Device, Host


@pytest.fixture
async def client(tmp_path):
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db_path = tmp_path / "h.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()

    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await store.hosts.upsert(Host(
        hw_addr="aa:bb:cc:dd:ee:01",
        discovered_at=ts, last_active=ts, disposition="new",
    ))

    mock_app = MagicMock()
    mock_app.db = db
    mock_app.store = store
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db
    await store.close()
    await db.close()


@pytest.mark.asyncio
async def test_empty_history_returns_empty_list(client):
    c, _ = client
    r = c.get("/api/devices/aa:bb:cc:dd:ee:01/authorization/history")
    assert r.status_code == 200
    body = r.json()
    assert body["mac"] == "aa:bb:cc:dd:ee:01"
    assert body["history"] == []


@pytest.mark.asyncio
async def test_history_records_every_transition(client):
    c, db = client
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="alice", reason="onboard")
    await db.reject_device("aa:bb:cc:dd:ee:01", actor="bob", reason="oops")
    await db.revoke_device("aa:bb:cc:dd:ee:01", actor="carol")

    r = c.get("/api/devices/aa:bb:cc:dd:ee:01/authorization/history")
    assert r.status_code == 200
    body = r.json()
    hist = body["history"]
    assert len(hist) == 3

    # newest first
    assert hist[0]["new_state"] == "unapproved"
    assert hist[0]["actor"] == "carol"
    assert hist[1]["new_state"] == "rejected"
    assert hist[1]["actor"] == "bob"
    assert hist[1]["reason"] == "oops"
    assert hist[2]["new_state"] == "approved"
    assert hist[2]["actor"] == "alice"


@pytest.mark.asyncio
async def test_history_limit_is_respected(client):
    c, db = client
    # 4 transitions: unapproved→approved→unapproved→approved→unapproved
    for _ in range(2):
        await db.approve_device("aa:bb:cc:dd:ee:01", actor="x")
        await db.revoke_device("aa:bb:cc:dd:ee:01", actor="x")

    r = c.get("/api/devices/aa:bb:cc:dd:ee:01/authorization/history?limit=2")
    assert r.status_code == 200
    assert len(r.json()["history"]) == 2


@pytest.mark.asyncio
async def test_unknown_device_returns_404(client):
    c, _ = client
    r = c.get("/api/devices/aa:bb:cc:dd:ee:ff/authorization/history")
    assert r.status_code == 404
