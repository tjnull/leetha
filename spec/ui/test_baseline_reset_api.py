"""Phase A follow-up — POST /api/baseline/reset."""

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
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01", first_seen=ts, last_seen=ts,
    ))
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:02", first_seen=ts, last_seen=ts,
    ))
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="alice")

    mock_app = MagicMock()
    mock_app.db = db
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db
    await db.close()


@pytest.mark.asyncio
async def test_baseline_reset_endpoint(client):
    c, db = client
    r = c.post("/api/baseline/reset", json={})
    assert r.status_code == 200
    assert r.json()["touched"] == 1

    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev.authorization == "unapproved"
