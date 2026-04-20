"""Phase A.4 Task 32 — PATCH accepts presence_threshold_seconds."""

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
    mock_app = MagicMock()
    mock_app.db = db
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db
    await db.close()


@pytest.mark.asyncio
async def test_patch_sets_presence_threshold(client):
    c, db = client
    r = c.patch(
        "/api/devices/aa:bb:cc:dd:ee:01",
        json={"presence_threshold_seconds": 900},
    )
    assert r.status_code == 200, r.text
    assert r.json()["presence_threshold_seconds"] == 900
    assert await db.get_presence_threshold("aa:bb:cc:dd:ee:01") == 900


@pytest.mark.asyncio
async def test_patch_rejects_below_minimum(client):
    c, _ = client
    r = c.patch(
        "/api/devices/aa:bb:cc:dd:ee:01",
        json={"presence_threshold_seconds": 10},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_rejects_above_maximum(client):
    c, _ = client
    r = c.patch(
        "/api/devices/aa:bb:cc:dd:ee:01",
        json={"presence_threshold_seconds": 999999},
    )
    assert r.status_code == 422
