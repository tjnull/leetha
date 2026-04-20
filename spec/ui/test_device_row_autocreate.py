"""Regression — mutation endpoints auto-create a devices row for live-only hosts.

Packet capture populates the ``hosts`` table via the Store. Phase A columns live
on the ``devices`` table managed by Database. When a user hits a mutation
endpoint for a MAC they saw in the UI, the devices row may not exist yet —
``_ensure_device_row`` should create it from the host row on demand.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Host


@pytest.fixture
async def live_only_host(tmp_path):
    """Store has a host row but Database has no matching devices row."""
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db_path = tmp_path / "live.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()

    await store.hosts.upsert(Host(
        hw_addr="aa:bb:cc:dd:ee:77",
        ip_addr="10.0.0.77",
        disposition="new",
    ))
    # No upsert_device — the devices row DOES NOT EXIST for this MAC.
    assert await db.get_device("aa:bb:cc:dd:ee:77") is None

    mock_app = MagicMock()
    mock_app.db = db
    mock_app.store = store
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db, store
    await store.close()
    await db.close()


@pytest.mark.asyncio
async def test_patch_auto_creates_devices_row(live_only_host):
    client, db, _store = live_only_host
    r = client.patch(
        "/api/devices/aa:bb:cc:dd:ee:77",
        json={"owner": "live-user", "criticality": "high"},
    )
    assert r.status_code == 200, r.text
    dev = await db.get_device("aa:bb:cc:dd:ee:77")
    assert dev is not None
    assert dev.owner == "live-user"
    assert dev.criticality == "high"
    # Carried from host row
    assert dev.ip_v4 == "10.0.0.77"


@pytest.mark.asyncio
async def test_approve_auto_creates_devices_row(live_only_host):
    client, db, _store = live_only_host
    r = client.post(
        "/api/devices/aa:bb:cc:dd:ee:77/approve",
        json={"reason": "live verification"},
    )
    assert r.status_code == 200, r.text
    dev = await db.get_device("aa:bb:cc:dd:ee:77")
    assert dev is not None
    assert dev.authorization == "approved"


@pytest.mark.asyncio
async def test_unknown_mac_still_404s(live_only_host):
    client, _, _ = live_only_host
    r = client.patch(
        "/api/devices/aa:bb:cc:dd:ee:de",  # neither hosts nor devices
        json={"owner": "nobody"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_bulk_auto_creates_for_known_hosts(live_only_host):
    client, db, _store = live_only_host
    r = client.post("/api/devices/bulk/authorization", json={
        "action": "approve",
        "macs": ["aa:bb:cc:dd:ee:77", "aa:bb:cc:dd:ee:de"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] == 1
    assert body["missing"] == ["aa:bb:cc:dd:ee:de"]
    dev = await db.get_device("aa:bb:cc:dd:ee:77")
    assert dev.authorization == "approved"
