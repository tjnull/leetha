"""Regression — GET /api/devices/{mac}/detail must include Phase A fields.

Live probe caught this: the /detail endpoint (used by DeviceDrawer) built
its response via _build_device_dict without merging in the Phase A fields
(owner/location/criticality/tags/notes, authorization/authorized_at/by,
is_online/offline_since/presence_threshold_seconds). The UI fell back to
defaults, which looked right on fresh devices but clobbered real values.
"""

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

    db_path = tmp_path / "detail.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()

    ts = datetime.now(timezone.utc)
    await store.hosts.upsert(Host(
        hw_addr="aa:bb:cc:dd:ee:01", ip_addr="10.0.0.1",
        discovered_at=ts, last_active=ts, disposition="new",
    ))
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01",
        first_seen=ts, last_seen=ts,
        owner="alice", location="lab", criticality="high",
        tags=["prod", "core"], notes="edge router",
        presence_threshold_seconds=900,
    ))
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="admin")

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
async def test_detail_returns_all_phase_a_fields(client):
    c, _ = client
    r = c.get("/api/devices/aa:bb:cc:dd:ee:01/detail")
    assert r.status_code == 200, r.text
    d = r.json()["device"]
    assert d["owner"] == "alice"
    assert d["location"] == "lab"
    assert d["criticality"] == "high"
    assert d["tags"] == ["prod", "core"]
    assert d["notes"] == "edge router"
    assert d["authorization"] == "approved"
    assert d["authorized_by"] == "admin"
    assert d["authorized_at"] is not None
    assert d["is_online"] is True
    assert d["offline_since"] is None
    assert d["presence_threshold_seconds"] == 900


@pytest.mark.asyncio
async def test_detail_defaults_when_no_devices_row(client):
    """Host exists, devices row doesn't — defaults must still be sane."""
    c, _ = client
    from leetha.store.models import Host as _Host
    # Use a fresh MAC that has no devices row
    import leetha.ui.web.app as web_app
    await web_app.app_instance.store.hosts.upsert(_Host(
        hw_addr="aa:bb:cc:dd:ee:02",
        disposition="new",
    ))
    r = c.get("/api/devices/aa:bb:cc:dd:ee:02/detail")
    assert r.status_code == 200, r.text
    d = r.json()["device"]
    assert d["authorization"] == "unapproved"
    assert d["is_online"] is True
    assert d["tags"] == []
    assert d["presence_threshold_seconds"] == 300


@pytest.mark.asyncio
async def test_detail_404_for_unknown_mac(client):
    c, _ = client
    r = c.get("/api/devices/ff:ff:ff:ff:ff:ff/detail")
    assert r.status_code == 404
