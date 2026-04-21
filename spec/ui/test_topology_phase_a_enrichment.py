"""Regression — topology endpoint's devices include Phase A fields.

The UI needs to style topology nodes by criticality and authorization;
that requires the device dicts in /api/topology to carry those fields.
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

    db_path = tmp_path / "topo.db"
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
        owner="alice", location="lab",
        criticality="high", tags=["prod"],
    ))
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="admin")

    mock_app = MagicMock()
    mock_app.db = db
    mock_app.store = store
    mock_app._running = True
    # clear topology cache
    import leetha.ui.web.app as webapp
    webapp._topology_cache = {"data": None, "ts": 0}
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app)
    await store.close()
    await db.close()


@pytest.mark.asyncio
async def test_topology_devices_include_phase_a_fields(client):
    r = client.get("/api/topology")
    assert r.status_code == 200, r.text
    body = r.json()
    nodes = body.get("nodes", [])
    assert nodes, f"topology returned no nodes: {body}"
    ours = next(
        (n for n in nodes if n.get("mac") == "aa:bb:cc:dd:ee:01" or n.get("id") == "aa:bb:cc:dd:ee:01"),
        None,
    )
    assert ours is not None, f"test device not in nodes: {[n.get('mac') or n.get('id') for n in nodes]}"
    for key in ("criticality", "authorization", "owner", "location", "tags"):
        assert key in ours, f"topology node missing Phase A field {key!r}"
    assert ours["criticality"] == "high"
    assert ours["authorization"] == "approved"
    assert ours["owner"] == "alice"
    assert ours["tags"] == ["prod"]
