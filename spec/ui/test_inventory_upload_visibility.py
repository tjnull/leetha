"""Regression — DHCP-uploaded devices must appear in /api/devices list."""

import pytest
import io
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database
from leetha.store.store import Store


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "dhcp_leases"


@pytest.fixture
async def client(tmp_path):
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db_path = tmp_path / "live.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()

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
async def test_uploaded_devices_appear_in_list(client):
    c, db, store = client
    data = (FIXTURES / "isc_dhcpd.leases").read_bytes()
    r = c.post(
        "/api/inventory/dhcp-leases/upload",
        files={"file": ("leases", io.BytesIO(data), "text/plain")},
    )
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 3

    # hosts table should now contain the 3 imported MACs
    host = await store.hosts.find_by_addr("aa:bb:cc:dd:ee:01")
    assert host is not None
    assert host.ip_addr == "192.168.1.100"

    # devices table also has them, with passively_observed=False
    dev = await db.get_device("aa:bb:cc:dd:ee:01")
    assert dev is not None
    assert dev.passively_observed is False

    # API list returns them
    resp = c.get("/api/devices?per_page=50")
    assert resp.status_code == 200
    body = resp.json()
    macs = {d["mac"] for d in body["devices"]}
    assert "aa:bb:cc:dd:ee:01" in macs
    assert "aa:bb:cc:dd:ee:02" in macs
    assert "aa:bb:cc:dd:ee:03" in macs
