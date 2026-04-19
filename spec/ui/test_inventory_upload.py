"""Phase A.3 Task 25 — POST /api/inventory/dhcp-leases/upload."""

import pytest
import io
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "dhcp_leases"


@pytest.fixture
async def client():
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db = Database(Path(":memory:"))
    await db.initialize()
    mock_app = MagicMock()
    mock_app.db = db
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app), db
    await db.close()


@pytest.mark.asyncio
async def test_upload_isc_leases(client):
    c, db = client
    data = (FIXTURES / "isc_dhcpd.leases").read_bytes()
    r = c.post(
        "/api/inventory/dhcp-leases/upload",
        files={"file": ("isc_dhcpd.leases", io.BytesIO(data), "text/plain")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imported"] == 3
    d = await db.get_device("aa:bb:cc:dd:ee:01")
    assert d is not None
    assert d.hostname == "alice-laptop"
    assert d.passively_observed is False


@pytest.mark.asyncio
async def test_upload_empty_file(client):
    c, _ = client
    r = c.post(
        "/api/inventory/dhcp-leases/upload",
        files={"file": ("empty", io.BytesIO(b""), "text/plain")},
    )
    assert r.status_code == 200
    assert r.json()["imported"] == 0


@pytest.mark.asyncio
async def test_upload_binary_is_tolerated(client):
    """Random binary bytes parse to zero devices; we should not 500."""
    c, _ = client
    r = c.post(
        "/api/inventory/dhcp-leases/upload",
        files={"file": ("bad.bin", io.BytesIO(bytes(range(256))), "application/octet-stream")},
    )
    assert r.status_code in (200, 400)
