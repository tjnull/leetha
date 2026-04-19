"""Phase A.1 — PATCH /api/devices/{mac} endpoint."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def seeded_app(tmp_path):
    """Real Database instance wired into app_instance; seeds one device."""
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app

    db = Database(Path(":memory:"))
    await db.initialize()
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac="aa:bb:cc:dd:ee:01",
        first_seen=ts, last_seen=ts,
    ))

    mock_app = MagicMock()
    mock_app.db = db
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False

    yield TestClient(fastapi_app), db, "aa:bb:cc:dd:ee:01"
    await db.close()


@pytest.mark.asyncio
async def test_patch_device_sets_all_props(seeded_app):
    client, db, mac = seeded_app
    response = client.patch(
        f"/api/devices/{mac}",
        json={
            "owner": "alice",
            "location": "room-101",
            "criticality": "high",
            "tags": ["production", "core"],
            "notes": "edge router",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["owner"] == "alice"
    assert body["location"] == "room-101"
    assert body["criticality"] == "high"
    assert body["tags"] == ["production", "core"]
    assert body["notes"] == "edge router"

    # Round-trip: DB reflects changes
    d = await db.get_device(mac)
    assert d.owner == "alice"
    assert d.tags == ["production", "core"]


@pytest.mark.asyncio
async def test_patch_rejects_invalid_criticality(seeded_app):
    client, _, mac = seeded_app
    response = client.patch(f"/api/devices/{mac}", json={"criticality": "bogus"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_patch_rejects_more_than_20_tags(seeded_app):
    client, _, mac = seeded_app
    response = client.patch(
        f"/api/devices/{mac}",
        json={"tags": [f"tag-{i}" for i in range(21)]},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_patch_rejects_non_string_tag(seeded_app):
    client, _, mac = seeded_app
    response = client.patch(f"/api/devices/{mac}", json={"tags": ["ok", 42]})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_patch_rejects_empty_tag(seeded_app):
    client, _, mac = seeded_app
    response = client.patch(f"/api/devices/{mac}", json={"tags": ["valid", "  "]})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_patch_partial_update_preserves_other_fields(seeded_app):
    client, _, mac = seeded_app
    client.patch(f"/api/devices/{mac}", json={"owner": "alice"})
    response = client.patch(f"/api/devices/{mac}", json={"notes": "rebooted"})
    assert response.status_code == 200
    body = response.json()
    assert body["owner"] == "alice"
    assert body["notes"] == "rebooted"


@pytest.mark.asyncio
async def test_patch_unknown_device_returns_404(seeded_app):
    client, _, _ = seeded_app
    response = client.patch(
        "/api/devices/aa:bb:cc:dd:ee:fe",
        json={"owner": "alice"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_patch_owner_and_location_max_length(seeded_app):
    client, _, mac = seeded_app
    response = client.patch(
        f"/api/devices/{mac}",
        json={"owner": "x" * 201},
    )
    assert response.status_code == 422
