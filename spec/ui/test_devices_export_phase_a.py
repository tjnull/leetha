"""Regression — CSV + JSON exports include Phase A fields."""

import pytest
import csv
import io
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

    db_path = tmp_path / "exp.db"
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
        tags=["prod", "core"], notes="edge",
    ))
    await db.approve_device("aa:bb:cc:dd:ee:01", actor="admin")

    mock_app = MagicMock()
    mock_app.db = db
    mock_app.store = store
    mock_app._running = True
    web_app.app_instance = mock_app
    web_app._auth_enabled = False
    yield TestClient(fastapi_app)
    await store.close()
    await db.close()


@pytest.mark.asyncio
async def test_csv_export_header_includes_phase_a_fields(client):
    r = client.get("/api/devices/export?format=csv")
    assert r.status_code == 200
    header = r.text.splitlines()[0]
    for col in ("owner", "location", "criticality", "tags", "notes",
                "authorization", "authorized_by",
                "is_online", "presence_threshold_seconds"):
        assert col in header, f"CSV header missing {col!r}: {header}"


@pytest.mark.asyncio
async def test_csv_export_data_roundtrip(client):
    r = client.get("/api/devices/export?format=csv")
    reader = csv.DictReader(io.StringIO(r.text))
    row = next(reader)
    assert row["owner"] == "alice"
    assert row["criticality"] == "high"
    assert row["authorization"] == "approved"
    assert row["tags"] == "prod,core"  # list serialized as comma-joined
    assert row["presence_threshold_seconds"] == "300"


@pytest.mark.asyncio
async def test_json_export_includes_phase_a_fields(client):
    r = client.get("/api/devices/export?format=json")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    row = rows[0]
    for col in ("owner", "location", "criticality", "tags", "notes",
                "authorization", "authorized_at", "authorized_by",
                "is_online", "offline_since", "presence_threshold_seconds"):
        assert col in row, f"JSON export missing {col!r}"
    assert row["owner"] == "alice"
    assert row["tags"] == ["prod", "core"]  # list preserved in JSON
    assert row["authorization"] == "approved"
