"""Indexes required by the high-cardinality inventory and dashboard paths."""

import pytest
import aiosqlite

from leetha.store.store import Store
from leetha.store.models import Sighting


@pytest.fixture
async def store():
    instance = Store(":memory:")
    await instance.initialize()
    yield instance
    await instance.close()


async def _indexes(store: Store, table: str) -> set[str]:
    cursor = await store.connection.execute(f"PRAGMA index_list({table})")
    return {row[1] for row in await cursor.fetchall()}


@pytest.mark.asyncio
async def test_sightings_have_dashboard_and_host_indexes(store):
    names = await _indexes(store, "sightings")
    assert "idx_sightings_hw_ts" in names
    assert "idx_sightings_ts_source" in names
    assert "idx_sightings_interface_hw" in names
    assert "idx_sightings_connections" in names


@pytest.mark.asyncio
async def test_sighting_addresses_are_stored_without_dashboard_json_scan(store):
    await store.sightings.record(Sighting(
        hw_addr="aa:bb:cc:dd:ee:ff",
        source="arp",
        payload={"src_ip": "10.0.0.1", "target_ip": "10.0.0.2"},
    ))
    cursor = await store.connection.execute(
        "SELECT src_ip, dst_ip FROM sightings"
    )
    assert tuple(await cursor.fetchone()) == ("10.0.0.1", "10.0.0.2")


@pytest.mark.asyncio
async def test_existing_sightings_table_gets_typed_address_columns(tmp_path):
    path = tmp_path / "legacy.db"
    connection = await aiosqlite.connect(path)
    await connection.execute("""
        CREATE TABLE sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hw_addr TEXT NOT NULL,
            source TEXT NOT NULL,
            payload TEXT DEFAULT '{}',
            analysis TEXT DEFAULT '{}',
            certainty REAL DEFAULT 0.0,
            interface TEXT,
            network TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    await connection.execute(
        "INSERT INTO sightings (hw_addr, source, payload, timestamp) "
        "VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", "tls",
         '{"src_ip":"192.0.2.1","dst_ip":"198.51.100.2"}',
         "2026-10-01T00:00:00+00:00"),
    )
    await connection.commit()
    await connection.close()

    migrated = Store(path)
    await migrated.initialize()
    cursor = await migrated.connection.execute(
        "SELECT src_ip, dst_ip FROM sightings"
    )
    assert tuple(await cursor.fetchone()) == ("192.0.2.1", "198.51.100.2")
    await migrated.close()


@pytest.mark.asyncio
async def test_inventory_and_findings_have_sort_indexes(store):
    assert "idx_hosts_last_active" in await _indexes(store, "hosts")
    assert "idx_hosts_discovered_at" in await _indexes(store, "hosts")
    assert "idx_findings_active_ts" in await _indexes(store, "findings")
    assert "idx_findings_hw_ts" in await _indexes(store, "findings")
    assert "idx_snapshots_hw_ts" in await _indexes(store, "fingerprint_snapshots")
