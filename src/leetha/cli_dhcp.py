"""Phase A.3 Task 26 — leetha dhcp-leases CLI."""

from __future__ import annotations

import aiosqlite
from datetime import datetime, timezone
from pathlib import Path

from leetha.config import get_config
from leetha.inventory.importers.dhcp_leases import DHCPLeaseImporter, parse_lease_file
from leetha.store.database import Database
from leetha.store.importer_config import ImporterConfig, ImporterConfigRepository
from leetha.store.models import Device, Host
from leetha.store.store import Store


async def handle_dhcp_command(parsed_args) -> int:
    action = getattr(parsed_args, "dhcp_action", None)
    if action == "import":
        return await _cmd_import(parsed_args)
    if action == "set-path":
        return await _cmd_set_path(parsed_args)
    print("Usage: leetha dhcp-leases {import|set-path} <path>")
    return 2


async def _cmd_import(args) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"File not found: {path}")
        return 1
    try:
        text = path.read_text(errors="replace")
    except Exception as err:
        print(f"Failed to read {path}: {err}")
        return 1
    devices = parse_lease_file(text)
    cfg = get_config()
    db = Database(cfg.db_path)
    await db.initialize()
    store = Store(str(cfg.db_path))
    await store.initialize()
    try:
        ts = datetime.now(timezone.utc)
        for d in devices:
            await db.upsert_device(Device(
                mac=d.mac, ip_v4=d.ip, hostname=d.hostname,
                first_seen=ts, last_seen=ts,
                passively_observed=False,
            ))
            # Also upsert into hosts so the device shows up in the UI list.
            await store.hosts.upsert(Host(
                hw_addr=d.mac, ip_addr=d.ip,
                discovered_at=ts, last_active=ts,
                disposition="new",
            ))
        print(f"Imported {len(devices)} device(s) from {path}")
        return 0
    finally:
        await store.close()
        await db.close()


async def _cmd_set_path(args) -> int:
    path = Path(args.path).expanduser().resolve()
    if not path.exists():
        print(f"Warning: path does not exist yet: {path}")
    cfg = get_config()
    # Use the main leetha DB for importer_config too (Store + Database share paths).
    conn = await aiosqlite.connect(str(cfg.db_path), isolation_level=None)
    conn.row_factory = aiosqlite.Row
    try:
        repo = ImporterConfigRepository(conn)
        await repo.create_tables()
        await repo.upsert(ImporterConfig(
            name="dhcp_leases",
            enabled=True,
            config={"path": str(path), "flavor": "auto"},
        ))
        # Test once so users see immediate feedback
        importer = DHCPLeaseImporter()
        importer.configure({"path": str(path), "flavor": "auto"})
        result = await importer.test_connection()
        print(f"Configured dhcp_leases importer: path={path} ok={result.ok} "
              f"message={result.message}")
        return 0 if result.ok else 1
    finally:
        await conn.close()
