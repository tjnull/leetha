#!/usr/bin/env python3
"""Exercise Leetha's main SQLite queries with an enterprise-sized fixture.

This is a repeatable engineering benchmark, not a claim that SQLite is the
enterprise backend.  It exposes query regressions while PostgreSQL support is
being built.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from leetha.store.store import Store


def _mac(value: int) -> str:
    return ":".join(f"{(value >> shift) & 0xff:02x}" for shift in (40, 32, 24, 16, 8, 0))


async def _initialize(path: Path) -> None:
    store = Store(path)
    await store.initialize()
    await store.close()


def _timed_query(conn: sqlite3.Connection, label: str, sql: str) -> tuple[str, float, int]:
    started = time.perf_counter()
    rows = conn.execute(sql).fetchall()
    return label, (time.perf_counter() - started) * 1000, len(rows)


def run(path: Path, device_count: int, sighting_count: int) -> None:
    asyncio.run(_initialize(path))
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    now = datetime.now(timezone.utc)
    started = time.perf_counter()
    with conn:
        conn.executemany(
            "INSERT INTO hosts "
            "(hw_addr, ip_addr, discovered_at, last_active, disposition) "
            "VALUES (?, ?, ?, ?, 'new')",
            (
                (
                    _mac(i),
                    f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
                    (now - timedelta(seconds=i % 86400)).isoformat(),
                    (now - timedelta(seconds=i % 3600)).isoformat(),
                )
                for i in range(device_count)
            ),
        )
        conn.executemany(
            "INSERT INTO sightings "
            "(hw_addr, source, payload, timestamp, certainty, src_ip, dst_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                (
                    _mac(i % device_count),
                    ("arp", "dhcp", "mdns", "tls")[i % 4],
                    json.dumps({
                        "src_ip": f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
                        "dst_ip": f"10.{((i + 1) >> 16) & 255}.{((i + 1) >> 8) & 255}.{(i + 1) & 255}",
                    }, separators=(",", ":")),
                    (now - timedelta(seconds=i % 86400)).isoformat(),
                    0.8,
                    f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
                    f"10.{((i + 1) >> 16) & 255}.{((i + 1) >> 8) & 255}.{(i + 1) & 255}",
                )
                for i in range(sighting_count)
            ),
        )
    ingest_seconds = time.perf_counter() - started

    queries = (
        _timed_query(
            conn,
            "inventory first page",
            "SELECT h.hw_addr FROM hosts h LEFT JOIN verdicts v ON h.hw_addr=v.hw_addr "
            "ORDER BY h.last_active DESC LIMIT 50",
        ),
        _timed_query(
            conn,
            "24h activity",
            "SELECT strftime('%H', timestamp), COUNT(*) FROM sightings "
            "WHERE timestamp > datetime('now', '-24 hours') GROUP BY 1",
        ),
        _timed_query(
            conn,
            "24h protocols",
            "SELECT source, COUNT(*) FROM sightings "
            "WHERE timestamp > datetime('now', '-24 hours') GROUP BY source",
        ),
        _timed_query(
            conn,
            "device drill-down",
            f"SELECT * FROM sightings WHERE hw_addr='{_mac(0)}' "
            "ORDER BY timestamp DESC LIMIT 100",
        ),
        _timed_query(
            conn,
            "top connections (indexed columns)",
            "SELECT src_ip, dst_ip, COUNT(*) "
            "FROM sightings WHERE timestamp > datetime('now', '-24 hours') "
            "AND src_ip IS NOT NULL AND dst_ip IS NOT NULL "
            "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20",
        ),
    )
    conn.close()

    print(f"database: {path.stat().st_size / 1024 / 1024:.1f} MiB")
    print(f"fixture: {device_count:,} devices, {sighting_count:,} sightings")
    print(f"bulk fixture load: {ingest_seconds:.2f}s")
    for label, elapsed_ms, rows in queries:
        print(f"{label}: {elapsed_ms:.1f}ms ({rows} rows)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=100_000)
    parser.add_argument("--sightings", type=int, default=1_000_000)
    parser.add_argument("--database", type=Path)
    args = parser.parse_args()
    if args.devices < 1 or args.sightings < 0:
        parser.error("--devices must be positive and --sightings cannot be negative")

    if args.database:
        run(args.database, args.devices, args.sightings)
    else:
        with tempfile.TemporaryDirectory(prefix="leetha-storage-") as directory:
            run(Path(directory) / "benchmark.db", args.devices, args.sightings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
