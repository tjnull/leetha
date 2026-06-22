"""Exposure-engine regression tests against crafted sightings.

These pin the audit fixes:
  * the context builder reads real data from hosts/verdicts/sightings
    (not the never-written `observations` table),
  * "protocol present on a normal network" findings are INFO/LOW inventory,
    not HIGH,
  * a single RA sender is INFO but multiple RA senders escalate to HIGH,
  * attack chains only assemble from actionable (MEDIUM+) findings,
  * the per-(device, source) cap keeps a low-volume actionable signal even
    when the device is extremely chatty in another protocol.
"""

import json
import itertools
import pytest

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.analysis.attack_surface import analyze_attack_surface

_counter = itertools.count()


async def _mkdb(tmp_path):
    # In production the legacy Database (devices/probe_targets) and the new
    # Store (hosts/verdicts/sightings) share one sqlite file. Recreate that:
    # initialise the Store schema, then drive everything through Database.
    path = tmp_path / f"as_{next(_counter)}.db"
    store = Store(path)
    await store.initialize()
    await store.close()
    db = Database(path)
    await db.initialize()
    return db


async def _add_host(db, mac, ip=None, vendor=None, category=None, platform=None):
    await db._conn.execute(
        "INSERT INTO hosts (hw_addr, ip_addr, discovered_at, last_active,"
        " mac_randomized, disposition) VALUES (?,?,?,?,0,'new')",
        (mac, ip, "2026-06-21T00:00:00+00:00", "2026-06-21T00:00:00+00:00"),
    )
    if vendor or category or platform:
        await db._conn.execute(
            "INSERT INTO verdicts (hw_addr, vendor, category, platform,"
            " certainty, computed_at) VALUES (?,?,?,?,?,?)",
            (mac, vendor, category, platform, 90, "2026-06-21T00:00:00+00:00"),
        )
    await db._conn.commit()


async def _add_sighting(db, mac, source, payload, ts="2026-06-21T00:00:00+00:00"):
    await db._conn.execute(
        "INSERT INTO sightings (hw_addr, source, payload, certainty, timestamp)"
        " VALUES (?,?,?,?,?)",
        (mac, source, json.dumps(payload), 0.9, ts),
    )
    await db._conn.commit()


def _by_id(findings):
    return {f["rule_id"]: f for f in findings}


async def test_builder_reads_sightings_not_observations(tmp_path):
    """analyze_attack_surface must surface findings from sightings data."""
    db = await _mkdb(tmp_path)
    await _add_host(db, "aa:bb:cc:00:00:01", "192.168.1.50")
    await _add_sighting(db, "aa:bb:cc:00:00:01", "mdns", {"service_type": "_ipp._tcp"})
    rep = await analyze_attack_surface(db)
    assert "NR-003" in _by_id(rep["findings"])  # mDNS detected from sightings
    await db.close()


async def test_presence_protocols_are_inventory_not_high(tmp_path):
    db = await _mkdb(tmp_path)
    await _add_host(db, "aa:bb:cc:00:00:01", "192.168.1.50")
    await _add_sighting(db, "aa:bb:cc:00:00:01", "mdns", {"service_type": "_ipp._tcp"})
    await _add_sighting(db, "aa:bb:cc:00:00:01", "dhcpv6", {"oro": "23"})
    rep = await analyze_attack_surface(db)
    fb = _by_id(rep["findings"])
    assert fb["NR-003"]["severity"] == "info"   # mDNS
    assert fb["DH-004"]["severity"] == "info"   # DHCPv6 presence
    # Nothing here should be HIGH/CRITICAL.
    assert not [f for f in rep["findings"] if f["severity"] in ("high", "critical")]
    await db.close()


async def test_single_ra_sender_is_info_multiple_is_high(tmp_path):
    # One RA sender = the normal router → INFO
    db = await _mkdb(tmp_path)
    await _add_host(db, "aa:bb:cc:00:00:0a", "192.168.1.1", category="router")
    await _add_sighting(db, "aa:bb:cc:00:00:0a", "icmpv6",
                        {"icmpv6_type": "router_advertisement"})
    rep = await analyze_attack_surface(db)
    assert _by_id(rep["findings"])["RT-001"]["severity"] == "info"
    await db.close()

    # Two distinct RA senders = candidate rogue RA → HIGH
    db = await _mkdb(tmp_path)
    await _add_host(db, "aa:bb:cc:00:00:0a", "192.168.1.1", category="router")
    await _add_host(db, "aa:bb:cc:00:00:0b", "192.168.1.66")
    await _add_sighting(db, "aa:bb:cc:00:00:0a", "icmpv6",
                        {"icmpv6_type": "router_advertisement"})
    await _add_sighting(db, "aa:bb:cc:00:00:0b", "icmpv6",
                        {"icmpv6_type": "router_advertisement"})
    rep = await analyze_attack_surface(db)
    assert _by_id(rep["findings"])["RT-001"]["severity"] == "high"
    await db.close()


async def test_chains_only_build_from_actionable_findings(tmp_path):
    """LLDP presence (INFO L2-006) must NOT assemble the STP takeover chain."""
    db = await _mkdb(tmp_path)
    await _add_host(db, "aa:bb:cc:00:00:0c", "192.168.1.3", category="switch")
    await _add_sighting(db, "aa:bb:cc:00:00:0c", "lldp",
                        {"chassis_id": "aa:bb:cc:00:00:0c", "system_name": "sw1"})
    rep = await analyze_attack_surface(db)
    assert _by_id(rep["findings"])["L2-006"]["severity"] == "info"
    assert rep["chains"] == []  # no CHAIN-010 from inventory LLDP
    await db.close()


async def test_per_source_cap_keeps_low_volume_signal(tmp_path):
    """A WPAD query must survive even when the device floods another protocol."""
    db = await _mkdb(tmp_path)
    mac = "aa:bb:cc:00:00:0d"
    await _add_host(db, mac, "192.168.1.51", vendor="ASUS", category="computer",
                    platform="Windows")
    # Flood tcp_syn far beyond any per-device cap...
    conn = db._conn
    rows = [(mac, "tcp_syn", json.dumps({"ttl": 64}), 0.5,
             f"2026-06-21T00:00:{i % 60:02d}+00:00") for i in range(6000)]
    await conn.executemany(
        "INSERT INTO sightings (hw_addr, source, payload, certainty, timestamp)"
        " VALUES (?,?,?,?,?)", rows)
    # ...plus a single, older WPAD DNS query.
    await conn.execute(
        "INSERT INTO sightings (hw_addr, source, payload, certainty, timestamp)"
        " VALUES (?,?,?,?,?)",
        (mac, "dns", json.dumps({"query_name": "wpad.lan", "query_type": 1}),
         0.9, "2026-06-20T00:00:00+00:00"))
    await conn.commit()
    rep = await analyze_attack_surface(db)
    assert "NR-004" in _by_id(rep["findings"])  # WPAD not truncated by tcp_syn flood
    await db.close()
