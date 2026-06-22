"""DTP/STP Layer-2 detections must be grounded in real captured frames.

Covers:
  * DTP parser maps the trunk-negotiation status byte to a mode;
  * L2-007 fires HIGH on a live negotiating DTP frame (switch-spoofing
    exposure);
  * L2-009 is INFO for a single stable STP root but HIGH when multiple
    distinct roots are advertised (superior-BPDU root takeover);
  * L2-010 states the vantage limitation when no STP/DTP/CDP is visible
    (likely an access port) and is suppressed once any is seen.
"""

import json
import itertools
import pytest

import scapy.all as s
from scapy.layers.l2 import Dot3, LLC
from scapy.contrib.dtp import DTP, DTPStatus, DTPType, DTPDomain, DTPNeighbor

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.analysis.attack_surface import analyze_attack_surface
from leetha.capture.parsers.dtp import parse_dtp as raw_parse_dtp

_c = itertools.count()


# ---- DTP parser unit tests --------------------------------------------------

def _dtp_frame(status_byte):
    return Dot3(dst="01:00:0c:cc:cc:cc", src="aa:bb:cc:dd:ee:ff") / LLC() / \
        s.SNAP(OUI=0x0c, code=0x2004) / DTP(tlvlist=[
            DTPDomain(), DTPStatus(status=bytes([status_byte])),
            DTPType(), DTPNeighbor(neighbor="aa:bb:cc:dd:ee:ff")])


@pytest.mark.parametrize("byte,mode,negotiating", [
    (0x03, "dynamic_desirable", True),
    (0x04, "dynamic_auto", True),
    (0x81, "trunk", True),
    (0x02, "off", False),
])
def test_dtp_parser_maps_modes(byte, mode, negotiating):
    res = raw_parse_dtp(Dot3(bytes(_dtp_frame(byte))))
    assert res is not None
    assert res["mode"] == mode
    assert res["negotiating"] is negotiating


# ---- detection (DB-backed) --------------------------------------------------

async def _mkdb(tmp_path):
    path = tmp_path / f"l2_{next(_c)}.db"
    store = Store(path); await store.initialize(); await store.close()
    db = Database(path); await db.initialize()
    return db


async def _host(db, mac, category=None):
    await db._conn.execute(
        "INSERT INTO hosts (hw_addr, ip_addr, discovered_at, last_active,"
        " mac_randomized, disposition) VALUES (?,?,?,?,0,'new')",
        (mac, None, "2026-06-22T00:00:00+00:00", "2026-06-22T00:00:00+00:00"))
    if category:
        await db._conn.execute(
            "INSERT INTO verdicts (hw_addr, category, certainty, computed_at)"
            " VALUES (?,?,?,?)", (mac, category, 90, "2026-06-22T00:00:00+00:00"))
    await db._conn.commit()


async def _sight(db, mac, source, payload):
    await db._conn.execute(
        "INSERT INTO sightings (hw_addr, source, payload, certainty, timestamp)"
        " VALUES (?,?,?,?,?)",
        (mac, source, json.dumps(payload), 0.9, "2026-06-22T00:00:00+00:00"))
    await db._conn.commit()


def _by_id(rep):
    return {f["rule_id"]: f for f in rep["findings"]}


async def test_negotiating_dtp_fires_l2007_high(tmp_path):
    db = await _mkdb(tmp_path)
    await _host(db, "aa:bb:cc:00:00:01", category="switch")
    await _sight(db, "aa:bb:cc:00:00:01", "dtp",
                 {"mode": "dynamic_desirable", "negotiating": True})
    fb = _by_id(await analyze_attack_surface(db))
    assert "L2-007" in fb and fb["L2-007"]["severity"] == "high"
    await db.close()


async def test_single_stp_root_is_info(tmp_path):
    db = await _mkdb(tmp_path)
    await _host(db, "aa:bb:cc:00:00:02", category="switch")
    await _sight(db, "aa:bb:cc:00:00:02", "stp",
                 {"root_mac": "00:11:22:33:44:55", "root_priority": 4096})
    fb = _by_id(await analyze_attack_surface(db))
    assert fb["L2-009"]["severity"] == "info"
    await db.close()


async def test_multiple_stp_roots_fire_high(tmp_path):
    db = await _mkdb(tmp_path)
    await _host(db, "aa:bb:cc:00:00:03", category="switch")
    await _sight(db, "aa:bb:cc:00:00:03", "stp",
                 {"root_mac": "00:11:22:33:44:55", "root_priority": 32768})
    await _sight(db, "aa:bb:cc:00:00:03", "stp",
                 {"root_mac": "66:77:88:99:aa:bb", "root_priority": 0})
    fb = _by_id(await analyze_attack_surface(db))
    assert fb["L2-009"]["severity"] == "high"
    await db.close()


async def test_no_l2_visibility_note_when_blind(tmp_path):
    db = await _mkdb(tmp_path)
    await _host(db, "aa:bb:cc:00:00:04", category="phone")
    await _sight(db, "aa:bb:cc:00:00:04", "mdns", {"service_type": "_airplay._tcp"})
    fb = _by_id(await analyze_attack_surface(db))
    assert "L2-010" in fb           # vantage note present
    assert "L2-007" not in fb and "L2-009" not in fb
    await db.close()


async def test_l2_visibility_note_suppressed_when_stp_seen(tmp_path):
    db = await _mkdb(tmp_path)
    await _host(db, "aa:bb:cc:00:00:05", category="switch")
    await _sight(db, "aa:bb:cc:00:00:05", "stp",
                 {"root_mac": "00:11:22:33:44:55", "root_priority": 4096})
    fb = _by_id(await analyze_attack_surface(db))
    assert "L2-010" not in fb       # we can see the L2 control plane
    await db.close()
