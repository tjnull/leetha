"""The manufacturer-agreement validator must actually validate live data.

Regression for two bugs that made it silently validate nothing:
  * it read the legacy `devices` table (never enriched by the live pipeline)
    instead of `verdicts`/`hosts`;
  * it looked up the OUI vendor under the key "manufacturer" when the cache
    stores it under "vendor".
It must also reuse the OS-derived skip so a PC (NIC vendor != OS vendor) is
not falsely flagged.
"""

import json
import itertools
import pytest

from leetha.store.database import Database
from leetha.store.store import Store
from leetha.analysis.validator import check_manufacturer_agreement

_c = itertools.count()


async def _mkdb(tmp_path):
    path = tmp_path / f"v_{next(_c)}.db"
    store = Store(path)
    await store.initialize()
    await store.close()
    db = Database(path)
    await db.initialize()
    return db


async def _add(db, mac, vendor=None, category=None, randomized=0):
    await db._conn.execute(
        "INSERT INTO hosts (hw_addr, ip_addr, discovered_at, last_active,"
        " mac_randomized, disposition) VALUES (?,?,?,?,?,'new')",
        (mac, None, "2026-06-22T00:00:00+00:00", "2026-06-22T00:00:00+00:00", randomized),
    )
    if vendor or category:
        await db._conn.execute(
            "INSERT INTO verdicts (hw_addr, vendor, category, certainty, computed_at)"
            " VALUES (?,?,?,?,?)",
            (mac, vendor, category, 90, "2026-06-22T00:00:00+00:00"),
        )
    await db._conn.commit()


def _cache(tmp_path):
    cd = tmp_path / "cache"
    cd.mkdir(exist_ok=True)
    (cd / "ieee_oui.json").write_text(json.dumps({"entries": {
        "00:24:E4": {"vendor": "Withings"},
        "AC:BB:CC": {"vendor": "Acme Corp"},
        "11:22:33": {"vendor": "Ubiquiti Inc"},
    }}), encoding="utf-8")
    return cd


async def test_genuine_vendor_mismatch_is_flagged(tmp_path):
    db = await _mkdb(tmp_path)
    # Verdict vendor disagrees with the authoritative OUI vendor.
    await _add(db, "00:24:e4:11:22:33", vendor="EyeFi, Inc.", category="health_device")
    rep = await check_manufacturer_agreement(db, _cache(tmp_path))
    macs = [d["mac"] for d in rep["details"]]
    assert "00:24:e4:11:22:33" in macs
    assert rep["failed"] == 1
    await db.close()


async def test_agreeing_vendor_passes(tmp_path):
    db = await _mkdb(tmp_path)
    await _add(db, "11:22:33:44:55:66", vendor="Ubiquiti", category="switch")
    rep = await check_manufacturer_agreement(db, _cache(tmp_path))
    assert rep["passed"] == 1 and rep["failed"] == 0
    await db.close()


async def test_os_vendor_computer_not_flagged(tmp_path):
    # NIC OUI (Acme) != OS vendor (Microsoft) is expected for a PC — skip it.
    db = await _mkdb(tmp_path)
    await _add(db, "ac:bb:cc:00:00:01", vendor="Microsoft", category="workstation")
    rep = await check_manufacturer_agreement(db, _cache(tmp_path))
    assert rep["failed"] == 0
    await db.close()


async def test_reads_verdicts_not_empty_devices_table(tmp_path):
    # The device exists only in hosts+verdicts (the live pipeline never
    # populates the legacy devices table) — it must still be evaluated.
    db = await _mkdb(tmp_path)
    await _add(db, "ac:bb:cc:99:99:99", vendor="Acme Corp", category="printer")
    rep = await check_manufacturer_agreement(db, _cache(tmp_path))
    assert rep["passed"] == 1  # would be 0 if it read the empty devices table
    await db.close()
