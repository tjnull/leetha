"""Offline integrity verification engine.

Cross-references device records against cached IEEE OUI data and
RFC constraints.  Every check operates on local data only -- no
network calls are made.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from leetha.store.database import Database

_log = logging.getLogger(__name__)


def _read_oui_db(cache_location: Path) -> dict[str, dict]:
    """Parse the cached IEEE OUI JSON file into a prefix-keyed dictionary."""
    oui_path = cache_location / "ieee_oui.json"
    if not oui_path.is_file():
        _log.warning("OUI cache absent at %s", oui_path)
        return {}

    try:
        with open(oui_path) as fh:
            blob = json.load(fh)
        raw_entries = blob.get("entries", {})
        # Normalise prefixes to uppercase hex without separators
        return {
            pfx.replace(":", "").replace("-", "").upper(): info
            for pfx, info in raw_entries.items()
        }
    except (json.JSONDecodeError, OSError) as err:
        _log.warning("OUI cache load failed: %s", err)
        return {}

# Legacy name
_load_oui_cache = _read_oui_db


def _extract_oui_prefix(mac: str) -> str:
    """Return the 6-char uppercase OUI prefix from a MAC address."""
    return mac.replace(":", "").replace("-", "").upper()[:6]


def _is_locally_administered(mac: str) -> bool:
    """True if the MAC has the locally-administered (U/L) bit set.

    Such addresses (randomized/privacy MACs, many VM/virtual NICs) are never
    registered in the IEEE OUI database by design, so checking them for "OUI
    coverage" or manufacturer agreement always yields a false positive. This
    is derived from the address itself, so it works even when the stored
    ``is_randomized_mac`` flag wasn't populated.
    """
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "")
    try:
        first_octet = int(cleaned[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x02)


def _skip_for_oui(dev) -> bool:
    """Devices to exclude from OUI-based checks (no IEEE registration)."""
    return bool(getattr(dev, "is_randomized_mac", False)) or _is_locally_administered(dev.mac)


def _skip_for_manufacturer(dev) -> bool:
    """Devices to exclude from the OUI-vs-manufacturer agreement check.

    For general-purpose computers the identified "manufacturer" is the OS
    vendor (Microsoft/Apple/Canonical/...), which legitimately differs from
    the NIC's hardware OUI — flagging that would be noise. We reuse the same
    OS-derived vendor/category vocabulary as the spoofing OUI-mismatch rule
    so the two stay consistent. The check then only validates hardware-vendor
    agreement for appliances/IoT, where the brand IS the hardware maker.
    """
    if _skip_for_oui(dev):
        return True
    try:
        from leetha.analysis.spoofing import (
            _OS_DERIVED_VENDORS, _OS_DERIVED_CATEGORIES,
        )
    except Exception:  # pragma: no cover - defensive
        return False
    mfr = (getattr(dev, "manufacturer", "") or "").lower()
    cat = (getattr(dev, "category", "") or "").lower().replace(" ", "_")
    if cat in _OS_DERIVED_CATEGORIES:
        return True
    return any(v in mfr for v in _OS_DERIVED_VENDORS)


async def _load_devices_for_validation(db: Database):
    """Build device records from the live ``hosts`` + ``verdicts`` tables.

    The validator must check the identifications the running pipeline
    actually produces: the vendor/category live in ``verdicts`` and host
    metadata in ``hosts``. The legacy ``devices`` table is no longer
    enriched (manufacturer/category are NULL), so reading it made the
    manufacturer-agreement check silently validate nothing.
    """
    from types import SimpleNamespace

    conn = db._conn
    assert conn is not None
    devices = []
    async with conn.execute(
        "SELECT h.hw_addr, h.mac_randomized, h.last_active, v.vendor, v.category "
        "FROM hosts h LEFT JOIN verdicts v ON v.hw_addr = h.hw_addr"
    ) as cur:
        rows = await cur.fetchall()
    for r in rows:
        last = r["last_active"]
        ls = None
        if isinstance(last, str):
            try:
                ls = datetime.fromisoformat(last)
            except ValueError:
                ls = None
        devices.append(SimpleNamespace(
            mac=r["hw_addr"],
            manufacturer=r["vendor"],
            category=r["category"] if "category" in r.keys() else None,
            is_randomized_mac=bool(r["mac_randomized"]),
            last_seen=ls or datetime.now(timezone.utc),
        ))
    return devices


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

async def check_oui_coverage(db: Database, cache_dir: Path) -> dict:
    """Verify that every device's OUI prefix appears in the IEEE database.

    Devices whose prefix is missing are likely using a randomised MAC
    or belong to an unregistered vendor.
    """
    oui_table = _read_oui_db(cache_dir)
    all_devices = await _load_devices_for_validation(db)

    ok_count = 0
    fail_count = 0
    issues: list[dict] = []

    for dev in all_devices:
        if _skip_for_oui(dev):
            continue

        pfx = _extract_oui_prefix(dev.mac)
        if pfx in oui_table:
            ok_count += 1
        else:
            fail_count += 1
            issues.append({
                "mac": dev.mac,
                "prefix": pfx,
                "reason": "OUI prefix not found in IEEE database",
            })

    return {"passed": ok_count, "failed": fail_count, "details": issues}


# Backward-compat alias
validate_oui_coverage = check_oui_coverage


async def check_manufacturer_agreement(db: Database, cache_dir: Path) -> dict:
    """Compare IEEE OUI manufacturer against the stored device manufacturer.

    Flags records where the two sources disagree (case-insensitive
    substring match is used as the equality test).
    """
    oui_table = _read_oui_db(cache_dir)
    all_devices = await _load_devices_for_validation(db)

    ok_count = 0
    fail_count = 0
    issues: list[dict] = []

    for dev in all_devices:
        if _skip_for_manufacturer(dev) or not dev.manufacturer:
            continue

        pfx = _extract_oui_prefix(dev.mac)
        oui_record = oui_table.get(pfx)

        # The IEEE OUI cache stores the vendor under "vendor" (with
        # "manufacturer" kept only as a legacy fallback).
        oui_mfr = oui_record.get("vendor") or oui_record.get("manufacturer") if oui_record else None
        if not oui_mfr:
            continue

        dev_mfr = dev.manufacturer

        if oui_mfr.lower() in dev_mfr.lower() or dev_mfr.lower() in oui_mfr.lower():
            ok_count += 1
        else:
            fail_count += 1
            issues.append({
                "mac": dev.mac,
                "oui_manufacturer": oui_mfr,
                "device_manufacturer": dev_mfr,
                "reason": "Manufacturer mismatch between OUI and device record",
            })

    return {"passed": ok_count, "failed": fail_count, "details": issues}


# Backward-compat alias
validate_manufacturer_consistency = check_manufacturer_agreement


async def check_stale_devices(db: Database, stale_days: int = 30) -> dict:
    """Identify devices that have not been observed within *stale_days*."""
    all_devices = await _load_devices_for_validation(db)
    threshold = datetime.now(timezone.utc) - timedelta(days=stale_days)

    dormant: list[dict] = []
    for dev in all_devices:
        ls = dev.last_seen
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)
        if ls < threshold:
            dormant.append({
                "mac": dev.mac,
                "last_seen": dev.last_seen.isoformat(),
                "days_ago": (datetime.now(timezone.utc) - ls).days,
            })

    return {"count": len(dormant), "details": dormant}


# Backward-compat alias
validate_stale_devices = check_stale_devices


# ---------------------------------------------------------------------------
# Combined report
# ---------------------------------------------------------------------------

async def execute_all_checks(db: Database, cache_dir: Path, stale_days: int = 30) -> dict:
    """Run every validation check and return a unified report."""
    oui_report = await check_oui_coverage(db, cache_dir)
    mfr_report = await check_manufacturer_agreement(db, cache_dir)
    staleness_report = await check_stale_devices(db, stale_days=stale_days)

    return {
        "timestamp": datetime.now().isoformat(),
        "checks": {
            "oui_coverage": oui_report,
            "manufacturer_consistency": mfr_report,
            "stale_devices": staleness_report,
        },
    }


# Backward-compat alias
run_validation = execute_all_checks
