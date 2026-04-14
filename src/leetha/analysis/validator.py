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


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

async def check_oui_coverage(db: Database, cache_dir: Path) -> dict:
    """Verify that every device's OUI prefix appears in the IEEE database.

    Devices whose prefix is missing are likely using a randomised MAC
    or belong to an unregistered vendor.
    """
    oui_table = _read_oui_db(cache_dir)
    all_devices = await db.list_devices()

    ok_count = 0
    fail_count = 0
    issues: list[dict] = []

    for dev in all_devices:
        if dev.is_randomized_mac:
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
    all_devices = await db.list_devices()

    ok_count = 0
    fail_count = 0
    issues: list[dict] = []

    for dev in all_devices:
        if dev.is_randomized_mac or not dev.manufacturer:
            continue

        pfx = _extract_oui_prefix(dev.mac)
        oui_record = oui_table.get(pfx)

        if not oui_record or not oui_record.get("manufacturer"):
            continue

        oui_mfr = oui_record["manufacturer"]
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
    all_devices = await db.list_devices()
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
