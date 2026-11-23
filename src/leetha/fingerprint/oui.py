"""MAC assignment matching and interpretation shared by lookup and validation."""

import re

PREFIX_LENGTHS = (9, 8, 7, 6, 4)
REGISTRY_PLACEHOLDER = "IEEE Registration Authority"
_MAC_RE = re.compile(r"[0-9A-F]{12}")


def is_registry_placeholder(vendor: str | None) -> bool:
    return bool(vendor and vendor.strip().casefold() == REGISTRY_PLACEHOLDER.casefold())


def compact_prefix(value: str) -> str:
    return value.replace(":", "").replace("-", "").replace(".", "").upper()


def match_assignment(mac: str, table: dict) -> tuple[str, dict] | None:
    address = compact_prefix(mac)
    if not _MAC_RE.fullmatch(address) or address == "0" * 12 or int(address[:2], 16) & 1:
        return None
    for size in PREFIX_LENGTHS:
        prefix = address[:size]
        if prefix in table:
            return prefix, table[prefix]
    return None


def is_current_assignment(record: dict) -> bool:
    """An explicit historical status cannot establish current ownership."""
    status = record.get("registration_status", record.get("status"))
    sources = record.get("sources")
    if isinstance(sources, str):
        sources = sources.split("+")
    return (
        status in (None, "", "current")
        and record.get("registry") != "CID"
        and (not sources or "IEEE" in sources)
    )


def matches_registrant(value: str, manufacturer: str, record: dict) -> bool:
    """Match the canonical name, literal registry name, or a former registrant."""
    value = value.strip().casefold()
    if not value:
        return False
    vendor = manufacturer.strip().casefold()
    if vendor and (value in vendor or vendor in value):
        return True
    aliases = (record.get("registrant_history") or "").split("|")
    aliases.append(record.get("registrant_raw") or "")
    return any(
        alias.strip().casefold() == value and value not in {"private", "unknown"}
        for alias in aliases
    )
