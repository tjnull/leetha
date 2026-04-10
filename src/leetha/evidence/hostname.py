"""Hostname validation – rejects UUIDs, hex strings, IPs, and external FQDNs."""

from __future__ import annotations

import ipaddress
import re

# 8-4-4-4-12 hex (standard UUID) or 8-4-4-4 (truncated UUID)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}(-[0-9a-f]{12})?$",
    re.IGNORECASE,
)

# Pure hex string, 8+ characters
_PURE_HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)

# Firmware/SDK default: short prefix + separator + MAC-derived hex
# e.g. ESDK_7893c366477c, ESP_32AB12, Tasmota-AABB11223344
_SDK_DEFAULT_RE = re.compile(
    r"^[A-Za-z]{1,10}[-_][0-9a-f]{8,12}$", re.IGNORECASE,
)

# Known firmware/SDK prefixes that produce auto-generated hostnames.
# These are never human-assigned names worth keeping.
_SDK_PREFIXES = frozenset({
    "esdk", "esp", "tasmota", "shelly", "tuya", "beken",
    "ewelink", "sonoff", "hap", "ble", "wlan", "wifi",
    "smartlife", "tplink", "kasa", "deco", "meross",
})

# Known public TLDs (common ones – enough to catch the obvious external names)
_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "io", "co", "uk", "de", "fr",
    "jp", "cn", "ru", "br", "au", "in", "ca", "us", "eu", "info", "biz",
    "me", "tv", "cc", "ws", "app", "dev", "cloud", "xyz",
})


def _is_hex_segment(s: str) -> bool:
    """Return True if *s* is a non-empty string of hex digits."""
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s)


def is_valid_hostname(name: str | None) -> bool:
    """Return True when *name* looks like a human-assigned hostname.

    Returns False for None / empty / whitespace, UUIDs, hex blobs, IPs,
    IPv6 addresses, and external FQDNs.
    """
    if name is None:
        return False
    name = name.strip()
    if not name:
        return False

    # --- IPv4 / IPv6 ---------------------------------------------------------
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        pass

    # --- External FQDN (2+ dots, last label is a known TLD) -----------------
    if "." in name:
        parts = name.split(".")
        if len(parts) >= 3 and parts[-1].lower() in _TLDS:
            return False

    # --- Full UUID (8-4-4-4-12 or 8-4-4-4) ----------------------------------
    if _UUID_RE.match(name):
        return False

    # --- Dash-separated segments analysis ------------------------------------
    if "-" in name:
        segments = name.split("-")

        # All segments are pure hex → reject  (e.g. f80f-f9c5-49d2)
        if all(_is_hex_segment(seg) for seg in segments):
            return False

        # "word-hex-hex-hex…" pattern: if 3+ trailing segments are all hex,
        # it's likely a UUID-derivative (e.g. fuchsia-f80f-f9c5-49d2).
        if len(segments) >= 4:
            trailing_hex = 0
            for seg in reversed(segments):
                if _is_hex_segment(seg):
                    trailing_hex += 1
                else:
                    break
            if trailing_hex >= 3:
                return False

    # --- Pure hex blob (8+ chars, no dashes) ---------------------------------
    if _PURE_HEX_RE.match(name):
        return False

    # --- Firmware/SDK default: short prefix + MAC hex -----------------------
    # e.g. ESDK_7893c366477c, ESP-32AB12CD, Tasmota-AABB11223344
    if _SDK_DEFAULT_RE.match(name):
        return False

    # Known SDK prefixes with any separator
    name_lower = name.lower()
    for pfx in _SDK_PREFIXES:
        if name_lower.startswith(pfx) and len(name) > len(pfx) + 1:
            suffix = name[len(pfx) + 1:]  # skip the separator char
            if _is_hex_segment(suffix) and len(suffix) >= 6:
                return False

    return True


# Hostname keywords that belong to a specific vendor.  If the device's
# resolved vendor doesn't match, the hostname is from a forwarded mDNS
# packet and should be stripped.
_HOSTNAME_VENDOR_KEYWORDS: dict[str, set[str]] = {
    "lutron": {"Lutron"},
    "hue": {"Philips", "Signify"},
    "sonos": {"Sonos"},
    "roku": {"Roku"},
    "nest": {"Google"},
    "echo": {"Amazon"},
    "alexa": {"Amazon"},
    "homepod": {"Apple"},
    "chromecast": {"Google"},
    "firestick": {"Amazon"},
    "ring": {"Amazon", "Ring"},
    "roborock": {"Roborock"},
    "roomba": {"iRobot"},
    "ecobee": {"ecobee"},
    "dyson": {"Dyson"},
}


def hostname_matches_vendor(hostname: str | None, vendor: str | None) -> bool:
    """Return True if the hostname is coherent with the vendor.

    Returns True when:
    - hostname is None/empty (nothing to reject)
    - vendor is None/empty (can't verify, assume OK)
    - hostname contains no vendor-specific keywords
    - hostname keyword matches the device vendor

    Returns False when a keyword in the hostname belongs to a
    DIFFERENT vendor than the device (forwarded mDNS).
    """
    if not hostname or not vendor:
        return True
    hn_lower = hostname.lower()
    for keyword, legit_vendors in _HOSTNAME_VENDOR_KEYWORDS.items():
        if keyword in hn_lower:
            if not any(v.lower() in vendor.lower() or vendor.lower() in v.lower()
                       for v in legit_vendors):
                return False
    return True
