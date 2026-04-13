"""
MAC address analysis and device correlation.

Detects locally-administered (randomised) MAC addresses and provides
helpers for correlating randomised MACs back to a device's real
identity using multi-signal scoring.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from leetha.store.database import Database


# Prefixes assigned by hypervisors and container runtimes -- these have
# the locally-administered bit set but are NOT randomised.
_HYPERVISOR_MAC_PREFIXES = (
    "02:42",        # Docker containers
    "02:50:56",     # VMware NSX
    "52:54:00",     # QEMU/KVM
)

# Signal weights for multi-factor identity correlation (higher = rarer signal).
_SIGNAL_WEIGHTS: dict[str, float] = {
    "hostname":   0.35,
    "dhcp_opt60": 0.25,
    "dhcp_opt55": 0.15,
    "tcp_sig":    0.15,
    "mdns_name":  0.10,
}

# Floor score that must be exceeded before two devices are considered
# the same identity (prevents single-signal false positives).
CORRELATION_THRESHOLD = 0.40


# ------------------------------------------------------------------
# Core MAC analysis
# ------------------------------------------------------------------

def detect_randomised_mac(addr: str | None) -> bool:
    """Return True when *addr* is a locally-administered (randomised) MAC.

    The locally-administered bit is bit 1 of the first octet.  Addresses
    assigned by Docker, QEMU/KVM and VMware NSX also carry this bit but
    are **not** randomised and are therefore excluded.

    Accepts colon- or dash-separated hex notation.  Returns False for
    ``None`` or empty strings.
    """
    if not addr:
        return False

    # Normalize to colon-separated uppercase for consistent comparison
    upper = addr.replace("-", ":").upper()

    # Exempt known hypervisor/container prefixes.
    for pfx in _HYPERVISOR_MAC_PREFIXES:
        if upper.startswith(pfx.upper()):
            return False

    first_hex = addr.split(":")[0].split("-")[0]
    if not first_hex:
        return False

    try:
        octet = int(first_hex, 16)
    except ValueError:
        return False

    return (octet & 0x02) != 0

# Backward-compat alias
is_randomized_mac = detect_randomised_mac


# ------------------------------------------------------------------
# Correlation fingerprint construction
# ------------------------------------------------------------------

def extract_correlation_signals(pkt: dict, proto: str) -> dict:
    """Pull identity-relevant signals out of parsed packet data.

    Returns a dict mapping signal names to normalised (lowercased)
    string values.  Only signals actually present in *pkt* appear.
    """
    signals: dict[str, str] = {}

    # Hostname from DHCP / DHCPv6 / mDNS
    hn = pkt.get("hostname") or pkt.get("fqdn")
    if hn:
        signals["hostname"] = hn.lower()

    # DHCP-specific signals
    if proto == "dhcpv4":
        v60 = pkt.get("opt60")
        if v60:
            signals["dhcp_opt60"] = v60
        v55 = pkt.get("opt55")
        if v55:
            signals["dhcp_opt55"] = v55

    # TCP stack fingerprint
    if proto == "tcp_syn":
        ttl_val = pkt.get("ttl")
        win_val = pkt.get("window_size")
        mss_val = pkt.get("mss")
        opts_val = pkt.get("tcp_options", "")
        if ttl_val is not None and win_val is not None:
            mss_str = str(mss_val) if mss_val else "*"
            signals["tcp_sig"] = f"{ttl_val}:{win_val}:{mss_str}:{opts_val}"

    # mDNS instance name
    if proto == "mdns":
        svc_name = pkt.get("name")
        if svc_name:
            signals["mdns_name"] = svc_name.lower()

    return signals

# Backward-compat alias
build_correlation_fingerprint = extract_correlation_signals


# ------------------------------------------------------------------
# Correlation scoring
# ------------------------------------------------------------------

def compute_correlation_score(probe_fp: dict, known_fp: dict) -> float:
    """Score how closely two signal-fingerprints overlap.

    Each shared signal contributes its weight from ``_SIGNAL_WEIGHTS``.
    The result is a float in [0.0, 1.0].
    """
    total = 0.0
    for sig, wt in _SIGNAL_WEIGHTS.items():
        a = probe_fp.get(sig)
        b = known_fp.get(sig)
        if a and b and a == b:
            total += wt
    return total

# Backward-compat alias
score_correlation = compute_correlation_score


# ------------------------------------------------------------------
# Candidate discovery
# ------------------------------------------------------------------

@dataclass
class IdentityCandidate:
    """A device that may share real-world identity with a randomised MAC."""

    real_mac: str
    confidence: float
    reason: str
    hostname: str | None = None

# Backward-compat alias
CorrelationCandidate = IdentityCandidate


async def discover_identity_candidates(
    mac: str,
    hostname: str | None,
    db: "Database",
) -> list[IdentityCandidate]:
    """Search for known devices that likely share identity with *mac*.

    When *hostname* is provided the database is scanned for other
    devices advertising the same hostname (case-insensitive).  Devices
    with a globally-unique OUI MAC receive a higher confidence than
    those that are also locally-administered.

    Returns a list sorted by confidence (descending).
    """
    if not hostname:
        return []

    all_devices = await db.list_devices()
    results: list[IdentityCandidate] = []

    hn_lower = hostname.lower()

    for dev in all_devices:
        if dev.mac == mac:
            continue

        if dev.hostname and dev.hostname.lower() == hn_lower:
            if not detect_randomised_mac(dev.mac):
                conf = 0.92
                why = "Matching hostname with real OUI MAC"
            else:
                conf = 0.85
                why = "Matching hostname with locally-administered MAC"

            results.append(
                IdentityCandidate(
                    real_mac=dev.mac,
                    confidence=conf,
                    reason=why,
                    hostname=dev.hostname,
                )
            )

    results.sort(key=lambda c: c.confidence, reverse=True)
    return results

# Backward-compat alias
find_correlation_candidates = discover_identity_candidates
