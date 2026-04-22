"""Ubiquiti AmpliFi line classification.

The Alien (and Gamer/Teleport) are proper routers, not mesh nodes. HD
and Instant are mesh routers. Mesh Point pucks are APs.
"""

import re
import pytest


@pytest.mark.parametrize("hostname, expected", [
    # Alien — flagship router
    ("amplifi-alien-kitchen", "router"),
    ("AFi-Alien-A1B2C3", "router"),
    ("afi-alien.local", "router"),
    # Gamer — router variant
    ("afi-gamer-01", "router"),
    ("amplifi-gamer", "router"),
    # Teleport — VPN router
    ("afi-teleport-hq", "router"),
    ("amplifi-teleport", "router"),
    # HD / Instant — mesh family
    ("amplifi-hd-living-room", "mesh_router"),
    ("afi-r-hd", "mesh_router"),
    ("amplifi-instant-01", "mesh_router"),
    # MeshPoint pucks — APs
    ("afi-p-hd-bedroom", "access_point"),
    # Generic AmpliFi — mesh fallback
    ("amplifi-home", "mesh_router"),
])
def test_hostname_classification_for_amplifi_line(hostname, expected):
    from leetha.topology import _HOSTNAME_DEVICE_HINTS
    hn_lower = hostname.lower()
    inferred = None
    for pattern, kind in _HOSTNAME_DEVICE_HINTS:
        if pattern in hn_lower:
            inferred = kind
            break
    assert inferred == expected, (
        f"hostname {hostname!r} classified as {inferred!r}, expected {expected!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    ("AFi-Alien",     "router"),
    ("AFi-ALN-R",     "router"),
    ("AmpliFi Alien", "router"),
    ("AmpliFi-ALN-R", "router"),
    ("AFi-G",         "router"),          # Gamer
    ("AmpliFi Gamer", "router"),
    ("AFi-Teleport",  "router"),
    ("AFi-R-HD",      "mesh_router"),
    ("AmpliFi HD Router", "mesh_router"),
    ("AFi-Instant",   "mesh_router"),
    ("AFi-P-HD",      "access_point"),    # MeshPoint HD
    ("AmpliFi",       "mesh_router"),      # generic fallback
])
def test_vendor_pattern_classification_for_amplifi_models(model_string, expected_type):
    from leetha.patterns.vendors import UBIQUITI_BANNER_PATTERNS as UBIQUITI_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in UBIQUITI_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"model {model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


def test_alien_does_not_match_alienware_workstation_rule():
    """Regression pin: the Dell Alienware vendor rule is keyed on
    'alienware' (full word) and must not swallow AmpliFi Alien hosts.
    """
    from leetha.topology import _VENDOR_DEVICE_TYPE_HINTS
    assert "alienware" in _VENDOR_DEVICE_TYPE_HINTS
    # Simulate the matcher: manufacturer would be "Ubiquiti" (the OUI
    # vendor) or "AmpliFi" — neither contains "alienware".
    for mfr in ("Ubiquiti", "Ubiquiti Networks", "AmpliFi", "ubnt"):
        mfr_lower = mfr.lower()
        for vendor_pattern, inferred_type in _VENDOR_DEVICE_TYPE_HINTS.items():
            if vendor_pattern in mfr_lower:
                assert inferred_type != "workstation", (
                    f"manufacturer {mfr!r} matched {vendor_pattern!r} → workstation"
                )
