"""Netgear + MikroTik classification coverage (follow-up audit).

Pins fixes for gaps left after the WiFi-7 Nighthawk / Orbi work:

  * Netgear Nighthawk M mobile hotspots (M1/M2/M5/M6/MR5200)
  * Netgear RAXE WiFi 6E
  * Netgear WAX business APs that weren't listed explicitly
  * Netgear business Orbi (CBK) and LTE (LM/LAX)
  * MikroTik RB5009, L009, hAP ax, cAP ax, wAP ax, Chateau LTE/5G,
    KNOT, CHR, netPower, and newer CRS/RB models
"""

import re
import pytest


# Netgear coverage

@pytest.mark.parametrize("model_string, expected_type", [
    # Nighthawk M mobile hotspots — cellular routers. Classified as
    # "router" to match the existing ZyXEL LTE/VMG family.
    ("Nighthawk M1",   "router"),
    ("Nighthawk M2",   "router"),
    ("Nighthawk M5",   "router"),
    ("Nighthawk M6",   "router"),
    ("Nighthawk M6 Pro", "router"),
    ("MR5200",         "router"),
    ("MR1100",         "router"),
    ("MR6500",         "router"),
    # Discrete LTE / 5G routers
    ("LM1200",         "router"),
    ("LAX20",          "router"),
    # RAXE (WiFi 6E Nighthawk)
    ("RAXE500",        "router"),
    ("RAXE300",        "router"),
    # Business WAX APs that need explicit callouts
    ("WAX204",         "access_point"),
    ("WAX214",         "access_point"),
    ("WAX630E",        "access_point"),
    ("WAX638E",        "access_point"),
    # Business Orbi (CBK)
    ("CBK40",          "mesh_router"),
    ("CBK752B",        "mesh_router"),
    # Managed switches
    ("XS508M",         "switch"),
    ("XS712T",         "switch"),
    ("GSM4230P",       "switch"),
])
def test_netgear_gap_coverage(model_string, expected_type):
    from leetha.patterns.vendors import NETGEAR_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in NETGEAR_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


# MikroTik coverage

@pytest.mark.parametrize("model_string, expected_type", [
    # RB5009 (flagship 10G) and newer L-series
    ("RB5009UG+S+IN",  "router"),
    ("RB5009",         "router"),
    ("L009UiGS-RM",    "router"),
    ("L009",           "router"),
    # WiFi 6 hAP / cAP / wAP ax variants
    ("hAP ax2",        "router"),
    ("hAP ax3",        "router"),
    ("hAP ax lite",    "router"),
    ("cAP ax",         "access_point"),
    ("wAP ax",         "access_point"),
    # LTE / 5G routers
    ("Chateau LTE12",  "router"),
    ("Chateau LTE18",  "router"),
    ("Chateau 5G ax",  "router"),
    ("Chateau 5G",     "router"),
    ("KNOT LR9",       "router"),
    # Cloud Hosted Router (virtual)
    ("CHR 7.11",       "router"),
    ("CHR",            "router"),
    # Newer CRS switches
    ("CRS106-1C-5S",   "switch"),
    ("CRS610-8P-2S+",  "switch"),
    ("CRS212-1G-10S-1S+IN", "switch"),
    # netPower PoE switches
    ("netPower 16P",   "switch"),
    ("netPower Lite 7R", "switch"),
    # Newer RouterBOARDs
    ("RB760iGS",       "router"),
    ("RB750Gr3",       "router"),
    # Outdoor wireless
    ("LHGG LTE6 kit",  "wireless_bridge"),
    ("DISC Lite5 ac",  "wireless_bridge"),
    ("LDF 5",          "wireless_bridge"),
    # Basic 60G PtP / PtMP
    ("wAP 60G",        "wireless_bridge"),
    ("Cube 60Pro ac",  "wireless_bridge"),
])
def test_mikrotik_gap_coverage(model_string, expected_type):
    from leetha.patterns.vendors import MIKROTIK_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in MIKROTIK_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )
