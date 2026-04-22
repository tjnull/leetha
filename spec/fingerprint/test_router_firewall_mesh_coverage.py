"""Router / firewall / mesh classification coverage.

Follows the shape of ``test_amplifi_classification.py``: each case asserts
either (a) a hostname substring in ``_HOSTNAME_DEVICE_HINTS`` maps to the
expected device type, or (b) a vendor banner pattern in one of the
``*_BANNER_PATTERNS`` lists classifies to the expected ``device_type``.

This file pins regressions for:
  * Mesh systems previously misclassified as plain "router"
    (Linksys Velop, D-Link COVR, ASUS ZenWiFi/AiMesh, Google Nest Wifi).
  * Vendors that had no coverage at all (Plume, Vilo, Firewalla,
    Turris, GL.iNet, Cudy, Tenda, Mercusys, VyOS, Untangle, Xiaomi).
  * Model lines that existed generically but needed finer grain
    (Netgear Nighthawk RS / CAX, ASUS ROG Rapture GT-AX/BE, ASUS RT-BE,
    Synology MR2200ac, QNAP QHora).
"""

import re
import pytest


# Hostname classifications (via _HOSTNAME_DEVICE_HINTS)

@pytest.mark.parametrize("hostname, expected", [
    # --- Mesh routers (previously missing / misclassified) ---
    ("plume-superpod-kitchen", "mesh_router"),
    ("superpod-living", "mesh_router"),
    ("vilo-mesh-01", "mesh_router"),
    ("zenwifi-xt8-office", "mesh_router"),
    ("covr-2202-living", "mesh_router"),
    ("rbk-orbi-hall", "mesh_router"),      # Netgear Orbi kit hostname
    ("rbr750-main", "mesh_router"),         # Orbi router node
    ("rbs750-satellite", "mesh_router"),    # Orbi satellite
    ("mr2200ac-bedroom", "mesh_router"),    # Synology mesh router

    # --- Consumer routers (new vendors) ---
    ("turris-omnia", "router"),
    ("turris-mox", "router"),
    ("glinet-mt3000", "router"),
    ("gl-mt3000-hotel", "router"),
    ("gl-ar750s-travel", "router"),
    ("rt-be96u-study", "router"),           # ASUS WiFi 7 router
    ("gt-be98-rog", "router"),              # ROG Rapture WiFi 7
    ("gt-ax6000-gaming", "router"),         # ROG Rapture WiFi 6
    ("tuf-ax5400-office", "router"),
    ("qhora-301w-qnap", "router"),          # QNAP QHora router
    ("cudy-ax3000", "router"),
    ("tenda-ax12", "router"),
    ("mercusys-mr90x", "router"),

    # --- Firewalls (new vendors / models) ---
    ("firewalla-gold", "firewall"),
    ("firewalla-purple", "firewall"),
    ("firebox-t40-edge", "firewall"),       # WatchGuard Firebox
    ("vyos-edge", "firewall"),
    ("untangle-gw", "firewall"),
])
def test_hostname_classification(hostname, expected):
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


# Vendor-keyword classifications (via _VENDOR_DEVICE_TYPE_HINTS)

@pytest.mark.parametrize("manufacturer, expected", [
    ("Plume Design", "mesh_router"),
    ("Vilo Living", "mesh_router"),
    ("Turris", "router"),
    ("CZ.NIC (Turris)", "router"),
    ("GL Technologies", "router"),       # GL.iNet manufacturer string
    ("Firewalla Inc.", "firewall"),
    ("VyOS", "firewall"),
    ("Untangle", "firewall"),
    ("Tenda Technology", "router"),
    ("Shenzhen Mercusys Technologies", "router"),
    ("Cudy Technologies", "router"),
])
def test_vendor_keyword_classification(manufacturer, expected):
    from leetha.topology import _VENDOR_DEVICE_TYPE_HINTS
    mfr_lower = manufacturer.lower()
    inferred = None
    for vendor_pattern, kind in _VENDOR_DEVICE_TYPE_HINTS.items():
        if vendor_pattern in mfr_lower:
            inferred = kind
            break
    assert inferred == expected, (
        f"manufacturer {manufacturer!r} classified as {inferred!r}, expected {expected!r}"
    )


# Banner-pattern misclassification fixes

@pytest.mark.parametrize("model_string, expected_type", [
    # Linksys Velop IS a mesh system, not a plain router
    ("Velop MX10600", "mesh_router"),
    ("Velop MBE7000", "mesh_router"),
    ("Linksys Velop",  "mesh_router"),
])
def test_linksys_velop_is_mesh(model_string, expected_type):
    from leetha.patterns.vendors import LINKSYS_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in LINKSYS_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    ("COVR-2202", "mesh_router"),
    ("COVR-X1870", "mesh_router"),
    ("COVR-1103", "mesh_router"),
])
def test_dlink_covr_is_mesh(model_string, expected_type):
    from leetha.patterns.vendors import DLINK_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in DLINK_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    # ZenWiFi and AiMesh are mesh systems
    ("ZenWiFi XT8", "mesh_router"),
    ("ZenWiFi Pro XT12", "mesh_router"),
    ("ZenWiFi BT10", "mesh_router"),
    ("AiMesh AX6100", "mesh_router"),
    # RT-AX / RT-AC / RT-BE are routers (including WiFi 7 RT-BE)
    ("RT-AX88U", "router"),
    ("RT-AC86U", "router"),
    ("RT-BE96U", "router"),
    # ROG Rapture GT-series are routers (gaming)
    ("GT-AX11000", "router"),
    ("GT-BE98 Pro", "router"),
    ("GT-AXE16000", "router"),
    # TUF Gaming routers
    ("TUF-AX5400", "router"),
    ("TUF-AX6000", "router"),
])
def test_asus_router_family_classification(model_string, expected_type):
    from leetha.patterns.vendors import ASUS_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in ASUS_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    ("Nest Wifi Pro",    "mesh_router"),
    ("Nest Wifi",        "mesh_router"),
    ("Google Wifi",      "mesh_router"),
])
def test_google_nest_wifi_is_mesh(model_string, expected_type):
    from leetha.patterns.vendors import GOOGLE_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in GOOGLE_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


# New vendor pattern tables

@pytest.mark.parametrize("model_string, expected_type", [
    ("SuperPod",             "mesh_router"),
    ("Plume SuperPod",       "mesh_router"),
    ("Plume Pod",            "mesh_router"),
])
def test_plume_classification(model_string, expected_type):
    from leetha.patterns.vendors import PLUME_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in PLUME_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    ("Firewalla Gold",        "firewall"),
    ("Firewalla Gold SE",     "firewall"),
    ("Firewalla Gold Plus",   "firewall"),
    ("Firewalla Purple",      "firewall"),
    ("Firewalla Purple SE",   "firewall"),
    ("Firewalla Blue Plus",   "firewall"),
    ("Firewalla Red",         "firewall"),
])
def test_firewalla_classification(model_string, expected_type):
    from leetha.patterns.vendors import FIREWALLA_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in FIREWALLA_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    ("VyOS 1.4",      "firewall"),
    ("VyOS rolling",  "firewall"),
    ("Untangle NG Firewall", "firewall"),
    ("Untangle 17",   "firewall"),
])
def test_open_source_firewall_classification(model_string, expected_type):
    from leetha.patterns.vendors import (
        VYOS_BANNER_PATTERNS,
        UNTANGLE_BANNER_PATTERNS,
    )
    matched = None
    for table in (VYOS_BANNER_PATTERNS, UNTANGLE_BANNER_PATTERNS):
        for pattern, _name, device_type, _os in table:
            if re.search(pattern, model_string, re.IGNORECASE):
                matched = device_type
                break
        if matched:
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    # Synology Mesh router (MR2200ac)
    ("MR2200ac",  "mesh_router"),
    # Synology routers (non-mesh)
    ("RT2600ac",  "router"),
    ("RT6600ax",  "router"),
    ("WRX560",    "router"),
])
def test_synology_router_vs_mesh(model_string, expected_type):
    from leetha.patterns.vendors import SYNOLOGY_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in SYNOLOGY_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    # QNAP QHora = enterprise-ish router (SD-WAN), NOT a NAS
    ("QHora-301W", "router"),
    ("QHora-322",  "router"),
])
def test_qnap_qhora_is_router(model_string, expected_type):
    from leetha.patterns.vendors import QNAP_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in QNAP_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("model_string, expected_type", [
    # Netgear Nighthawk WiFi 7 (RS series)
    ("RS700S",       "router"),
    ("RS600",        "router"),
    ("Nighthawk RS300", "router"),
    # Netgear Nighthawk Pro Gaming (XR series)
    ("XR1000",       "router"),
    ("XR500",        "router"),
    ("XR700",        "router"),
    # Netgear cable gateway
    ("CAX80",        "router"),
    ("CAX30",        "router"),
    ("CAX700",       "router"),
    # Netgear Orbi WiFi 7 (RBE series kits)
    ("RBE970",       "mesh_router"),
    ("RBE973",       "mesh_router"),
    # Netgear Orbi satellites keep their range_extender type
    ("RBS860",       "range_extender"),
])
def test_netgear_extended_models(model_string, expected_type):
    from leetha.patterns.vendors import NETGEAR_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in NETGEAR_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )
