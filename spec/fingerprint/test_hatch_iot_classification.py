"""Hatch Baby IoT device classification coverage.

Real-world bug: a Hatch Rest 2nd Generation baby sound machine /
nightlight showed up as a MikroTik router in the topology (complete
with "GATEWAY" badge and router icon). The Hatch Rest line reports a
hostname like ``Rest2ndGen-252E42`` where the suffix is the last six
MAC nibbles. Leetha's vendor-inference picked up ``MikroTik`` (a
misattributed OUI), which the topology classifier then promoted to
``router`` via the ``mikrotik → router`` vendor-hint rule. With the
original router (AmpliFi) temporarily misclassified due to reflected
mDNS, the Hatch inherited the "inferred gateway" role.

Pin the correct classification so hostname wins over a misattributed
vendor:
  * ``Rest2ndGen-xxxxxx``       → iot_device
  * ``Hatch-Rest-xxxxxx``       → iot_device
  * ``hatch-rest-xxxxxx``       → iot_device
  * ``restplus-xxxxxx``         → iot_device (Hatch Rest+)
  * ``hatch-restore-xxxxxx``    → iot_device (Hatch Restore)
"""

import pytest


@pytest.mark.parametrize("hostname, expected", [
    # Hatch Rest 2nd Gen
    ("Rest2ndGen-252E42", "iot_device"),
    ("rest2ndgen-abc123", "iot_device"),
    # Hatch Rest variants
    ("Hatch-Rest-abcdef", "iot_device"),
    ("hatch-rest-2ndgen", "iot_device"),
    ("HatchRest-nursery", "iot_device"),
    # Hatch Rest+ (has extra sensors)
    ("RestPlus-aabbcc", "iot_device"),
    ("rest-plus-baby", "iot_device"),
    # Hatch Restore (adult sleep device)
    ("HatchRestore-112233", "iot_device"),
    ("hatch-restore-bedroom", "iot_device"),
    # Hatch Rest Mini
    ("RestMini-nightlight", "iot_device"),
    ("hatch-rest-mini", "iot_device"),
    # Generic Hatch branding fallback
    ("hatch-baby-01", "iot_device"),
])
def test_hatch_hostname_classification(hostname, expected):
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


def test_hatch_hostname_beats_mikrotik_vendor_misattribution():
    """If the OUI cache misattributes Hatch's MAC to MikroTik, the
    router-refinement pass must still correctly classify it as an IoT
    device via the hostname hint. Without this, the ``mikrotik →
    router`` vendor rule would make a noise machine look like a router
    and eligible for inferred-gateway promotion."""
    from leetha.topology import _refine_type_from_context
    # Starting state: vendor inference already mapped us to "router"
    # because the OUI cache said "MikroTik".
    starting_type = "router"
    hostname = "Rest2ndGen-252E42"
    # With no Hatch hostname hint, the refiner would leave device_type
    # unchanged as "router". With the hint present, hostname patterns
    # run first and demote to iot_device.
    refined = _refine_type_from_context(starting_type, hostname, [])
    assert refined == "iot_device", (
        f"Hatch hostname must override misattributed router type, got {refined!r}"
    )


def test_vendor_manufacturer_keyword_hatch_maps_to_iot():
    """If any future OUI data correctly attributes a Hatch device, the
    vendor-keyword dict should classify it as an IoT device, not a
    router or generic ``unknown``."""
    from leetha.topology import _VENDOR_DEVICE_TYPE_HINTS
    found = None
    for pattern, kind in _VENDOR_DEVICE_TYPE_HINTS.items():
        if pattern in "hatch baby":
            found = kind
            break
    assert found == "iot_device", (
        f"'hatch' vendor keyword should map to iot_device, got {found!r}"
    )
