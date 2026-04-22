"""mDNS exclusive-service reflection guard.

Reproduces a real-world bug: a Ubiquiti AmpliFi mesh router was
misclassified as a Google smart_speaker with 100% certainty because the
router reflects mDNS traffic across its VLANs. When the Chromecast
announcement is rebroadcast, the Ethernet source MAC is the router's
locally-administered virtual MAC — so leetha attributed the ``Cast OS``
identity to the router.

Fix invariant: physical-device-only exclusive services
(``_googlecast._tcp``, ``_roku-rsp._tcp``, ``_sonos._tcp``, etc.) must
drop category / platform and lower certainty when the packet's source
MAC is locally-administered. Real Chromecasts / Rokus / Sonos speakers
/ Samsung & LG TVs ship with real vendor OUIs — they don't randomize.

Apple services (``_airplay``, ``_raop``, ``_companion-link``,
``_homekit``, ``_apple-mobdev*``) are NOT physical-device-only:
iPhones advertise them too and iOS randomizes per-SSID, so these must
stay trusted when the source MAC is locally-administered.
"""

import pytest

from leetha.processors.names import NameResolutionProcessor
from leetha.capture.packets import CapturedPacket


# The `d2:` first byte has bit 0x02 set → locally-administered.
RANDOMIZED_MAC = "d2:21:f9:78:d4:08"

# A real Google OUI (FA:8F:CA is Google Chromecast).
REAL_GOOGLE_MAC = "fa:8f:ca:11:22:33"


@pytest.mark.parametrize("service", [
    "_googlecast._tcp",
    "_googlerpc._tcp",
    "_googlehomedevice._tcp",
    "_amzn-wplay._tcp",
    "_samsungtvrc._tcp",
    "_samsung-msn._tcp",
    "_roku-rsp._tcp",
    "_sonos._tcp",
    "_lgtvremote._tcp",
])
def test_physical_only_service_from_random_mac_drops_category_and_platform(service):
    """Random MAC + physical-device service ⇒ reflected traffic."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=RANDOMIZED_MAC, ip_addr="192.168.1.1",
        fields={"service_type": service, "name": f"Foo.{service}.local"},
    )
    result = proc.analyze(pkt)
    exclusive = [e for e in result if e.source == "mdns_exclusive"]
    assert exclusive, "expected an mdns_exclusive Evidence record"
    e = exclusive[0]
    # Category and platform must be stripped so the router doesn't
    # inherit a Chromecast/Roku/etc. classification.
    assert e.category is None, f"{service}: category should be stripped on reflected traffic, got {e.category!r}"
    assert e.platform is None, f"{service}: platform should be stripped on reflected traffic, got {e.platform!r}"
    # Certainty should be downgraded
    assert e.certainty <= 0.50, f"{service}: certainty should drop to ≤0.50 on reflected traffic, got {e.certainty}"
    # Should be marked as cross_device so the fusion layer knows
    assert e.raw.get("cross_device") is True, f"{service}: expected cross_device=True in raw, got {e.raw!r}"


@pytest.mark.parametrize("service", [
    "_googlecast._tcp",
    "_roku-rsp._tcp",
    "_sonos._tcp",
])
def test_physical_only_service_from_real_oui_keeps_full_evidence(service):
    """Real vendor-OUI MAC + physical-device service ⇒ full evidence."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=REAL_GOOGLE_MAC, ip_addr="192.168.1.50",
        fields={"service_type": service, "name": f"Foo.{service}.local"},
    )
    result = proc.analyze(pkt)
    exclusive = [e for e in result if e.source == "mdns_exclusive"]
    assert exclusive
    e = exclusive[0]
    assert e.vendor is not None
    # Category/platform depend on service, but at minimum the vendor
    # should be present and certainty should match the dict entry.
    assert e.certainty >= 0.85, f"real-OUI match should stay high-certainty, got {e.certainty}"
    assert e.raw.get("cross_device") is False


@pytest.mark.parametrize("service", [
    "_airplay._tcp",
    "_raop._tcp",
    "_companion-link._tcp",
    "_homekit._tcp",
    "_apple-mobdev2._tcp",
])
def test_apple_service_from_random_mac_stays_trusted(service):
    """iPhones randomize MACs per SSID, so Apple services are fine."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=RANDOMIZED_MAC, ip_addr="192.168.1.60",
        # Use a plain name — no hex_id@friendly_name prefix, so the
        # AirPlay cross-device check can't fire for a different reason.
        fields={"service_type": service, "name": f"iPhone.{service}.local"},
    )
    result = proc.analyze(pkt)
    exclusive = [e for e in result if e.source == "mdns_exclusive"]
    assert exclusive, f"expected mdns_exclusive for Apple service {service}"
    e = exclusive[0]
    assert e.vendor == "Apple"
    # No cross-device downgrade for Apple services from random MACs.
    assert e.raw.get("cross_device") is False, (
        f"{service} from random MAC must NOT be flagged as cross-device "
        "— iPhones randomize MACs per SSID"
    )
    assert e.certainty >= 0.85, (
        f"Apple service certainty should not drop for random MAC, got {e.certainty}"
    )
