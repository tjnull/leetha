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
def test_apple_service_from_random_mac_is_reflected(service):
    """A router reflecting iPhone Apple services must not inherit the
    Apple vendor tag — otherwise the router ends up classified as an
    Apple device (and worse, pairs with reflected printer services to
    show up as ``Apple printer``)."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=RANDOMIZED_MAC, ip_addr="192.168.1.1",
        fields={"service_type": service, "name": f"Foo.{service}.local"},
    )
    result = proc.analyze(pkt)
    exclusive = [e for e in result if e.source == "mdns_exclusive"]
    assert exclusive, f"expected mdns_exclusive for {service}"
    e = exclusive[0]
    # Reflected traffic must not propagate vendor/category/platform.
    assert e.vendor is None, (
        f"{service} from random MAC should not attribute Apple vendor "
        "to the reflecting device; got vendor={e.vendor!r}"
    )
    assert e.category is None
    assert e.platform is None
    assert e.certainty <= 0.50
    assert e.raw.get("cross_device") is True


@pytest.mark.parametrize("service", [
    # Printer services — when reflected by a router with mDNS-reflection
    # enabled, the router ended up classified as ``printer @ 100%``.
    "_ipp._tcp",
    "_ipps._tcp",
    "_airprint._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_privet._tcp",
    # Scanner / NAS / file services follow the same path and would
    # mis-classify a router as a scanner/nas/workstation via reflection.
    "_scanner._tcp",
    "_uscan._tcp",
    "_smb._tcp",
    "_nfs._tcp",
])
def test_non_exclusive_service_from_random_mac_is_reflected(service):
    """Router mDNS reflection of printer / NAS / scanner services must
    not attribute their category to the reflecting router. Real printers
    / NAS boxes / scanners ship with real vendor OUIs — locally-
    administered MACs never belong to this class of hardware."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=RANDOMIZED_MAC, ip_addr="192.168.1.1",
        fields={"service_type": service, "name": f"Foo.{service}.local"},
    )
    result = proc.analyze(pkt)
    # The second mdns_service evidence (from match_mdns_service) must
    # not carry vendor/category/platform when the source MAC is random.
    informative = [
        e for e in result
        if e.source == "mdns_service" and (e.vendor or e.category or e.platform)
    ]
    assert not informative, (
        f"{service} from random MAC must not attribute category/vendor "
        f"to the reflecting device; got: {[(e.vendor, e.category, e.platform, e.certainty) for e in informative]}"
    )


@pytest.mark.parametrize("service", [
    "_ipp._tcp",
    "_printer._tcp",
    "_airprint._tcp",
])
def test_non_exclusive_service_from_real_oui_keeps_category(service):
    """Real printer OUIs (bit 0x02 = 0) must keep the printer category."""
    proc = NameResolutionProcessor()
    # HP Inc. universally-administered OUI
    real_hp_mac = "3c:52:82:11:22:33"
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=real_hp_mac, ip_addr="192.168.1.50",
        fields={"service_type": service, "name": f"HP_LaserJet.{service}.local"},
    )
    result = proc.analyze(pkt)
    printer_evs = [e for e in result if e.category == "printer"]
    assert printer_evs, (
        f"real-OUI printer advertising {service} must still classify as printer; "
        f"got evidence: {[(e.source, e.vendor, e.category, e.platform, e.certainty) for e in result]}"
    )


@pytest.mark.parametrize("service", [
    "_airplay._tcp",
    "_homekit._tcp",
    "_apple-mobdev2._tcp",
])
def test_apple_service_from_real_apple_oui_stays_trusted(service):
    """Real Apple hardware OUIs (bit 0x02 = 0) keep full trust."""
    proc = NameResolutionProcessor()
    # Apple Inc. universally-administered OUI (bit 0x02 = 0)
    real_apple_mac = "ac:bc:32:11:22:33"
    pkt = CapturedPacket(
        protocol="mdns", hw_addr=real_apple_mac, ip_addr="192.168.1.50",
        fields={"service_type": service, "name": f"iPhone.{service}.local"},
    )
    result = proc.analyze(pkt)
    exclusive = [e for e in result if e.source == "mdns_exclusive"]
    assert exclusive
    e = exclusive[0]
    assert e.vendor == "Apple"
    assert e.certainty >= 0.85
    assert e.raw.get("cross_device") is False
