"""Spoofing-detector audit fixes: OUI-mismatch scoping + per-detection rules.

  * A general-purpose computer (NIC vendor != OS vendor) must NOT raise an
    OUI mismatch — that was the ASUS-NIC / Windows("Microsoft") false
    positive that dominated the findings list.
  * An appliance/IoT device whose brand IS the hardware maker still raises
    OUI mismatch when the OUI vendor disagrees.
  * Each spoofing detection carries a precise ``rule`` so findings no longer
    collapse into a single ``identity_shift`` bucket.
"""

import pytest

from leetha.analysis.spoofing import SpoofingDetector
from leetha.store.models import Device, AlertType, FindingRule
from leetha.app import _resolve_finding_rule


def _mac_dev(**kw):
    base = dict(mac="a0:36:bc:ac:ab:ab", confidence=90, is_randomized_mac=False)
    base.update(kw)
    return Device(**base)


async def _noop_writer(*a, **k):
    return None


async def _no_prior(mac, limit=1):
    return []


async def test_computer_with_foreign_nic_is_not_oui_mismatch():
    det = SpoofingDetector(db=None)
    dev = _mac_dev(manufacturer="Microsoft", device_type="computer")
    alerts = await det.process_device_update(
        dev, oui_vendor="ASUSTek COMPUTER INC.",
        snapshot_reader=_no_prior, snapshot_writer=_noop_writer)
    assert not any(getattr(a, "rule", None) == "oui_mismatch" for a in alerts)


async def test_os_vendor_manufacturer_is_not_oui_mismatch():
    # Even if category were unknown, an OS-vendor manufacturer label must not
    # trip OUI mismatch (OS vendors don't make NICs).
    det = SpoofingDetector(db=None)
    dev = _mac_dev(manufacturer="Canonical", device_type=None)
    alerts = await det.process_device_update(
        dev, oui_vendor="Intel Corporate",
        snapshot_reader=_no_prior, snapshot_writer=_noop_writer)
    assert not any(getattr(a, "rule", None) == "oui_mismatch" for a in alerts)


async def test_google_hardware_device_oui_mismatch_still_flags():
    # Google makes hardware (Nest/Chromecast); a Google-branded device with a
    # mismatched NIC OUI must STILL be checked (regression: "google" was
    # wrongly treated as an OS-only vendor and skipped).
    det = SpoofingDetector(db=None)
    dev = _mac_dev(mac="00:11:22:33:44:66", manufacturer="Google",
                   device_type="smart_speaker")
    alerts = await det.process_device_update(
        dev, oui_vendor="Some Unrelated Vendor LLC",
        snapshot_reader=_no_prior, snapshot_writer=_noop_writer)
    assert any(getattr(a, "rule", None) == "oui_mismatch" for a in alerts)


async def test_appliance_brand_mismatch_still_flags():
    det = SpoofingDetector(db=None)
    dev = _mac_dev(mac="00:11:22:33:44:55", manufacturer="Hikvision",
                   device_type="camera")
    alerts = await det.process_device_update(
        dev, oui_vendor="Some Unrelated Vendor LLC",
        snapshot_reader=_no_prior, snapshot_writer=_noop_writer)
    oui = [a for a in alerts if getattr(a, "rule", None) == "oui_mismatch"]
    assert len(oui) == 1
    assert oui[0].rule == "oui_mismatch"


async def test_mac_spoofing_carries_its_own_rule():
    det = SpoofingDetector(db=None)
    dev = _mac_dev(mac="00:aa:bb:cc:dd:ee", manufacturer="Cisco",
                   device_type="switch", os_family="IOS")

    async def _reader(mac, limit=1):
        # Prior snapshot with a completely different OUI vendor → device swap.
        return [{"oui_vendor": "Netgear", "manufacturer": "Netgear",
                 "os_family": "RAIDiator"}]

    alerts = await det.process_device_update(
        dev, oui_vendor="Cisco Systems, Inc",
        snapshot_reader=_reader, snapshot_writer=_noop_writer)
    assert any(getattr(a, "rule", None) == "mac_spoofing" for a in alerts)


async def test_fp_drift_ignores_os_vendor_facet_flip():
    """ASUS <-> Microsoft manufacturer churn on a PC is not fingerprint drift."""
    det = SpoofingDetector(db=None)
    dev = _mac_dev(manufacturer="Microsoft", device_type="computer",
                   os_family="Windows")

    async def _reader(mac, limit=1):
        return [{"os_family": "Windows", "manufacturer": "ASUS",
                 "oui_vendor": "ASUSTek COMPUTER INC."}]

    alerts = await det.process_device_update(
        dev, oui_vendor="ASUSTek COMPUTER INC.",
        snapshot_reader=_reader, snapshot_writer=_noop_writer)
    assert not any(getattr(a, "rule", None) == "fingerprint_drift" for a in alerts)


async def test_fp_drift_suppresses_flip_flop():
    """A device oscillating A->B->A must not keep emitting drift findings."""
    det = SpoofingDetector(db=None)
    prev = {"mfr": "Initial"}

    async def _reader(mac, limit=1):
        return [{"os_family": "Linux", "manufacturer": prev["mfr"],
                 "oui_vendor": "Acme"}]

    async def _step(cur):
        # Clear the 300s rate limiter so we isolate the flip-flop gate
        # (which suppresses reverts even after the rate-limit window passes).
        det._rate_limiter.clear()
        dev = _mac_dev(mac="00:de:ad:be:ef:01", manufacturer=cur,
                       device_type="printer", os_family="Linux")
        out = await det.process_device_update(
            dev, oui_vendor="Acme",
            snapshot_reader=_reader, snapshot_writer=_noop_writer)
        prev["mfr"] = cur
        return any(getattr(a, "rule", None) == "fingerprint_drift" for a in out)

    assert await _step("Acme")     # Initial -> Acme : genuine, fires
    assert await _step("Globex")   # Acme -> Globex   : genuine, fires
    # Globex -> Acme : reverts to a recently-seen identity → suppressed.
    assert not await _step("Acme")


def test_resolve_finding_rule_prefers_precise_rule():
    class _A:
        alert_type = AlertType.SPOOFING
        rule = "oui_mismatch"
    fallback = {AlertType.SPOOFING: FindingRule.IDENTITY_SHIFT}
    assert _resolve_finding_rule(_A(), fallback) == FindingRule.OUI_MISMATCH


def test_resolve_finding_rule_falls_back_when_absent():
    class _A:
        alert_type = AlertType.SPOOFING
        rule = None
    fallback = {AlertType.SPOOFING: FindingRule.IDENTITY_SHIFT}
    assert _resolve_finding_rule(_A(), fallback) == FindingRule.IDENTITY_SHIFT
