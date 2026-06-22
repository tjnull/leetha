"""Benign-churn guards for ARP-based spoofing detectors.

  * IP conflict only fires when two MACs contest an IP at roughly the same
    time; a stale prior claim (DHCP reassignment) or two randomized MACs
    (privacy rotation) must not.
  * ARP flip-flop must not fire when every oscillating MAC is randomized,
    nor for infrastructure (VRRP/HSRP failover on a shared virtual IP).
"""

import time
import pytest

from leetha.analysis.spoofing import SpoofingDetector, IP_CONFLICT_ACTIVE_WINDOW


class _Dev:
    def __init__(self, device_type=None, ip_v4=None, hostname=None):
        self.device_type = device_type
        self.ip_v4 = ip_v4
        self.hostname = hostname


class _FakeDB:
    def __init__(self, devices=None):
        self._d = devices or {}

    async def get_device(self, mac):
        return self._d.get(mac)

    async def upsert_arp_entry(self, *a, **k):
        return None


async def _arp(det, src_mac, src_ip, op=2):
    return await det.inspect_arp(src_mac, src_ip, "ff:ff:ff:ff:ff:ff",
                                 src_ip, op, "eth0")


def _kinds(alerts):
    return {getattr(a, "rule", None) for a in alerts}


async def test_ip_conflict_fires_for_two_real_macs():
    det = SpoofingDetector(_FakeDB())
    await _arp(det, "00:11:22:33:44:01", "192.168.1.10")
    out = await _arp(det, "00:11:22:33:44:02", "192.168.1.10")
    assert "addr_conflict" in _kinds(out)


async def test_ip_conflict_suppressed_for_randomized_pair():
    det = SpoofingDetector(_FakeDB())
    await _arp(det, "fa:11:22:33:44:01", "192.168.1.11")   # LAA
    out = await _arp(det, "f6:55:66:77:88:02", "192.168.1.11")  # LAA
    assert "addr_conflict" not in _kinds(out)


async def test_ip_conflict_suppressed_when_prior_is_stale():
    det = SpoofingDetector(_FakeDB())
    # Prior claim from long ago → DHCP reassignment, not a live conflict.
    det._arp_timeline["192.168.1.12"] = {
        "mac": "00:11:22:33:44:aa",
        "last_seen": time.monotonic() - (IP_CONFLICT_ACTIVE_WINDOW + 60),
    }
    out = await _arp(det, "00:11:22:33:44:bb", "192.168.1.12")
    assert "addr_conflict" not in _kinds(out)


async def test_flip_flop_suppressed_when_all_macs_randomized():
    det = SpoofingDetector(_FakeDB())
    # >=3 transitions among randomized (LAA) MACs on one IP.
    for mac in ("fa:00:00:00:00:01", "fe:00:00:00:00:02",
                "f2:00:00:00:00:03", "fa:00:00:00:00:01"):
        out = await _arp(det, mac, "192.168.1.20")
    assert "arp_spoofing" not in _kinds(out)


async def test_flip_flop_fires_for_real_macs():
    det = SpoofingDetector(_FakeDB())
    out = []
    for mac in ("00:aa:00:00:00:01", "00:bb:00:00:00:02",
                "00:cc:00:00:00:03", "00:aa:00:00:00:01"):
        out = await _arp(det, mac, "192.168.1.21")
    assert "arp_spoofing" in _kinds(out)


async def test_flip_flop_suppressed_for_infrastructure():
    db = _FakeDB({
        "00:aa:00:00:00:01": _Dev(device_type="router"),
        "00:bb:00:00:00:02": _Dev(device_type="router"),
        "00:cc:00:00:00:03": _Dev(device_type="router"),
    })
    det = SpoofingDetector(db)
    out = []
    for mac in ("00:aa:00:00:00:01", "00:bb:00:00:00:02",
                "00:cc:00:00:00:03", "00:aa:00:00:00:01"):
        out = await _arp(det, mac, "192.168.1.22")
    assert "arp_spoofing" not in _kinds(out)
