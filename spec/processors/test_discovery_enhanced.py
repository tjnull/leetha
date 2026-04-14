"""Tests for WS-Discovery and NTP processors."""
import pytest
from leetha.processors.discovery_enhanced import EnhancedDiscoveryProcessor
from leetha.capture.packets import CapturedPacket


def test_ws_discovery_printer():
    proc = EnhancedDiscoveryProcessor()
    pkt = CapturedPacket(
        protocol="ws_discovery",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100",
        fields={
            "action": "hello",
            "device_types": ["printer"],
            "manufacturer": "HP",
            "model": "LaserJet Pro M404",
            "firmware": "20230815",
        },
    )
    evidence = proc.analyze(pkt)
    assert len(evidence) == 1
    assert evidence[0].source == "ws_discovery"
    assert evidence[0].vendor == "HP"
    assert evidence[0].model == "LaserJet Pro M404"
    assert evidence[0].certainty == 0.85


def test_ws_discovery_type_only():
    proc = EnhancedDiscoveryProcessor()
    pkt = CapturedPacket(
        protocol="ws_discovery",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100",
        fields={"action": "probe_match", "device_types": ["scanner"], "manufacturer": None, "model": None},
    )
    evidence = proc.analyze(pkt)
    assert len(evidence) == 1
    assert evidence[0].category == "scanner"
    assert evidence[0].certainty == 0.65


def test_ntp_server():
    proc = EnhancedDiscoveryProcessor()
    pkt = CapturedPacket(
        protocol="ntp",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.1",
        fields={"mode": "server", "stratum": 2, "reference_id": "10.0.0.1"},
    )
    evidence = proc.analyze(pkt)
    assert len(evidence) == 1
    assert evidence[0].source == "ntp"
    # NTP server mode no longer assigns category -- too many false positives
    assert evidence[0].category is None


def test_ntp_client():
    proc = EnhancedDiscoveryProcessor()
    pkt = CapturedPacket(
        protocol="ntp",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.50",
        fields={"mode": "client", "stratum": 0, "reference_id": ""},
    )
    evidence = proc.analyze(pkt)
    assert len(evidence) == 1
    assert evidence[0].raw["ntp_role"] == "client"
    assert evidence[0].certainty == 0.30
