"""Tests for NetworkDiscoveryProcessor and PassiveObserverProcessor."""
from leetha.processors.network import NetworkDiscoveryProcessor
from leetha.processors.passive import PassiveObserverProcessor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


class TestNetworkDiscoveryProcessor:
    def setup_method(self):
        self.processor = NetworkDiscoveryProcessor()

    def test_arp_produces_evidence(self):
        pkt = CapturedPacket(protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.1", fields={"op": 1})
        result = self.processor.analyze(pkt)
        assert len(result) >= 1
        assert all(isinstance(e, Evidence) for e in result)

    def test_dhcpv4_with_hostname(self):
        pkt = CapturedPacket(protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.100",
                             fields={"hostname": "DESKTOP-ABC", "opt55": "1,3,6,15"})
        result = self.processor.analyze(pkt)
        assert any(e.hostname == "DESKTOP-ABC" for e in result)

    def test_icmpv6_router_advertisement(self):
        pkt = CapturedPacket(protocol="icmpv6", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="fe80::1",
                             fields={"icmpv6_type": "router_advertisement", "hop_limit": 64})
        result = self.processor.analyze(pkt)
        assert any(e.category == "router" for e in result)

    def test_unknown_protocol_returns_empty(self):
        pkt = CapturedPacket(protocol="unknown", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.1")
        result = self.processor.analyze(pkt)
        assert result == []


class TestPassiveObserverProcessor:
    def setup_method(self):
        self.processor = PassiveObserverProcessor()

    def test_dst_port_produces_service_hint(self):
        """Verify processor reads dst_port (not 'port') from fallback parser."""
        pkt = CapturedPacket(
            protocol="ip_observed",
            hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.50",
            fields={"src_port": 54321, "dst_port": 443, "ttl": 128},
        )
        result = self.processor.analyze(pkt)
        port_evidence = [e for e in result if e.source == "ip_observed_port"]
        assert len(port_evidence) == 1
        assert port_evidence[0].raw["port"] == 443
        assert port_evidence[0].raw["service_hint"] == "https"

    def test_no_port_field_returns_no_port_evidence(self):
        """When dst_port is None, no port evidence should be produced."""
        pkt = CapturedPacket(
            protocol="ip_observed",
            hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.50",
            fields={"ttl": 64},
        )
        result = self.processor.analyze(pkt)
        port_evidence = [e for e in result if e.source == "ip_observed_port"]
        assert len(port_evidence) == 0
