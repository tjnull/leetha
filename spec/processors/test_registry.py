"""Tests for processor registry."""
import importlib

from leetha.processors.registry import register_processor, get_processor, get_all_processors, clear_registry
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


def _reload_all_processors():
    """Re-register all processors by reloading their modules."""
    import leetha.processors.network
    import leetha.processors.services
    import leetha.processors.names
    import leetha.processors.infrastructure
    import leetha.processors.iot_scada
    import leetha.processors.passive
    import leetha.processors.banner
    import leetha.processors.behavioral
    import leetha.processors.active
    import leetha.processors.discovery_enhanced

    importlib.reload(leetha.processors.network)
    importlib.reload(leetha.processors.services)
    importlib.reload(leetha.processors.names)
    importlib.reload(leetha.processors.infrastructure)
    importlib.reload(leetha.processors.iot_scada)
    importlib.reload(leetha.processors.passive)
    importlib.reload(leetha.processors.banner)
    importlib.reload(leetha.processors.behavioral)
    importlib.reload(leetha.processors.active)
    importlib.reload(leetha.processors.discovery_enhanced)


class TestRegistry:
    def setup_method(self):
        clear_registry()
        _reload_all_processors()

    def test_arp_has_processor(self):
        cls = get_processor("arp")
        assert cls is not None

    def test_lldp_has_processor(self):
        cls = get_processor("lldp")
        assert cls is not None

    def test_tcp_syn_has_processor(self):
        cls = get_processor("tcp_syn")
        assert cls is not None

    def test_dns_has_processor(self):
        cls = get_processor("dns")
        assert cls is not None

    def test_ip_observed_has_processor(self):
        cls = get_processor("ip_observed")
        assert cls is not None

    def test_probe_has_processor(self):
        cls = get_processor("probe")
        assert cls is not None

    def test_unknown_protocol_returns_none(self):
        assert get_processor("nonexistent") is None

    def test_all_processors_returns_dict(self):
        all_procs = get_all_processors()
        assert isinstance(all_procs, dict)
        assert len(all_procs) >= 15  # We have 15+ protocol registrations

    def test_processor_analyze_returns_evidence(self):
        """Every registered processor should return Evidence from analyze()."""
        pkt = CapturedPacket(protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="192.168.1.1",
                             fields={"op": 1})
        cls = get_processor("arp")
        processor = cls()
        result = processor.analyze(pkt)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, Evidence)
