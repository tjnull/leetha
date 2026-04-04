"""Integration tests for passive banner capture pipeline."""
from leetha.capture.protocols import PARSER_CHAIN
from leetha.processors.registry import get_processor


class TestBannerPipelineIntegration:
    def test_service_banner_parser_in_chain(self):
        """Banner parser must be in PARSER_CHAIN before ip_observed."""
        names = [p.__name__ for p in PARSER_CHAIN]
        assert "parse_service_banner" in names
        banner_idx = names.index("parse_service_banner")
        observed_idx = names.index("parse_ip_observed")
        assert banner_idx < observed_idx

    def test_service_banner_processor_registered(self):
        """BannerProcessor must be registered for 'service_banner' protocol."""
        import leetha.processors.banner  # noqa: F401
        proc_cls = get_processor("service_banner")
        assert proc_cls is not None
        assert proc_cls.__name__ == "BannerProcessor"

    def test_banner_ports_bpf_included(self):
        """BPF filter must include banner ports."""
        from leetha.capture.engine import _FULL_BPF
        assert "tcp port 22" in _FULL_BPF
        assert "tcp port 3306" in _FULL_BPF
        assert "tcp port 445" in _FULL_BPF
        assert "tcp port 3389" in _FULL_BPF
        assert "tcp port 631" in _FULL_BPF

    def test_chain_still_ends_with_ip_observed(self):
        """ip_observed must remain the last (fallback) parser."""
        names = [p.__name__ for p in PARSER_CHAIN]
        assert names[-1] == "parse_ip_observed"

    def test_chain_count_increased(self):
        """Chain should now have 20 parsers (19 original + 1 banner)."""
        assert len(PARSER_CHAIN) >= 20

    def test_processor_produces_evidence_from_banner_packet(self):
        """End-to-end: CapturedPacket -> BannerProcessor -> Evidence."""
        import leetha.processors.banner  # noqa: F401
        from leetha.capture.packets import CapturedPacket
        from leetha.evidence.models import Evidence

        proc_cls = get_processor("service_banner")
        processor = proc_cls()
        pkt = CapturedPacket(
            protocol="service_banner",
            hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="10.0.0.1",
            fields={
                "service": "ssh",
                "software": "OpenSSH_9.2p1",
                "version": "9.2p1",
                "server_port": 22,
                "raw_banner": "SSH-2.0-OpenSSH_9.2p1",
            },
        )
        result = processor.analyze(pkt)
        assert len(result) >= 1
        assert isinstance(result[0], Evidence)
        assert result[0].source == "passive_banner"
        assert result[0].certainty == 0.85
