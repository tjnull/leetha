"""Tests for VerdictEngine."""
import re
from pathlib import Path
from leetha.evidence.engine import VerdictEngine, _SOURCE_WEIGHTS
from leetha.evidence.models import Evidence, Verdict


class TestVerdictEngine:
    def setup_method(self):
        self.engine = VerdictEngine()

    def test_empty_evidence_returns_zero_certainty(self):
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", [])
        assert v.hw_addr == "aa:bb:cc:dd:ee:ff"
        assert v.certainty == 0
        assert v.category is None

    def test_single_evidence(self):
        evidence = [Evidence(source="lldp", method="exact", certainty=0.9,
                            category="switch", vendor="Cisco")]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.category == "switch"
        assert v.vendor == "Cisco"
        assert v.certainty > 0

    def test_multiple_agreeing_sources_boost(self):
        evidence = [
            Evidence(source="lldp", method="exact", certainty=0.9, vendor="Cisco"),
            Evidence(source="cdp", method="exact", certainty=0.92, vendor="Cisco"),
        ]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.vendor == "Cisco"
        # Two agreeing sources should produce higher certainty than one

    def test_conflicting_evidence_picks_stronger(self):
        evidence = [
            Evidence(source="lldp", method="exact", certainty=0.95, vendor="Cisco"),
            Evidence(source="ip_observed", method="heuristic", certainty=0.3, vendor="Unknown"),
        ]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.vendor == "Cisco"  # LLDP has higher weight

    def test_hostname_preserved(self):
        evidence = [Evidence(source="dhcpv4", method="exact", certainty=0.8,
                            hostname="DESKTOP-ABC123")]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.hostname == "DESKTOP-ABC123"

    def test_evidence_chain_preserved(self):
        evidence = [
            Evidence(source="lldp", method="exact", certainty=0.9, vendor="Cisco"),
            Evidence(source="stp", method="heuristic", certainty=0.5, category="switch"),
        ]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert len(v.evidence_chain) == 2

    def test_update_appends_evidence(self):
        initial = [Evidence(source="arp", method="heuristic", certainty=0.3)]
        v1 = self.engine.compute("aa:bb:cc:dd:ee:ff", initial)

        new = [Evidence(source="lldp", method="exact", certainty=0.9, vendor="Cisco")]
        v2 = self.engine.update(v1, new)
        assert len(v2.evidence_chain) == 2
        assert v2.vendor == "Cisco"

    def test_platform_and_version(self):
        evidence = [Evidence(source="cdp", method="exact", certainty=0.92,
                            platform="IOS-XE", platform_version="16.12.4")]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.platform == "IOS-XE"
        assert v.platform_version == "16.12.4"

    def test_full_verdict(self):
        evidence = [
            Evidence(source="lldp", method="exact", certainty=0.9,
                    category="switch", vendor="Cisco", model="WS-C3850"),
            Evidence(source="cdp", method="exact", certainty=0.92,
                    platform="IOS-XE", platform_version="16.12.4"),
            Evidence(source="dhcpv4", method="exact", certainty=0.75,
                    hostname="core-sw01"),
        ]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.category == "switch"
        assert v.vendor == "Cisco"
        assert v.platform == "IOS-XE"
        assert v.hostname == "core-sw01"
        assert v.model == "WS-C3850"
        assert v.certainty > 50

    def test_is_classified(self):
        evidence = [Evidence(source="lldp", method="exact", certainty=0.9, vendor="Cisco")]
        v = self.engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert v.is_classified is True

    def test_all_processor_sources_have_explicit_weights(self):
        """Every source= value used by processors must have an explicit weight."""
        processors_dir = Path(__file__).resolve().parents[2] / "src" / "leetha" / "processors"
        source_pattern = re.compile(r'source="([a-z_]+)"')
        sources_used = set()
        for py_file in processors_dir.glob("*.py"):
            text = py_file.read_text()
            sources_used.update(source_pattern.findall(text))

        missing = sources_used - set(_SOURCE_WEIGHTS.keys())
        assert not missing, (
            f"Processor sources missing from _SOURCE_WEIGHTS: {sorted(missing)}"
        )
