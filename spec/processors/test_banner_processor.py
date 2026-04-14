"""Tests for BannerProcessor."""
from leetha.processors.banner import BannerProcessor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


class TestBannerProcessor:
    def setup_method(self):
        self.processor = BannerProcessor()

    def test_ssh_banner(self):
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.10",
            fields={"service": "ssh", "software": "OpenSSH_9.2p1 Ubuntu-1",
                     "version": "9.2p1", "server_port": 22},
        )
        result = self.processor.analyze(pkt)
        assert len(result) == 1
        ev = result[0]
        assert ev.source == "passive_banner"
        assert ev.certainty == 0.30  # SSH certainty lowered to avoid false server classification
        assert ev.vendor == "OpenSSH"
        assert ev.platform_version == "9.2p1"
        assert ev.platform == "Linux"

    def test_mysql_banner(self):
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.20",
            fields={"service": "mysql", "software": "MySQL 8.0",
                     "version": "8.0", "server_port": 3306},
        )
        result = self.processor.analyze(pkt)
        assert len(result) == 1
        ev = result[0]
        assert ev.vendor == "MySQL"
        assert ev.category == "server"

    def test_smb_banner(self):
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.30",
            fields={"service": "smb", "software": "Samba 4.17",
                     "version": "4.17", "server_port": 445},
        )
        result = self.processor.analyze(pkt)
        assert len(result) == 1
        assert result[0].source == "passive_banner"

    def test_rdp_banner_no_automatic_windows_platform(self):
        """RDP no longer auto-assigns Windows -- xrdp on Linux is a known FP."""
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.40",
            fields={"service": "rdp", "software": "Microsoft Terminal Services",
                     "version": "10.0", "server_port": 3389},
        )
        result = self.processor.analyze(pkt)
        assert len(result) == 1
        # Platform should NOT be auto-assigned based on service name alone
        assert result[0].platform is None

    def test_printer_ipp_banner(self):
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.50",
            fields={"service": "ipp", "software": "CUPS 2.4",
                     "version": "2.4", "server_port": 631},
        )
        result = self.processor.analyze(pkt)
        assert len(result) == 1
        assert result[0].category == "printer"

    def test_unknown_service_returns_generic_evidence(self):
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.60",
            fields={"service": "custom_proto", "software": "SomeServer",
                     "version": "1.0", "server_port": 9999},
        )
        result = self.processor.analyze(pkt)
        assert len(result) == 1
        ev = result[0]
        assert ev.source == "passive_banner"
        assert ev.vendor == "SomeServer"

    def test_empty_fields_returns_empty(self):
        pkt = CapturedPacket(
            protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.70",
            fields={},
        )
        result = self.processor.analyze(pkt)
        assert result == []
