"""Phase A.3 Task 23 — DHCP lease file parser."""

import pytest
from pathlib import Path

from leetha.inventory.importers.dhcp_leases import (
    DHCPLeaseImporter,
    parse_isc,
    parse_dnsmasq,
    parse_lease_file,
)


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "dhcp_leases"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_isc_fixture():
    devices = parse_isc(_read("isc_dhcpd.leases"))
    assert len(devices) == 3
    macs = [d.mac for d in devices]
    assert "aa:bb:cc:dd:ee:01" in macs
    assert "aa:bb:cc:dd:ee:02" in macs
    assert "aa:bb:cc:dd:ee:03" in macs
    alice = next(d for d in devices if d.mac == "aa:bb:cc:dd:ee:01")
    assert alice.ip == "192.168.1.100"
    assert alice.hostname == "alice-laptop"
    assert alice.source == "dhcp_leases"
    assert alice.metadata["flavor"] == "isc"


def test_parse_dnsmasq_fixture():
    devices = parse_dnsmasq(_read("dnsmasq.leases"))
    assert len(devices) == 3
    macs = [d.mac for d in devices]
    assert "aa:bb:cc:dd:ee:11" in macs
    alice = next(d for d in devices if d.mac == "aa:bb:cc:dd:ee:11")
    assert alice.ip == "10.0.0.10"
    assert alice.hostname == "alice-pc"
    wildcard = next(d for d in devices if d.mac == "aa:bb:cc:dd:ee:12")
    assert wildcard.hostname is None  # "*" → None


def test_parse_lease_file_auto_detects_dnsmasq():
    devices = parse_lease_file(_read("dnsmasq.leases"))
    assert len(devices) == 3


def test_parse_lease_file_auto_detects_isc():
    devices = parse_lease_file(_read("isc_dhcpd.leases"))
    assert len(devices) == 3


def test_malformed_lines_are_skipped_not_fatal(caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        devices = parse_dnsmasq(_read("malformed.leases"))
    # two valid lines survive
    assert len(devices) == 2
    assert any("malformed" in r.getMessage().lower() for r in caplog.records)


@pytest.mark.asyncio
async def test_importer_sync_yields_devices(tmp_path):
    p = tmp_path / "leases"
    p.write_text(_read("isc_dhcpd.leases"))
    imp = DHCPLeaseImporter()
    imp.configure({"path": str(p), "flavor": "isc"})
    collected = []
    async for dev in imp.sync():
        collected.append(dev)
    assert len(collected) == 3


@pytest.mark.asyncio
async def test_importer_test_connection_reports_count(tmp_path):
    p = tmp_path / "leases"
    p.write_text(_read("dnsmasq.leases"))
    imp = DHCPLeaseImporter()
    imp.configure({"path": str(p), "flavor": "auto"})
    res = await imp.test_connection()
    assert res.ok is True
    assert res.device_count == 3


@pytest.mark.asyncio
async def test_importer_test_connection_missing_file(tmp_path):
    imp = DHCPLeaseImporter()
    imp.configure({"path": str(tmp_path / "nope")})
    res = await imp.test_connection()
    assert res.ok is False
