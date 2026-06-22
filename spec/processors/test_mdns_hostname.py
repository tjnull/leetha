"""Hostnames must be real device names, not mDNS/DNS-SD service labels.

Regression for the inventory showing "_airplay", "_sftp-ssh",
"_apple-mobdev2", "_esphomelib", "_googlezone", etc. as hostnames — those
are service-discovery labels leaking in via service-enumeration PTR
records. Also verifies the mDNS instance name (the device's friendly name)
is surfaced as a proper hostname.
"""

import pytest

from leetha.evidence.hostname import is_valid_hostname
from leetha.processors.names import NameResolutionProcessor
from leetha.capture.packets import CapturedPacket


@pytest.mark.parametrize("label", [
    "_airplay", "_sftp-ssh", "_apple-mobdev2", "_esphomelib", "_xbmc-events",
    "_googlezone", "_googcrossdevice", "_services._dns-sd._udp",
    "Living._airplay._tcp.local", "x._sub._http._tcp.local",
])
def test_service_labels_rejected(label):
    assert is_valid_hostname(label) is False


@pytest.mark.parametrize("name", [
    "conops", "iPhone", "Lutron Status", "Johns-iPhone", "Living Room",
    "Office-Printer", "DESKTOP-AB12",
])
def test_real_hostnames_accepted(name):
    assert is_valid_hostname(name) is True


def test_mdns_instance_name_becomes_hostname():
    """A device announcing a service uses its friendly instance name as the
    hostname — never the service type."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr="00:11:22:33:44:55", ip_addr="192.168.1.50",
        fields={"service_type": "_airplay._tcp",
                "name": "Living Room._airplay._tcp.local"},
    )
    result = proc.analyze(pkt)
    hostnames = [e.hostname for e in result if e.hostname]
    assert "Living Room" in hostnames
    # No service-label hostname leaked.
    assert not any(h.startswith("_") for h in hostnames)


def test_mdns_service_type_does_not_leak_as_hostname():
    """An announcement with no instance name yields no hostname (not the
    service label)."""
    proc = NameResolutionProcessor()
    pkt = CapturedPacket(
        protocol="mdns", hw_addr="00:11:22:33:44:55", ip_addr="192.168.1.51",
        fields={"service_type": "_sftp-ssh._tcp", "name": None},
    )
    result = proc.analyze(pkt)
    assert all(not (e.hostname and e.hostname.startswith("_")) for e in result)
