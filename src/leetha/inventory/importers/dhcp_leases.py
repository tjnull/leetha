"""Phase A.3 Task 23 — DHCP lease file importer (ISC dhcpd + dnsmasq)."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path

from leetha.inventory.base import BaseImporter, ImportedDevice, TestResult
from leetha.inventory.config_schema import ConfigField
from leetha.inventory.registry import register_importer

log = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)
_ISC_LEASE_START = re.compile(r"^lease\s+(\S+)\s*\{", re.IGNORECASE)
_ISC_HW_ETH = re.compile(r"hardware\s+ethernet\s+([^;]+);", re.IGNORECASE)
_ISC_HOSTNAME = re.compile(r'client-hostname\s+"([^"]*)"', re.IGNORECASE)
_ISC_ENDS = re.compile(r"ends\s+\S+\s+([^;]+);", re.IGNORECASE)


def _norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower()
    if _MAC_RE.match(m):
        return m
    return None


def _detect_flavor(sample: str) -> str:
    for line in sample.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _ISC_LEASE_START.match(stripped):
            return "isc"
        # dnsmasq lines start with a unix epoch (integer)
        first = stripped.split(" ", 1)[0]
        if first.isdigit():
            return "dnsmasq"
        return "isc"  # fallback
    return "dnsmasq"


def parse_dnsmasq(text: str) -> list[ImportedDevice]:
    """Parse dnsmasq.leases format: ``expiry mac ip hostname clientid``."""
    devices: list[ImportedDevice] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            log.warning("malformed dnsmasq lease line %d: %r", lineno, raw)
            continue
        expiry, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
        mac_n = _norm_mac(mac)
        if mac_n is None:
            log.warning("malformed dnsmasq MAC on line %d: %r", lineno, mac)
            continue
        host = None if hostname == "*" else hostname
        devices.append(ImportedDevice(
            mac=mac_n,
            ip=ip,
            hostname=host,
            source="dhcp_leases",
            certainty=0.75,
            metadata={"flavor": "dnsmasq", "lease_expiry": expiry},
        ))
    return devices


def parse_isc(text: str) -> list[ImportedDevice]:
    """Parse ISC dhcpd.leases format: ``lease <ip> { hardware ethernet ..; }``."""
    devices: list[ImportedDevice] = []
    current_ip: str | None = None
    current_block: list[str] = []
    in_block = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not in_block:
            m = _ISC_LEASE_START.match(line)
            if m:
                current_ip = m.group(1)
                current_block = []
                in_block = True
            continue
        if line.startswith("}"):
            block_text = " ".join(current_block)
            mac_m = _ISC_HW_ETH.search(block_text)
            host_m = _ISC_HOSTNAME.search(block_text)
            ends_m = _ISC_ENDS.search(block_text)
            mac_n = _norm_mac(mac_m.group(1) if mac_m else None)
            if mac_n is None:
                log.warning("ISC lease at line %d missing/invalid MAC", lineno)
            else:
                devices.append(ImportedDevice(
                    mac=mac_n,
                    ip=current_ip,
                    hostname=host_m.group(1) if host_m else None,
                    source="dhcp_leases",
                    certainty=0.75,
                    metadata={
                        "flavor": "isc",
                        "lease_expiry": ends_m.group(1).strip() if ends_m else None,
                    },
                ))
            in_block = False
            current_ip = None
            current_block = []
            continue
        current_block.append(line)
    return devices


def parse_lease_file(text: str) -> list[ImportedDevice]:
    """Auto-detect format and parse. Empty or unknown → empty list."""
    flavor = _detect_flavor(text)
    if flavor == "dnsmasq":
        return parse_dnsmasq(text)
    return parse_isc(text)


@register_importer("dhcp_leases")
class DHCPLeaseImporter(BaseImporter):
    """Reads a local DHCP lease file and emits ImportedDevice records."""

    def __init__(self) -> None:
        self._config: dict = {}

    def configure(self, config: dict) -> None:
        self._config = config or {}

    @classmethod
    def config_schema(cls) -> list[ConfigField]:
        return [
            ConfigField(name="path", type="string", required=True,
                         help="Path to dhcpd.leases or dnsmasq.leases"),
            ConfigField(name="flavor", type="select",
                         choices=["auto", "isc", "dnsmasq"],
                         default="auto",
                         help="Lease-file format. 'auto' sniffs the first line."),
        ]

    async def test_connection(self) -> TestResult:
        path = self._config.get("path")
        if not path:
            return TestResult(ok=False, message="no path configured")
        p = Path(path)
        if not p.exists():
            return TestResult(ok=False, message=f"file not found: {path}")
        try:
            text = p.read_text(errors="replace")
        except Exception as err:
            return TestResult(ok=False, message=f"read failed: {err}")
        devices = parse_lease_file(text)
        return TestResult(
            ok=True,
            message=f"parsed {len(devices)} lease(s) from {path}",
            device_count=len(devices),
        )

    async def sync(self) -> AsyncIterator[ImportedDevice]:
        path = self._config.get("path")
        if not path:
            return
        p = Path(path)
        if not p.exists():
            log.warning("dhcp_leases path missing: %s", path)
            return
        text = p.read_text(errors="replace")
        flavor = self._config.get("flavor", "auto")
        if flavor == "isc":
            devices = parse_isc(text)
        elif flavor == "dnsmasq":
            devices = parse_dnsmasq(text)
        else:
            devices = parse_lease_file(text)
        for d in devices:
            yield d
