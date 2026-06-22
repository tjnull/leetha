"""Infrastructure protocol parsers (LLDP, CDP, STP, SNMP).

These wrap the existing raw parsers from leetha.capture.parsers
to return CapturedPacket instead of plain dicts.
"""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_lldp(packet) -> CapturedPacket | None:
    """Parse LLDP frame into CapturedPacket."""
    from leetha.capture.parsers.lldp import parse_lldp as _parse_raw
    result = _parse_raw(packet)
    if result is None:
        return None
    return CapturedPacket(
        protocol="lldp",
        hw_addr=packet.src if hasattr(packet, 'src') else "",
        ip_addr=result.get("management_ip") or "",
        fields=result,
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_cdp(packet) -> CapturedPacket | None:
    """Parse CDP frame into CapturedPacket."""
    from leetha.capture.parsers.cdp import parse_cdp as _parse_raw
    result = _parse_raw(packet)
    if result is None:
        return None
    return CapturedPacket(
        protocol="cdp",
        hw_addr=packet.src if hasattr(packet, 'src') else "",
        ip_addr=result.get("management_ip") or "",
        fields=result,
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_stp(packet) -> CapturedPacket | None:
    """Parse STP BPDU into CapturedPacket."""
    from leetha.capture.parsers.stp import parse_stp as _parse_raw
    result = _parse_raw(packet)
    if result is None:
        return None
    return CapturedPacket(
        protocol="stp",
        hw_addr=packet.src if hasattr(packet, 'src') else "",
        ip_addr="",
        fields=result,
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dtp(packet) -> CapturedPacket | None:
    """Parse a Cisco DTP frame into CapturedPacket."""
    from leetha.capture.parsers.dtp import parse_dtp as _parse_raw
    result = _parse_raw(packet)
    if result is None:
        return None
    return CapturedPacket(
        protocol="dtp",
        hw_addr=packet.src if hasattr(packet, 'src') else "",
        ip_addr="",
        fields=result,
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_snmp(packet) -> CapturedPacket | None:
    """Parse SNMP packet into CapturedPacket."""
    from leetha.capture.parsers.snmp import parse_snmp as _parse_raw
    result = _parse_raw(packet)
    if result is None:
        return None

    # Try to extract IP address from the packet
    ip_addr = ""
    try:
        from scapy.layers.inet import IP
        if packet.haslayer(IP):
            ip_addr = packet[IP].src
    except ImportError:
        pass

    return CapturedPacket(
        protocol="snmp",
        hw_addr=packet.src if hasattr(packet, 'src') else "",
        ip_addr=ip_addr,
        fields=result,
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
