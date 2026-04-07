"""RADIUS parser -- enterprise authentication protocol."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket

_CODE_NAMES = {
    1: "access_request", 2: "access_accept", 3: "access_reject",
    4: "accounting_request", 5: "accounting_response",
    11: "access_challenge",
}

_RADIUS_PORTS = {1812, 1813, 1645, 1646}


def parse_radius(packet) -> CapturedPacket | None:
    """Detect RADIUS authentication/accounting packets."""
    try:
        from scapy.layers.inet import IP, UDP
    except ImportError:
        return None

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    # Try scapy's native Radius layer first
    try:
        from scapy.layers.radius import Radius
        if packet.haslayer(Radius):
            radius = packet[Radius]
            code = radius.code if hasattr(radius, 'code') else 0
            return CapturedPacket(
                protocol="radius",
                hw_addr=packet.src,
                ip_addr=packet[IP].src,
                target_ip=packet[IP].dst,
                fields={
                    "code": code,
                    "code_name": _CODE_NAMES.get(code, f"code_{code}"),
                },
            )
    except ImportError:
        pass

    # Fallback: check by port if scapy doesn't have Radius layer
    udp = packet[UDP]
    if udp.dport not in _RADIUS_PORTS and udp.sport not in _RADIUS_PORTS:
        return None

    try:
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw])
    if len(payload) < 20:
        return None

    code = payload[0]

    return CapturedPacket(
        protocol="radius",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "code": code,
            "code_name": _CODE_NAMES.get(code, f"code_{code}"),
            "is_server": udp.sport in _RADIUS_PORTS,
        },
    )
