"""ICMPv6 Router/Neighbor Discovery parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_icmpv6(packet) -> CapturedPacket | None:
    """Extract ICMPv6 Router/Neighbor Discovery info.

    Captures Router Advertisement, Neighbor Solicitation, and Neighbor Advertisement.
    """
    try:
        from scapy.all import IPv6
        from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS
    except ImportError:
        return None

    if not packet.haslayer(IPv6):
        return None

    icmp_type = None
    data = {}

    if packet.haslayer(ICMPv6ND_RA):
        icmp_type = "router_advertisement"
        ra = packet[ICMPv6ND_RA]
        data = {
            "hop_limit": getattr(ra, 'chlim', None),
            "managed": getattr(ra, 'M', None),
            "other": getattr(ra, 'O', None),
        }
    elif packet.haslayer(ICMPv6ND_NS):
        icmp_type = "neighbor_solicitation"
        ns = packet[ICMPv6ND_NS]
        data = {
            "target": getattr(ns, 'tgt', None),
        }
    elif packet.haslayer(ICMPv6ND_NA):
        icmp_type = "neighbor_advertisement"
        na = packet[ICMPv6ND_NA]
        data = {
            "target": getattr(na, 'tgt', None),
            "router": getattr(na, 'R', None),
            "solicited": getattr(na, 'S', None),
            "override": getattr(na, 'O', None),
        }
    elif packet.haslayer(ICMPv6ND_RS):
        icmp_type = "router_solicitation"
        data = {}

    if not icmp_type:
        return None

    ipv6 = packet[IPv6]

    return CapturedPacket(
        protocol="icmpv6",
        hw_addr=packet.src,
        ip_addr=ipv6.src,
        target_ip=ipv6.dst,
        target_hw=packet.dst,
        fields={
            "icmpv6_type": icmp_type,
            **data,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
