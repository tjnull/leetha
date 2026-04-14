"""Fallback IP observation parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def _guess_initial_ttl(ttl: int) -> tuple[int, str | None]:
    """Guess the initial TTL and broad OS hint from observed TTL.

    TTL 1-64: Too ambiguous (Linux, iOS, macOS, Android, FreeBSD all use 64).
    TTL 65-128: Windows.
    TTL 129-255: Network device (Cisco, etc.).
    """
    if ttl <= 64:
        return 64, None
    if ttl <= 128:
        return 128, "windows"
    return 255, "network_device"


def parse_ip_observed(packet) -> CapturedPacket | None:
    """Fallback parser: extract basic IP-level info from any IP packet.

    Used for passive device discovery on VPN interfaces where protocol-specific
    parsers may not match (e.g., non-SYN TCP, unknown UDP ports).
    """
    from scapy.all import IP, TCP, UDP

    if IP not in packet:
        return None

    ip = packet[IP]
    src_mac = packet.src if hasattr(packet, "src") else ""

    ttl_initial, ttl_hint = _guess_initial_ttl(ip.ttl)
    ttl_hops = ttl_initial - ip.ttl

    fields = {
        "proto": ip.proto,
        "ttl": ip.ttl,
        "ttl_initial_guess": ttl_initial,
        "ttl_os_hint": ttl_hint,
        "ttl_hops": ttl_hops,
        "src_port": None,
        "dst_port": None,
    }

    if TCP in packet:
        fields["src_port"] = packet[TCP].sport
        fields["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        fields["src_port"] = packet[UDP].sport
        fields["dst_port"] = packet[UDP].dport

    return CapturedPacket(
        protocol="ip_observed",
        hw_addr=src_mac,
        ip_addr=ip.src,
        target_ip=ip.dst,
        fields=fields,
    )
