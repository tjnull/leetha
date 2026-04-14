"""NTP (Network Time Protocol) parser.

Captures NTP client, server, and broadcast packets on UDP 123.
Extracts mode, stratum, and reference ID for device classification.
"""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket

_MODE_NAMES = {
    1: "symmetric_active",
    2: "symmetric_passive",
    3: "client",
    4: "server",
    5: "broadcast",
}


def parse_ntp(packet) -> CapturedPacket | None:
    """Extract NTP fields from UDP port 123 packets."""
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        return None

    if not packet.haslayer(UDP):
        return None
    if not packet.haslayer(IP) and not packet.haslayer(IPv6):
        return None

    udp = packet[UDP]
    if udp.dport != 123 and udp.sport != 123:
        return None

    try:
        payload = bytes(udp.payload)
    except Exception:
        return None

    if len(payload) < 48:
        return None

    # Byte 0: LI (2 bits) | VN (3 bits) | Mode (3 bits)
    mode_val = payload[0] & 0x07
    mode = _MODE_NAMES.get(mode_val)
    if mode is None:
        return None

    # Byte 1: Stratum
    stratum = payload[1]

    # Bytes 12-15: Reference ID
    ref_bytes = payload[12:16]
    if stratum <= 1:
        # Stratum 0-1: ASCII clock source (e.g. "GPS\0", "PPS\0")
        reference_id = ref_bytes.decode("ascii", errors="ignore").rstrip("\x00").strip()
    else:
        # Stratum 2+: IP address of upstream NTP server
        reference_id = f"{ref_bytes[0]}.{ref_bytes[1]}.{ref_bytes[2]}.{ref_bytes[3]}"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    return CapturedPacket(
        protocol="ntp",
        hw_addr=packet.src,
        ip_addr=src_ip,
        target_ip=dst_ip,
        fields={
            "mode": mode,
            "stratum": stratum,
            "reference_id": reference_id,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
