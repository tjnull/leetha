"""QUIC parser -- HTTP/3 initial packet SNI extraction."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_quic(packet) -> CapturedPacket | None:
    """Extract SNI from QUIC Initial packets (UDP 443)."""
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    if udp.dport != 443 and udp.sport != 443:
        return None

    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw])
    if len(payload) < 5:
        return None

    # QUIC long header: first bit = 1, next bit = 1 (long header)
    # Form bit (0x80) and fixed bit (0x40) must be set
    first_byte = payload[0]
    if not (first_byte & 0xC0 == 0xC0):
        return None

    # Try to find SNI in the payload by searching for TLS SNI extension
    # SNI type = 0x0000, followed by length, then host_name type (0x00)
    sni = _extract_sni_from_quic(payload)
    if not sni:
        return None

    return CapturedPacket(
        protocol="quic",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "sni": sni,
            "dst_port": udp.dport,
        },
    )


def _extract_sni_from_quic(payload: bytes) -> str | None:
    """Search for SNI extension in QUIC Initial payload."""
    # Look for the SNI extension pattern: 0x00 0x00 (extension type)
    # followed by length, then 0x00 (host_name type), then name length + name
    idx = 0
    while idx < len(payload) - 10:
        # Search for potential SNI marker
        if payload[idx:idx + 2] == b'\x00\x00':
            try:
                ext_len = int.from_bytes(payload[idx + 2:idx + 4], 'big')
                if ext_len < 4 or ext_len > 256:
                    idx += 1
                    continue
                sni_list_len = int.from_bytes(payload[idx + 4:idx + 6], 'big')
                if payload[idx + 6] != 0:  # host_name type
                    idx += 1
                    continue
                name_len = int.from_bytes(payload[idx + 7:idx + 9], 'big')
                if name_len < 3 or name_len > 253:
                    idx += 1
                    continue
                name = payload[idx + 9:idx + 9 + name_len]
                try:
                    hostname = name.decode('ascii')
                    if '.' in hostname and all(
                        c.isalnum() or c in '.-' for c in hostname
                    ):
                        return hostname
                except (UnicodeDecodeError, ValueError):
                    pass
            except (IndexError, ValueError):
                pass
        idx += 1
    return None
