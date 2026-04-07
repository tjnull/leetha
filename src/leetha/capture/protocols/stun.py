"""STUN/TURN parser -- WebRTC NAT traversal."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_stun(packet) -> CapturedPacket | None:
    """Detect STUN binding requests/responses on common ports."""
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    # STUN typically on 3478, 5349, or 19302 (Google)
    stun_ports = {3478, 5349, 19302, 19303, 19304, 19305, 19306, 19307, 19308}
    if udp.dport not in stun_ports and udp.sport not in stun_ports:
        return None

    # STUN magic cookie check (0x2112A442 at offset 4)
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw])
    if len(payload) < 20:
        return None
    # STUN magic cookie at bytes 4-7
    if payload[4:8] != b'\x21\x12\xa4\x42':
        return None

    msg_type = int.from_bytes(payload[0:2], 'big')
    msg_len = int.from_bytes(payload[2:4], 'big')

    type_names = {
        0x0001: "binding_request",
        0x0101: "binding_response",
        0x0111: "binding_error",
        0x0003: "allocate_request",
        0x0103: "allocate_response",
    }

    return CapturedPacket(
        protocol="stun",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "msg_type": msg_type,
            "type_name": type_names.get(msg_type, f"type_{msg_type:#06x}"),
            "msg_length": msg_len,
            "dst_port": udp.dport,
        },
    )
