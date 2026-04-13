"""TLS Client Hello parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_tls_client_hello(packet) -> CapturedPacket | None:
    """Extract TLS Client Hello from TCP payload on port 443.

    Computes JA3 and JA4 fingerprints from the Client Hello fields.
    """
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    ip = packet[IP]

    # Accept TLS Client Hello on any common TLS port, not just 443.
    # This captures JA3/JA4 fingerprints from IMAPS, POP3S, LDAPS, etc.
    _TLS_PORTS = {443, 465, 636, 853, 993, 995, 5061, 8443, 8883, 9443}
    if tcp.dport not in _TLS_PORTS:
        return None

    payload = bytes(tcp.payload)
    if len(payload) < 6:
        return None

    from leetha.capture.tls_parser import parse_client_hello
    from leetha.patterns.tls import compute_ja3, compute_ja4

    fields = parse_client_hello(payload)
    if fields is None:
        return None

    ja3_hash, ja3_full = compute_ja3(
        tls_version=fields.tls_version,
        ciphers=fields.ciphers,
        extensions=fields.extensions,
        elliptic_curves=fields.elliptic_curves,
        ec_point_formats=fields.ec_point_formats,
    )

    ja4 = compute_ja4(
        tls_version=fields.tls_version,
        ciphers=fields.ciphers,
        extensions=fields.extensions,
        sni=fields.sni,
        alpn=fields.alpn,
    )

    return CapturedPacket(
        protocol="tls",
        hw_addr=packet.src,
        ip_addr=ip.src,
        target_ip=ip.dst,
        target_hw=packet.dst,
        fields={
            "ja3_hash": ja3_hash,
            "ja3_full": ja3_full,
            "ja4": ja4,
            "sni": fields.sni,
            "tls_version": fields.tls_version,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
