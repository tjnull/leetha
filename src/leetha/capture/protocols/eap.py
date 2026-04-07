"""EAP/802.1X parser -- port-based network access control."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_eap(packet) -> CapturedPacket | None:
    """Detect 802.1X/EAP authentication frames."""
    try:
        from scapy.layers.l2 import Ether
        from scapy.layers.eap import EAP, EAPOL
    except ImportError:
        return None

    if not packet.haslayer(EAPOL):
        return None

    eapol = packet[EAPOL]
    eapol_type = eapol.type if hasattr(eapol, 'type') else 0

    fields = {
        "eapol_type": eapol_type,
        "eapol_type_name": {0: "eap_packet", 1: "eapol_start",
                            2: "eapol_logoff", 3: "eapol_key"}.get(
            eapol_type, f"type_{eapol_type}"),
    }

    if packet.haslayer(EAP):
        eap = packet[EAP]
        fields["eap_code"] = eap.code if hasattr(eap, 'code') else None
        fields["eap_type"] = eap.type if hasattr(eap, 'type') else None
        fields["eap_code_name"] = {
            1: "request", 2: "response",
            3: "success", 4: "failure",
        }.get(fields["eap_code"], "unknown")
        # EAP type names
        fields["eap_type_name"] = {
            1: "identity", 2: "notification", 3: "nak",
            4: "md5_challenge", 13: "tls", 21: "ttls",
            25: "peap", 43: "fast",
        }.get(fields["eap_type"], "unknown")
        # Extract identity if present
        if fields["eap_type"] == 1 and hasattr(eap, 'identity'):
            fields["identity"] = (
                eap.identity.decode('utf-8', errors='replace')
                if isinstance(eap.identity, bytes)
                else str(eap.identity)
            )

    src_mac = packet.src if hasattr(packet, 'src') else (
        packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
    )

    return CapturedPacket(
        protocol="eap",
        hw_addr=src_mac,
        ip_addr="0.0.0.0",  # EAP is L2, no IP
        fields=fields,
    )
