"""IGMP parser -- multicast group membership."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_igmp(packet) -> CapturedPacket | None:
    """Extract IGMP membership reports and queries."""
    try:
        from scapy.layers.inet import IP
        from scapy.contrib.igmp import IGMP
    except ImportError:
        return None

    if not packet.haslayer(IGMP) or not packet.haslayer(IP):
        return None

    igmp = packet[IGMP]
    ip = packet[IP]

    # IGMP type: 0x11=query, 0x16=v2 report, 0x17=leave, 0x22=v3 report
    igmp_type = igmp.type if hasattr(igmp, 'type') else 0
    group = str(igmp.gaddr) if hasattr(igmp, 'gaddr') else None

    # Skip queries from routers (we want device reports)
    if igmp_type == 0x11:
        return None

    if not group or group == "0.0.0.0":
        return None

    return CapturedPacket(
        protocol="igmp",
        hw_addr=packet.src,
        ip_addr=ip.src,
        fields={
            "igmp_type": igmp_type,
            "group": group,
            "type_name": {0x16: "membership_report_v2", 0x17: "leave_group",
                          0x22: "membership_report_v3"}.get(igmp_type, f"type_{igmp_type}"),
        },
    )
