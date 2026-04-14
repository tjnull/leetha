"""STP (Spanning Tree Protocol) parser.

Extracts bridge ID, root bridge ID, port priority, and topology
information from STP BPDUs.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


def parse_stp(packet) -> dict | None:
    """Parse STP BPDU and extract bridge topology information."""
    try:
        from scapy.layers.l2 import STP
    except ImportError:
        return None

    if not packet.haslayer(STP):
        return None

    stp = packet[STP]
    result = {"protocol": "stp"}

    try:
        result["bridge_id"] = f"{stp.bridgeid:04x}.{stp.bridgemac}"
        result["root_id"] = f"{stp.rootid:04x}.{stp.rootmac}"
        result["root_mac"] = str(stp.rootmac)
        result["bridge_mac"] = str(stp.bridgemac)
        result["root_priority"] = int(stp.rootid)
        result["bridge_priority"] = int(stp.bridgeid)
        result["port_priority"] = int(stp.portid >> 12) if stp.portid else 0
        result["port_id"] = int(stp.portid & 0xFFF) if stp.portid else 0
        result["root_path_cost"] = int(stp.pathcost)
        result["is_root"] = stp.rootmac == stp.bridgemac
    except Exception:
        pass

    return result if len(result) > 1 else None
