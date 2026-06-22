"""DTP (Dynamic Trunking Protocol) parser.

Extracts trunk-negotiation state from Cisco DTP frames. A switch port left
in ``dynamic auto``/``dynamic desirable`` advertises that it will form a
trunk — the exposure an attacker exploits for VLAN hopping via switch
spoofing. Seeing ``desirable``/``on`` DTP from an endpoint is the attack
itself.

Importing ``scapy.contrib.dtp`` at module load registers the SNAP PID
(0x2004) -> DTP binding, so frames sniffed from the wire actually dissect
into a DTP layer (otherwise they stay as opaque SNAP payload).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:  # registers the SNAP->DTP layer binding as an import side effect
    from scapy.contrib.dtp import (
        DTP, DTPStatus, DTPType, DTPDomain, DTPNeighbor,
    )
    _DTP_OK = True
except Exception:  # pragma: no cover - scapy missing/old
    _DTP_OK = False

# DTP status byte -> trunk-negotiation mode. Scapy/Brezular treat 0x03 as
# desirable and 0x04 as auto; some references swap them, so both are counted
# as "negotiating". 0x81 is a hard-set trunk ("on").
_DTP_MODES = {
    0x01: "access", 0x02: "off",
    0x03: "dynamic_desirable", 0x04: "dynamic_auto", 0x81: "trunk",
}
_NEGOTIATING_BYTES = frozenset({0x03, 0x04, 0x81})
_ENCAP = {0x42: "isl", 0xa5: "dot1q", 0x45: "dot1q_force"}


def _last_byte(val) -> int | None:
    if isinstance(val, (bytes, bytearray)) and val:
        return val[-1]
    if isinstance(val, int):
        return val
    return None


def parse_dtp(packet) -> dict | None:
    """Parse a Cisco DTP frame into a trunk-negotiation descriptor."""
    if not _DTP_OK or not packet.haslayer(DTP):
        return None

    result: dict = {"protocol": "dtp"}
    try:
        if packet.haslayer(DTPStatus):
            sb = _last_byte(packet[DTPStatus].status)
            if sb is not None:
                result["status_byte"] = int(sb)
                result["mode"] = _DTP_MODES.get(sb, "unknown")
                result["negotiating"] = sb in _NEGOTIATING_BYTES

        if packet.haslayer(DTPType):
            tb = _last_byte(packet[DTPType].dtptype)
            if tb is not None:
                result["dtp_type_byte"] = int(tb)
                result["encap"] = _ENCAP.get(tb, "unknown")

        if packet.haslayer(DTPDomain):
            dom = packet[DTPDomain].domain
            if isinstance(dom, (bytes, bytearray)):
                result["domain"] = dom.decode(errors="ignore").rstrip("\x00")
            elif dom:
                result["domain"] = str(dom)

        if packet.haslayer(DTPNeighbor):
            result["neighbor_mac"] = str(packet[DTPNeighbor].neighbor)

        if hasattr(packet, "src"):
            result["src_mac"] = packet.src
    except Exception:  # pragma: no cover - defensive
        pass

    return result if len(result) > 1 else None
