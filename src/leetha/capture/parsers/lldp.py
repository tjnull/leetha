"""LLDP (Link Layer Discovery Protocol) parser.

Extracts chassis ID, port ID, system name, system description,
and management addresses from LLDP frames.
"""

from __future__ import annotations
import ipaddress
import logging

logger = logging.getLogger(__name__)


def parse_lldp(packet) -> dict | None:
    """Parse LLDP frame and extract device information."""
    try:
        from scapy.contrib.lldp import (
            LLDPDU, LLDPDUChassisID, LLDPDUPortID,
            LLDPDUSystemName, LLDPDUSystemDescription,
            LLDPDUManagementAddress, LLDPDUSystemCapabilities,
            LLDPDUPortDescription,
        )
    except ImportError:
        return None

    if not packet.haslayer(LLDPDU):
        return None

    result = {"protocol": "lldp"}

    # Chassis ID
    if packet.haslayer(LLDPDUChassisID):
        chassis = packet[LLDPDUChassisID]
        try:
            result["chassis_id"] = chassis.id.decode("utf-8", errors="replace") if isinstance(chassis.id, bytes) else str(chassis.id)
            result["chassis_id_subtype"] = int(chassis.subtype)
        except Exception:
            pass

    # Port ID
    if packet.haslayer(LLDPDUPortID):
        port = packet[LLDPDUPortID]
        try:
            result["port_id"] = port.id.decode("utf-8", errors="replace") if isinstance(port.id, bytes) else str(port.id)
            result["port_id_subtype"] = int(port.subtype)
        except Exception:
            pass

    # Port Description
    if packet.haslayer(LLDPDUPortDescription):
        try:
            desc = packet[LLDPDUPortDescription].description
            result["port_description"] = desc.decode("utf-8", errors="replace") if isinstance(desc, bytes) else str(desc)
        except Exception:
            pass

    # System Name
    if packet.haslayer(LLDPDUSystemName):
        try:
            name = packet[LLDPDUSystemName].system_name
            result["system_name"] = name.decode("utf-8", errors="replace") if isinstance(name, bytes) else str(name)
        except Exception:
            pass

    # System Description
    if packet.haslayer(LLDPDUSystemDescription):
        try:
            desc = packet[LLDPDUSystemDescription].description
            result["system_description"] = desc.decode("utf-8", errors="replace") if isinstance(desc, bytes) else str(desc)
        except Exception:
            pass

    # System Capabilities
    if packet.haslayer(LLDPDUSystemCapabilities):
        try:
            cap = packet[LLDPDUSystemCapabilities]
            caps = []
            cap_val = int(cap.capabilities or 0)
            if cap_val & 0x01: caps.append("other")
            if cap_val & 0x02: caps.append("repeater")
            if cap_val & 0x04: caps.append("bridge")
            if cap_val & 0x08: caps.append("wlan_ap")
            if cap_val & 0x10: caps.append("router")
            if cap_val & 0x20: caps.append("telephone")
            if cap_val & 0x40: caps.append("docsis")
            if cap_val & 0x80: caps.append("station")
            result["capabilities"] = caps
        except Exception:
            pass

    # Management Address
    if packet.haslayer(LLDPDUManagementAddress):
        try:
            mgmt = packet[LLDPDUManagementAddress]
            addr = mgmt.management_address
            if isinstance(addr, bytes):
                if len(addr) == 4:
                    result["management_ip"] = ".".join(str(b) for b in addr)
                elif len(addr) == 16:
                    result["management_ip"] = str(ipaddress.IPv6Address(addr))
                else:
                    result["management_ip"] = addr.hex()
            else:
                result["management_ip"] = str(addr)
        except Exception:
            pass

    return result if len(result) > 1 else None
