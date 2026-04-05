"""Leetha vendor-specific fingerprint patterns.

MAC prefix databases, banner patterns, and port signatures for identifying
specific network equipment vendors. Used by the fingerprint lookup engine
to map hardware addresses and service banners to vendor identities.

This module contains curated vendor intelligence gathered from public
documentation, device firmware analysis, and protocol specifications.
"""

from typing import Dict, List, Tuple, Optional, Any
import re

# ZYXEL DEVICE PATTERNS

ZYXEL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:13:49": ("network_device", "Network Equipment", "ZyXEL"),
    "00:19:CB": ("network_device", "Network Equipment", "ZyXEL"),
    "00:23:F8": ("network_device", "Network Equipment", "ZyXEL"),
    "00:A0:C5": ("network_device", "Network Equipment", "ZyXEL"),
    "28:28:5D": ("network_device", "Network Equipment", "ZyXEL"),
    "40:4A:03": ("network_device", "Network Equipment", "ZyXEL"),
    "50:67:F0": ("network_device", "Network Equipment", "ZyXEL"),
    "54:83:3A": ("network_device", "Network Equipment", "ZyXEL"),
    "5C:E2:8C": ("network_device", "Network Equipment", "ZyXEL"),
    "84:9B:06": ("network_device", "Network Equipment", "ZyXEL"),
    "90:EF:68": ("network_device", "Network Equipment", "ZyXEL"),
    "98:77:B8": ("network_device", "Network Equipment", "ZyXEL"),
    "B0:B2:DC": ("network_device", "Network Equipment", "ZyXEL"),
    # Note: BC:F6:85 is D-Link International per IEEE - removed from ZyXEL
    "C8:6C:87": ("network_device", "Network Equipment", "ZyXEL"),
    "CC:5D:4E": ("network_device", "Network Equipment", "ZyXEL"),
    "E4:18:6B": ("network_device", "Network Equipment", "ZyXEL"),
    "FC:F5:28": ("network_device", "Network Equipment", "ZyXEL"),
}

ZYXEL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Firewalls
    (r"USG\s*FLEX\s*\d+", "ZyXEL USG FLEX", "firewall", "ZLD"),
    (r"USG\d+", "ZyXEL USG", "firewall", "ZLD"),
    (r"ATP\d+", "ZyXEL ATP", "firewall", "ZLD"),
    (r"VPN\d+", "ZyXEL VPN Firewall", "firewall", "ZLD"),
    (r"ZyWALL\s*\d+", "ZyXEL ZyWALL", "firewall", "ZLD"),
    # Switches
    (r"GS\d{4}", "ZyXEL GS Switch", "switch", "Firmware"),
    (r"XGS\d{4}", "ZyXEL XGS Switch", "switch", "Firmware"),
    (r"XS\d{4}", "ZyXEL XS Switch", "switch", "Firmware"),
    # Access Points
    (r"NWA\d+", "ZyXEL NWA AP", "access_point", "Firmware"),
    (r"WAX\d+", "ZyXEL WAX AP", "access_point", "Firmware"),
    (r"WAC\d+", "ZyXEL WAC AP", "access_point", "Firmware"),
    # Routers
    (r"NBG\d+", "ZyXEL NBG Router", "router", "Firmware"),
    (r"VMG\d+", "ZyXEL VMG Router", "router", "Firmware"),
    (r"LTE\d+", "ZyXEL LTE Router", "router", "Firmware"),
    # Generic
    (r"ZyXEL", "ZyXEL Device", "router", None),
]


# D-LINK DEVICE PATTERNS

DLINK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # D-Link Corporation (IEEE MA-L)
    "00:05:5D": ("network_device", "Network Equipment", "D-Link"),
    "00:0D:88": ("network_device", "Network Equipment", "D-Link"),
    "00:0F:3D": ("network_device", "Network Equipment", "D-Link"),
    "00:11:95": ("network_device", "Network Equipment", "D-Link"),
    "00:13:46": ("network_device", "Network Equipment", "D-Link"),
    "00:15:E9": ("network_device", "Network Equipment", "D-Link"),
    "00:17:9A": ("network_device", "Network Equipment", "D-Link"),
    "00:19:5B": ("network_device", "Network Equipment", "D-Link"),
    "00:1B:11": ("network_device", "Network Equipment", "D-Link"),
    "00:1C:F0": ("network_device", "Network Equipment", "D-Link"),
    "00:1E:58": ("network_device", "Network Equipment", "D-Link"),
    "00:21:91": ("network_device", "Network Equipment", "D-Link"),
    "00:22:B0": ("network_device", "Network Equipment", "D-Link"),
    "00:24:01": ("network_device", "Network Equipment", "D-Link"),
    "00:26:5A": ("network_device", "Network Equipment", "D-Link"),
    "00:50:BA": ("network_device", "Network Equipment", "D-Link"),
    "04:BA:D6": ("network_device", "Network Equipment", "D-Link"),
    "34:02:9C": ("network_device", "Network Equipment", "D-Link"),
    "34:08:04": ("network_device", "Network Equipment", "D-Link"),
    "3C:33:32": ("network_device", "Network Equipment", "D-Link"),
    "40:86:CB": ("network_device", "Network Equipment", "D-Link"),
    "5C:D9:98": ("network_device", "Network Equipment", "D-Link"),
    "64:29:43": ("network_device", "Network Equipment", "D-Link"),
    "88:76:B9": ("network_device", "Network Equipment", "D-Link"),
    "C8:78:7D": ("network_device", "Network Equipment", "D-Link"),
    "D0:32:C3": ("network_device", "Network Equipment", "D-Link"),
    "DC:EA:E7": ("network_device", "Network Equipment", "D-Link"),
    "F0:7D:68": ("network_device", "Network Equipment", "D-Link"),
    # D-Link International (IEEE MA-L)
    "00:AD:24": ("network_device", "Network Equipment", "D-Link"),
    "08:5A:11": ("network_device", "Network Equipment", "D-Link"),
    "0C:0E:76": ("network_device", "Network Equipment", "D-Link"),
    "0C:B6:D2": ("network_device", "Network Equipment", "D-Link"),
    "10:62:EB": ("network_device", "Network Equipment", "D-Link"),
    "10:BE:F5": ("network_device", "Network Equipment", "D-Link"),
    "14:D6:4D": ("network_device", "Network Equipment", "D-Link"),
    "18:0F:76": ("network_device", "Network Equipment", "D-Link"),
    "1C:5F:2B": ("network_device", "Network Equipment", "D-Link"),
    "1C:7E:E5": ("network_device", "Network Equipment", "D-Link"),
    "1C:AF:F7": ("network_device", "Network Equipment", "D-Link"),
    "1C:BD:B9": ("network_device", "Network Equipment", "D-Link"),
    "28:10:7B": ("network_device", "Network Equipment", "D-Link"),
    "28:3B:82": ("network_device", "Network Equipment", "D-Link"),
    "34:0A:33": ("network_device", "Network Equipment", "D-Link"),
    "3C:1E:04": ("network_device", "Network Equipment", "D-Link"),
    "40:9B:CD": ("network_device", "Network Equipment", "D-Link"),
    "48:EE:0C": ("network_device", "Network Equipment", "D-Link"),
    "54:B8:0A": ("network_device", "Network Equipment", "D-Link"),
    "58:D5:6E": ("network_device", "Network Equipment", "D-Link"),
    "60:63:4C": ("network_device", "Network Equipment", "D-Link"),
    "6C:19:8F": ("network_device", "Network Equipment", "D-Link"),
    "6C:72:20": ("network_device", "Network Equipment", "D-Link"),
    "70:62:B8": ("network_device", "Network Equipment", "D-Link"),
    "74:DA:DA": ("network_device", "Network Equipment", "D-Link"),
    "78:32:1B": ("network_device", "Network Equipment", "D-Link"),
    "78:54:2E": ("network_device", "Network Equipment", "D-Link"),
    "78:98:E8": ("network_device", "Network Equipment", "D-Link"),
    "80:26:89": ("network_device", "Network Equipment", "D-Link"),
    "84:C9:B2": ("network_device", "Network Equipment", "D-Link"),
    "90:8D:78": ("network_device", "Network Equipment", "D-Link"),
    "90:94:E4": ("network_device", "Network Equipment", "D-Link"),
    "9C:D6:43": ("network_device", "Network Equipment", "D-Link"),
    "A0:A3:F0": ("network_device", "Network Equipment", "D-Link"),
    "A0:AB:1B": ("network_device", "Network Equipment", "D-Link"),
    "A4:2A:95": ("network_device", "Network Equipment", "D-Link"),
    "A8:63:7D": ("network_device", "Network Equipment", "D-Link"),
    "AC:F1:DF": ("network_device", "Network Equipment", "D-Link"),
    "B0:C5:54": ("network_device", "Network Equipment", "D-Link"),
    "B8:A3:86": ("network_device", "Network Equipment", "D-Link"),
    "BC:0F:9A": ("network_device", "Network Equipment", "D-Link"),
    "BC:22:28": ("network_device", "Network Equipment", "D-Link"),
    "BC:F6:85": ("network_device", "Network Equipment", "D-Link"),
    "C0:A0:BB": ("network_device", "Network Equipment", "D-Link"),
    "C4:12:F5": ("network_device", "Network Equipment", "D-Link"),
    "C4:A8:1D": ("network_device", "Network Equipment", "D-Link"),
    "C4:E9:0A": ("network_device", "Network Equipment", "D-Link"),
    "C8:BE:19": ("network_device", "Network Equipment", "D-Link"),
    "C8:D3:A3": ("network_device", "Network Equipment", "D-Link"),
    "CC:B2:55": ("network_device", "Network Equipment", "D-Link"),
    "D8:FE:E3": ("network_device", "Network Equipment", "D-Link"),
    "E0:1C:FC": ("network_device", "Network Equipment", "D-Link"),
    "E4:6F:13": ("network_device", "Network Equipment", "D-Link"),
    "E8:CC:18": ("network_device", "Network Equipment", "D-Link"),
    "EC:22:80": ("network_device", "Network Equipment", "D-Link"),
    "EC:AD:E0": ("network_device", "Network Equipment", "D-Link"),
    "F0:B4:D2": ("network_device", "Network Equipment", "D-Link"),
    "F4:8C:EB": ("network_device", "Network Equipment", "D-Link"),
    "F8:E9:03": ("network_device", "Network Equipment", "D-Link"),
    "FC:75:16": ("network_device", "Network Equipment", "D-Link"),
}

DLINK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Routers
    (r"DIR-\d+", "D-Link DIR Router", "router", "Firmware"),
    (r"DSR-\d+", "D-Link DSR Router", "router", "Firmware"),
    (r"DWR-\d+", "D-Link DWR Mobile Router", "router", "Firmware"),
    (r"COVR-\d+", "D-Link COVR Mesh", "router", "Firmware"),
    # Switches
    (r"DGS-\d+", "D-Link DGS Switch", "switch", "Firmware"),
    (r"DES-\d+", "D-Link DES Switch", "switch", "Firmware"),
    (r"DXS-\d+", "D-Link DXS Switch", "switch", "Firmware"),
    # Access Points
    (r"DAP-\d+", "D-Link DAP AP", "access_point", "Firmware"),
    (r"DWL-\d+", "D-Link DWL AP", "access_point", "Firmware"),
    # Cameras
    (r"DCS-\d+", "D-Link DCS Camera", "ip_camera", "Firmware"),
    # NAS
    (r"DNS-\d+", "D-Link DNS NAS", "nas", "Firmware"),
    (r"DNR-\d+", "D-Link DNR NVR", "nvr", "Firmware"),
    # Generic
    (r"D-Link", "D-Link Device", "router", None),
]


# LINKSYS DEVICE PATTERNS

LINKSYS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Cisco-Linksys, LLC (IEEE MA-L)
    "00:04:5A": ("network_device", "Network Equipment", "Linksys"),
    "00:06:25": ("network_device", "Network Equipment", "Linksys"),
    "00:0C:41": ("network_device", "Network Equipment", "Linksys"),
    "00:0E:08": ("network_device", "Network Equipment", "Linksys"),
    "00:0F:66": ("network_device", "Network Equipment", "Linksys"),
    "00:12:17": ("network_device", "Network Equipment", "Linksys"),
    "00:13:10": ("network_device", "Network Equipment", "Linksys"),
    "00:14:BF": ("network_device", "Network Equipment", "Linksys"),
    "00:16:B6": ("network_device", "Network Equipment", "Linksys"),
    "00:18:39": ("network_device", "Network Equipment", "Linksys"),
    "00:18:F8": ("network_device", "Network Equipment", "Linksys"),
    "00:1A:70": ("network_device", "Network Equipment", "Linksys"),
    "00:1C:10": ("network_device", "Network Equipment", "Linksys"),
    "00:1D:7E": ("network_device", "Network Equipment", "Linksys"),
    "00:1E:E5": ("network_device", "Network Equipment", "Linksys"),
    "00:21:29": ("network_device", "Network Equipment", "Linksys"),
    "00:22:6B": ("network_device", "Network Equipment", "Linksys"),
    "00:23:69": ("network_device", "Network Equipment", "Linksys"),
    "00:25:9C": ("network_device", "Network Equipment", "Linksys"),
    "20:AA:4B": ("network_device", "Network Equipment", "Linksys"),
    "48:F8:B3": ("network_device", "Network Equipment", "Linksys"),
    "58:6D:8F": ("network_device", "Network Equipment", "Linksys"),
    "68:7F:74": ("network_device", "Network Equipment", "Linksys"),
    "98:FC:11": ("network_device", "Network Equipment", "Linksys"),
    "C0:C1:C0": ("network_device", "Network Equipment", "Linksys"),
    "C8:B3:73": ("network_device", "Network Equipment", "Linksys"),
    "C8:D7:19": ("network_device", "Network Equipment", "Linksys"),
    # Belkin International (IEEE MA-L) — Linksys parent company
    "00:17:3F": ("router", "Network Equipment", "Linksys/Belkin"),
    "00:1C:DF": ("router", "Network Equipment", "Linksys/Belkin"),
    "00:22:75": ("router", "Network Equipment", "Linksys/Belkin"),
    "08:86:3B": ("router", "Network Equipment", "Linksys/Belkin"),
    "14:91:82": ("router", "Network Equipment", "Linksys/Belkin"),
    "24:F5:A2": ("router", "Network Equipment", "Linksys/Belkin"),
    "30:23:03": ("router", "Network Equipment", "Linksys/Belkin"),
    "58:EF:68": ("router", "Network Equipment", "Linksys/Belkin"),
    "60:38:E0": ("router", "Network Equipment", "Linksys/Belkin"),
    "80:69:1A": ("router", "Network Equipment", "Linksys/Belkin"),
    "94:10:3E": ("router", "Network Equipment", "Linksys/Belkin"),
    "94:44:52": ("router", "Network Equipment", "Linksys/Belkin"),
    "B4:75:0E": ("router", "Network Equipment", "Linksys/Belkin"),
    "C0:56:27": ("router", "Network Equipment", "Linksys/Belkin"),
    "C4:41:1E": ("router", "Network Equipment", "Linksys/Belkin"),
    "D8:EC:5E": ("router", "Network Equipment", "Linksys/Belkin"),
    "E8:9F:80": ("router", "Network Equipment", "Linksys/Belkin"),
    "EC:1A:59": ("router", "Network Equipment", "Linksys/Belkin"),
}

LINKSYS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Velop Mesh
    (r"Velop\s*MX\d+", "Linksys Velop MX", "router", "Firmware"),
    (r"Velop\s*MBE\d+", "Linksys Velop MBE", "router", "Firmware"),
    (r"Velop", "Linksys Velop Mesh", "router", "Firmware"),
    # WiFi 6/6E Routers
    (r"MR\d{4}", "Linksys MR Router", "router", "Firmware"),
    (r"MX\d{4}", "Linksys MX Router", "router", "Firmware"),
    # Classic Routers
    (r"WRT\d+", "Linksys WRT Router", "router", "Firmware"),
    (r"EA\d{4}", "Linksys EA Router", "router", "Firmware"),
    (r"E\d{4}", "Linksys E Router", "router", "Firmware"),
    # Range Extenders
    (r"RE\d{4}", "Linksys RE Extender", "range_extender", "Firmware"),
    # Switches
    (r"LGS\d+", "Linksys LGS Switch", "switch", "Firmware"),
    # Generic
    (r"Linksys", "Linksys Device", "router", None),
]


# CISCO MERAKI DEVICE PATTERNS

MERAKI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Core Meraki OUIs (registered under Cisco Meraki / Cisco Systems)
    "00:18:0A": ("access_point", "Network Equipment", "Meraki"),
    "00:84:1E": ("network_device", "Network Equipment", "Meraki"),
    "08:6A:0B": ("network_device", "Network Equipment", "Meraki"),
    "08:71:1C": ("network_device", "Network Equipment", "Meraki"),
    "08:F1:B3": ("network_device", "Network Equipment", "Meraki"),
    "0C:7B:C8": ("network_device", "Network Equipment", "Meraki"),
    "0C:8D:DB": ("access_point", "Network Equipment", "Meraki"),
    "14:9F:43": ("network_device", "Network Equipment", "Meraki"),
    "2C:3F:0B": ("network_device", "Network Equipment", "Meraki"),
    "30:3B:49": ("network_device", "Network Equipment", "Meraki"),
    "34:56:FE": ("access_point", "Network Equipment", "Meraki"),
    "38:84:79": ("network_device", "Network Equipment", "Meraki"),
    "40:27:A8": ("network_device", "Network Equipment", "Meraki"),
    "4C:C8:A1": ("network_device", "Network Equipment", "Meraki"),
    "5C:06:10": ("network_device", "Network Equipment", "Meraki"),
    "68:3A:1E": ("access_point", "Network Equipment", "Meraki"),
    "68:49:92": ("network_device", "Network Equipment", "Meraki"),
    "88:15:44": ("access_point", "Network Equipment", "Meraki"),
    "98:18:88": ("network_device", "Network Equipment", "Meraki"),
    "AC:17:C8": ("access_point", "Network Equipment", "Meraki"),
    "B8:07:56": ("network_device", "Network Equipment", "Meraki"),
    "CC:03:D9": ("network_device", "Network Equipment", "Meraki"),
    "E0:55:3D": ("access_point", "Network Equipment", "Meraki"),
    "E0:CB:BC": ("access_point", "Network Equipment", "Meraki"),
    "F8:9E:28": ("network_device", "Network Equipment", "Meraki"),
}

MERAKI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Access Points
    (r"MR\d{2,3}", "Meraki MR Access Point", "access_point", "Meraki Dashboard"),
    (r"MR\s*\d{2}", "Meraki MR Access Point", "access_point", "Meraki Dashboard"),
    # Switches
    (r"MS\d{2,3}", "Meraki MS Switch", "switch", "Meraki Dashboard"),
    (r"MS\s*\d{2}", "Meraki MS Switch", "switch", "Meraki Dashboard"),
    # Security Appliances
    (r"MX\d{2,3}", "Meraki MX Security Appliance", "firewall", "Meraki Dashboard"),
    (r"MX\s*\d{2}", "Meraki MX Security Appliance", "firewall", "Meraki Dashboard"),
    (r"Z\d", "Meraki Z Teleworker", "router", "Meraki Dashboard"),
    # Cameras
    (r"MV\d{2}", "Meraki MV Camera", "ip_camera", "Meraki Dashboard"),
    # Sensors
    (r"MT\d{2}", "Meraki MT Sensor", "sensor", "Meraki Dashboard"),
    # Mobile Device Manager - use full name to avoid matching "SM" in "Samsung"
    (r"Meraki\s*Systems?\s*Manager", "Meraki Systems Manager", "mdm", "Meraki Dashboard"),
    (r"Meraki\s*SM(?:\s|$)", "Meraki Systems Manager", "mdm", "Meraki Dashboard"),
    # Generic
    (r"Meraki", "Cisco Meraki Device", "access_point", "Meraki Dashboard"),
]


# BUFFALO DEVICE PATTERNS

BUFFALO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:07:40": ("network_device", "Network Equipment", "Buffalo"),
    "00:0D:0B": ("network_device", "Network Equipment", "Buffalo"),
    "00:16:01": ("network_device", "Network Equipment", "Buffalo"),
    "00:1D:73": ("network_device", "Network Equipment", "Buffalo"),
    "00:24:A5": ("network_device", "Network Equipment", "Buffalo"),
    "10:6F:3F": ("network_device", "Network Equipment", "Buffalo"),
    "4C:E6:76": ("network_device", "Network Equipment", "Buffalo"),
    "74:03:BD": ("network_device", "Network Equipment", "Buffalo"),
    "84:AF:EC": ("network_device", "Network Equipment", "Buffalo"),
    "B0:C7:45": ("network_device", "Network Equipment", "Buffalo"),
    "DC:FB:02": ("network_device", "Network Equipment", "Buffalo"),
}

BUFFALO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Routers
    (r"WXR-\d+", "Buffalo WXR Router", "router", "DD-WRT"),
    (r"WSR-\d+", "Buffalo WSR Router", "router", "Firmware"),
    (r"WZR-\d+", "Buffalo WZR Router", "router", "DD-WRT"),
    (r"WHR-\d+", "Buffalo WHR Router", "router", "Firmware"),
    # NAS
    (r"LinkStation", "Buffalo LinkStation", "nas", "Firmware"),
    (r"TeraStation", "Buffalo TeraStation", "nas", "Firmware"),
    (r"LS\d{3}", "Buffalo LinkStation", "nas", "Firmware"),
    (r"TS\d{4}", "Buffalo TeraStation", "nas", "Firmware"),
    # Generic
    (r"Buffalo", "Buffalo Device", "router", None),
]


# MIMOSA DEVICE PATTERNS

MIMOSA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "58:C1:7A": ("wireless_bridge", "Network Equipment", "Mimosa"),
}

MIMOSA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"B5c", "Mimosa B5c", "wireless_bridge", "Mimosa Firmware"),
    (r"B5", "Mimosa B5", "wireless_bridge", "Mimosa Firmware"),
    (r"B11", "Mimosa B11", "wireless_bridge", "Mimosa Firmware"),
    (r"B24", "Mimosa B24", "wireless_bridge", "Mimosa Firmware"),
    (r"C5c", "Mimosa C5c", "cpe", "Mimosa Firmware"),
    (r"C5x", "Mimosa C5x", "cpe", "Mimosa Firmware"),
    (r"C5", "Mimosa C5", "cpe", "Mimosa Firmware"),
    (r"A5c", "Mimosa A5c", "access_point", "Mimosa Firmware"),
    (r"A5x", "Mimosa A5x", "access_point", "Mimosa Firmware"),
    (r"A5", "Mimosa A5", "access_point", "Mimosa Firmware"),
    (r"Mimosa", "Mimosa Device", "wireless_bridge", None),
]


# CRADLEPOINT DEVICE PATTERNS

CRADLEPOINT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:30:44": ("router", "Network Equipment", "Cradlepoint"),
}

CRADLEPOINT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # E-Series
    (r"E3000", "Cradlepoint E3000", "router", "NetCloud"),
    (r"E300", "Cradlepoint E300", "router", "NetCloud"),
    (r"E100", "Cradlepoint E100", "router", "NetCloud"),
    # R-Series
    (r"R1900", "Cradlepoint R1900", "router", "NetCloud"),
    (r"R920", "Cradlepoint R920", "router", "NetCloud"),
    # IBR Series
    (r"IBR\d+", "Cradlepoint IBR", "router", "NetCloud"),
    # CBA Series
    (r"CBA\d+", "Cradlepoint CBA", "router", "NetCloud"),
    # AER Series
    (r"AER\d+", "Cradlepoint AER", "router", "NetCloud"),
    # Generic
    (r"Cradlepoint", "Cradlepoint Router", "router", "NetCloud"),
]


# ENGENIUS DEVICE PATTERNS

ENGENIUS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:02:6F": ("access_point", "Network Equipment", "EnGenius"),
    "88:DC:96": ("access_point", "Network Equipment", "EnGenius"),
    # Note: 9C:D6:43 is D-Link International per IEEE - removed from EnGenius
}

ENGENIUS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Cloud Managed
    (r"ECW\d+", "EnGenius ECW Cloud AP", "access_point", "EnGenius Cloud"),
    (r"ECS\d+", "EnGenius ECS Cloud Switch", "switch", "EnGenius Cloud"),
    # Access Points
    (r"EWS\d+", "EnGenius EWS AP", "access_point", "Firmware"),
    (r"ENS\d+", "EnGenius ENS Outdoor AP", "access_point", "Firmware"),
    (r"EAP\d+", "EnGenius EAP AP", "access_point", "Firmware"),
    # Switches
    (r"EGS\d+", "EnGenius EGS Switch", "switch", "Firmware"),
    # Bridges
    (r"ENH\d+", "EnGenius ENH Bridge", "wireless_bridge", "Firmware"),
    (r"EnStation", "EnGenius EnStation", "cpe", "Firmware"),
    # Generic
    (r"EnGenius", "EnGenius Device", "access_point", None),
]


# AEROHIVE / EXTREME DEVICE PATTERNS

AEROHIVE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:19:77": ("access_point", "Network Equipment", "Aerohive"),
    "08:EA:44": ("access_point", "Network Equipment", "Aerohive"),
    "40:18:B1": ("access_point", "Network Equipment", "Aerohive"),
    "88:5B:DD": ("access_point", "Network Equipment", "Aerohive"),
    "E0:1C:41": ("access_point", "Network Equipment", "Aerohive"),
}

AEROHIVE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Access Points
    (r"AP\d{3}", "Aerohive AP", "access_point", "HiveOS"),
    (r"AP\d{4}", "Aerohive AP", "access_point", "HiveOS"),
    (r"AP\s*\d{3}", "Aerohive AP", "access_point", "HiveOS"),
    # Switches
    (r"SR\d{4}", "Aerohive SR Switch", "switch", "HiveOS"),
    # Routers
    (r"BR\d{3}", "Aerohive BR Router", "router", "HiveOS"),
    # Generic
    (r"Aerohive", "Aerohive Device", "access_point", "HiveOS"),
    (r"HiveOS", "Aerohive Device", "access_point", "HiveOS"),
]


# UBIQUITI DEVICE PATTERNS

# Ubiquiti MAC OUI prefixes and their typical device types
# Format: "XX:XX:XX" -> (device_type, device_category, model_hint)
UBIQUITI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # UniFi Switches - comprehensive list
    # These OUIs are used for UniFi Switch product line
    "70:A7:41": ("network_device", "Network Equipment", "Ubiquiti"),  # Shared OUI: switches AND APs (e.g. U6 In-Wall)
    "74:83:C2": ("switch", "Network Equipment", "UniFi Switch"),
    "FC:EC:DA": ("switch", "Network Equipment", "UniFi Switch"),
    "78:8A:20": ("switch", "Network Equipment", "UniFi Switch"),
    "74:AC:B9": ("switch", "Network Equipment", "UniFi Switch"),  # Also used for switches

    # UniFi Access Points
    "80:2A:A8": ("access_point", "Network Equipment", "UniFi AP"),
    "F0:9F:C2": ("access_point", "Network Equipment", "UniFi AP"),
    "18:E8:29": ("access_point", "Network Equipment", "UniFi AP"),
    "68:D7:9A": ("access_point", "Network Equipment", "UniFi AP"),
    "24:5A:4C": ("access_point", "Network Equipment", "UniFi AP"),
    "44:D9:E7": ("access_point", "Network Equipment", "UniFi AP"),
    "DC:9F:DB": ("access_point", "Network Equipment", "UniFi AP"),
    "E0:63:DA": ("network_device", "Network Equipment", "Ubiquiti"),  # Shared OUI: APs, cameras, doorbells
    "04:18:D6": ("access_point", "Network Equipment", "UniFi AP"),
    "9C:05:D6": ("access_point", "Network Equipment", "UniFi AP"),  # U6 series
    "E8:78:29": ("access_point", "Network Equipment", "UniFi AP"),
    "AC:8B:A9": ("access_point", "Network Equipment", "UniFi AP"),

    # EdgeRouter / EdgeSwitch (UBNT legacy product line)
    "24:A4:3C": ("router", "Network Equipment", "EdgeRouter"),
    "00:15:6D": ("network_device", "Network Equipment", "Ubiquiti"),  # Legacy UBNT OUI

    # UniFi Security Gateway / Dream Machine / Cloud Gateway
    "78:45:58": ("router", "Network Equipment", "UniFi Dream Machine"),
    "F4:92:BF": ("router", "Network Equipment", "UniFi Dream Machine Pro"),
    "B4:FB:E4": ("router", "Network Equipment", "UniFi Dream Machine"),

    # UniFi Protect Cameras / NVR
    "E4:38:83": ("ip_camera", "Surveillance", "UniFi Protect Camera"),
    "68:72:51": ("ip_camera", "Surveillance", "UniFi Protect Camera"),

    # AirMax / AirFiber (wireless bridges)
    "00:27:22": ("wireless_bridge", "Network Equipment", "AirMax"),

    # Additional IEEE-registered Ubiquiti OUIs
    "0C:EA:14": ("network_device", "Network Equipment", "Ubiquiti"),
    "1C:0B:8B": ("network_device", "Network Equipment", "Ubiquiti"),
    "1C:6A:1B": ("network_device", "Network Equipment", "Ubiquiti"),
    "28:70:4E": ("network_device", "Network Equipment", "Ubiquiti"),
    "58:D6:1F": ("network_device", "Network Equipment", "Ubiquiti"),
    "60:22:32": ("network_device", "Network Equipment", "Ubiquiti"),
    "6C:63:F8": ("network_device", "Network Equipment", "Ubiquiti"),
    "74:F9:2C": ("network_device", "Network Equipment", "Ubiquiti"),
    "74:FA:29": ("network_device", "Network Equipment", "Ubiquiti"),
    "84:78:48": ("network_device", "Network Equipment", "Ubiquiti"),
    "8C:30:66": ("network_device", "Network Equipment", "Ubiquiti"),
    "8C:ED:E1": ("network_device", "Network Equipment", "Ubiquiti"),
    "90:41:B2": ("network_device", "Network Equipment", "Ubiquiti"),
    "94:2A:6F": ("network_device", "Network Equipment", "Ubiquiti"),
    "A4:F8:FF": ("network_device", "Network Equipment", "Ubiquiti"),
    "A8:9C:6C": ("network_device", "Network Equipment", "Ubiquiti"),
    "CC:35:D9": ("network_device", "Network Equipment", "Ubiquiti"),
    "D0:21:F9": ("network_device", "Network Equipment", "Ubiquiti"),
    "D4:89:C1": ("network_device", "Network Equipment", "Ubiquiti"),
    "D8:B3:70": ("network_device", "Network Equipment", "Ubiquiti"),
    "F4:E2:C6": ("network_device", "Network Equipment", "Ubiquiti"),
}

# Ubiquiti model detection patterns from service banners
# Format: (regex, model_name, device_type, firmware_hint)
UBIQUITI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # UniFi Switches - US series
    (r"US-8-150W", "UniFi Switch 8 PoE (150W)", "switch", "UniFi OS"),
    (r"US-8-60W", "UniFi Switch 8 PoE (60W)", "switch", "UniFi OS"),
    (r"US-8", "UniFi Switch 8", "switch", "UniFi OS"),
    (r"US-16-150W", "UniFi Switch 16 PoE (150W)", "switch", "UniFi OS"),
    (r"US-24-250W", "UniFi Switch 24 PoE (250W)", "switch", "UniFi OS"),
    (r"US-24-500W", "UniFi Switch 24 PoE (500W)", "switch", "UniFi OS"),
    (r"US-24", "UniFi Switch 24", "switch", "UniFi OS"),
    (r"US-48-500W", "UniFi Switch 48 PoE (500W)", "switch", "UniFi OS"),
    (r"US-48-750W", "UniFi Switch 48 PoE (750W)", "switch", "UniFi OS"),
    (r"US-48", "UniFi Switch 48", "switch", "UniFi OS"),

    # UniFi Switches - USW series (newer)
    (r"USW-Flex-Mini", "UniFi Switch Flex Mini", "switch", "UniFi OS"),
    (r"USW-Flex-XG", "UniFi Switch Flex XG", "switch", "UniFi OS"),
    (r"USW-Flex", "UniFi Switch Flex", "switch", "UniFi OS"),
    (r"USW-Lite-8-PoE", "UniFi Switch Lite 8 PoE", "switch", "UniFi OS"),
    (r"USW-Lite-16-PoE", "UniFi Switch Lite 16 PoE", "switch", "UniFi OS"),
    (r"USW-Pro-24-PoE", "UniFi Switch Pro 24 PoE", "switch", "UniFi OS"),
    (r"USW-Pro-48-PoE", "UniFi Switch Pro 48 PoE", "switch", "UniFi OS"),
    (r"USW-Pro-24", "UniFi Switch Pro 24", "switch", "UniFi OS"),
    (r"USW-Pro-48", "UniFi Switch Pro 48", "switch", "UniFi OS"),
    (r"USW-Enterprise-8-PoE", "UniFi Switch Enterprise 8 PoE", "switch", "UniFi OS"),
    (r"USW-Enterprise-24-PoE", "UniFi Switch Enterprise 24 PoE", "switch", "UniFi OS"),
    (r"USW-Enterprise-48-PoE", "UniFi Switch Enterprise 48 PoE", "switch", "UniFi OS"),
    (r"USW-Aggregation", "UniFi Switch Aggregation", "switch", "UniFi OS"),
    (r"USW-Industrial", "UniFi Switch Industrial", "switch", "UniFi OS"),
    (r"USW-Mission-Critical", "UniFi Switch Mission Critical", "switch", "UniFi OS"),

    # UniFi Access Points - UAP series
    (r"UAP-AC-Pro", "UniFi AP AC Pro", "access_point", "UniFi OS"),
    (r"UAP-AC-Lite", "UniFi AP AC Lite", "access_point", "UniFi OS"),
    (r"UAP-AC-LR", "UniFi AP AC Long Range", "access_point", "UniFi OS"),
    (r"UAP-AC-HD", "UniFi AP AC HD", "access_point", "UniFi OS"),
    (r"UAP-AC-SHD", "UniFi AP AC SHD", "access_point", "UniFi OS"),
    (r"UAP-AC-EDU", "UniFi AP AC EDU", "access_point", "UniFi OS"),
    (r"UAP-AC-IW", "UniFi AP AC In-Wall", "access_point", "UniFi OS"),
    (r"UAP-AC-M-Pro", "UniFi AP AC Mesh Pro", "access_point", "UniFi OS"),
    (r"UAP-AC-M", "UniFi AP AC Mesh", "access_point", "UniFi OS"),
    (r"UAP-IW-HD", "UniFi AP In-Wall HD", "access_point", "UniFi OS"),
    (r"UAP-FlexHD", "UniFi FlexHD", "access_point", "UniFi OS"),
    (r"UAP-nanoHD", "UniFi nanoHD", "access_point", "UniFi OS"),
    (r"UAP-BeaconHD", "UniFi BeaconHD", "access_point", "UniFi OS"),

    # UniFi Access Points - U6/U7 series (WiFi 6/6E/7)
    (r"U6-Pro", "UniFi 6 Pro", "access_point", "UniFi OS"),
    (r"U6-Lite", "UniFi 6 Lite", "access_point", "UniFi OS"),
    (r"U6-LR", "UniFi 6 Long Range", "access_point", "UniFi OS"),
    (r"U6-Enterprise", "UniFi 6 Enterprise", "access_point", "UniFi OS"),
    (r"U6-Mesh", "UniFi 6 Mesh", "access_point", "UniFi OS"),
    (r"U6-IW", "UniFi 6 In-Wall", "access_point", "UniFi OS"),
    (r"U6-Extender", "UniFi 6 Extender", "access_point", "UniFi OS"),
    (r"U6\+", "UniFi 6+", "access_point", "UniFi OS"),
    (r"U6-Enterprise-IW", "UniFi 6 Enterprise In-Wall", "access_point", "UniFi OS"),
    (r"U7-Pro-Max", "UniFi 7 Pro Max", "access_point", "UniFi OS"),
    (r"U7-Pro-Wall", "UniFi 7 Pro Wall", "access_point", "UniFi OS"),
    (r"U7-Pro", "UniFi 7 Pro", "access_point", "UniFi OS"),
    (r"U7-Outdoor", "UniFi 7 Outdoor", "access_point", "UniFi OS"),

    # UniFi Building Bridge
    (r"UBB", "UniFi Building Bridge", "wireless_bridge", "UniFi OS"),

    # UniFi Gateways
    (r"USG-Pro-4", "UniFi Security Gateway Pro 4", "router", "UniFi OS"),
    (r"USG-XG-8", "UniFi Security Gateway XG-8", "router", "UniFi OS"),
    (r"USG-3P", "UniFi Security Gateway 3P", "router", "UniFi OS"),
    (r"USG", "UniFi Security Gateway", "router", "UniFi OS"),
    (r"UDM-Pro-Max", "UniFi Dream Machine Pro Max", "router", "UniFi OS"),
    (r"UDM-Pro-SE", "UniFi Dream Machine Pro SE", "router", "UniFi OS"),
    (r"UDM-Pro", "UniFi Dream Machine Pro", "router", "UniFi OS"),
    (r"UDM-SE", "UniFi Dream Machine SE", "router", "UniFi OS"),
    (r"UDM", "UniFi Dream Machine", "router", "UniFi OS"),
    (r"UDR", "UniFi Dream Router", "router", "UniFi OS"),
    (r"UXG-Pro", "UniFi Next-Gen Gateway Pro", "router", "UniFi OS"),
    (r"UXG-Max", "UniFi Express Gateway Max", "router", "UniFi OS"),
    (r"UX", "UniFi Express", "router", "UniFi OS"),
    (r"UCG-Ultra", "UniFi Cloud Gateway Ultra", "router", "UniFi OS"),
    (r"Cloud Key Gen2 Plus", "UniFi Cloud Key Gen2 Plus", "controller", "UniFi OS"),
    (r"Cloud Key Gen2", "UniFi Cloud Key Gen2", "controller", "UniFi OS"),
    (r"Cloud Key", "UniFi Cloud Key", "controller", "UniFi OS"),

    # UniFi Protect Cameras
    (r"UVC-G4-Pro", "UniFi Protect G4 Pro", "ip_camera", "UniFi Protect"),
    (r"UVC-G4-Bullet", "UniFi Protect G4 Bullet", "ip_camera", "UniFi Protect"),
    (r"UVC-G4-Dome", "UniFi Protect G4 Dome", "ip_camera", "UniFi Protect"),
    (r"UVC-G4-PTZ", "UniFi Protect G4 PTZ", "ip_camera", "UniFi Protect"),
    (r"UVC-G4-Doorbell", "UniFi Protect G4 Doorbell", "doorbell", "UniFi Protect"),
    (r"UVC-G3-Flex", "UniFi Protect G3 Flex", "ip_camera", "UniFi Protect"),
    (r"UVC-G3-Bullet", "UniFi Protect G3 Bullet", "ip_camera", "UniFi Protect"),
    (r"UVC-G3-Dome", "UniFi Protect G3 Dome", "ip_camera", "UniFi Protect"),
    (r"UVC-AI-Pro", "UniFi AI Pro", "ip_camera", "UniFi Protect"),
    (r"UVC-AI-Bullet", "UniFi AI Bullet", "ip_camera", "UniFi Protect"),
    (r"UVC-AI-360", "UniFi AI 360", "ip_camera", "UniFi Protect"),
    (r"UNVR-Pro", "UniFi Protect UNVR Pro", "nvr", "UniFi Protect"),
    (r"UNVR", "UniFi Protect UNVR", "nvr", "UniFi Protect"),

    # EdgeRouter series
    (r"EdgeRouter-X-SFP", "EdgeRouter X SFP", "router", "EdgeOS"),
    (r"EdgeRouter-X", "EdgeRouter X", "router", "EdgeOS"),
    (r"EdgeRouter-4", "EdgeRouter 4", "router", "EdgeOS"),
    (r"EdgeRouter-6P", "EdgeRouter 6P", "router", "EdgeOS"),
    (r"EdgeRouter-12", "EdgeRouter 12", "router", "EdgeOS"),
    (r"EdgeRouter-12P", "EdgeRouter 12P", "router", "EdgeOS"),
    (r"EdgeRouter-Infinity", "EdgeRouter Infinity", "router", "EdgeOS"),
    (r"EdgeRouter-Pro", "EdgeRouter Pro", "router", "EdgeOS"),
    (r"EdgeRouter-Lite", "EdgeRouter Lite", "router", "EdgeOS"),
    (r"EdgeRouter", "EdgeRouter", "router", "EdgeOS"),

    # EdgeSwitch series
    (r"EdgeSwitch-48-750W", "EdgeSwitch 48 PoE (750W)", "switch", "EdgeSwitch OS"),
    (r"EdgeSwitch-48-500W", "EdgeSwitch 48 PoE (500W)", "switch", "EdgeSwitch OS"),
    (r"EdgeSwitch-24-500W", "EdgeSwitch 24 PoE (500W)", "switch", "EdgeSwitch OS"),
    (r"EdgeSwitch-24-250W", "EdgeSwitch 24 PoE (250W)", "switch", "EdgeSwitch OS"),
    (r"EdgeSwitch-16-150W", "EdgeSwitch 16 PoE (150W)", "switch", "EdgeSwitch OS"),
    (r"EdgeSwitch-8-150W", "EdgeSwitch 8 PoE (150W)", "switch", "EdgeSwitch OS"),
    (r"EdgeSwitch", "EdgeSwitch", "switch", "EdgeSwitch OS"),

    # AirMax / AirFiber
    (r"airFiber-60", "airFiber 60", "wireless_bridge", "AirOS"),
    (r"airFiber-5XHD", "airFiber 5XHD", "wireless_bridge", "AirOS"),
    (r"airFiber-5X", "airFiber 5X", "wireless_bridge", "AirOS"),
    (r"airFiber-24HD", "airFiber 24HD", "wireless_bridge", "AirOS"),
    (r"airFiber", "airFiber", "wireless_bridge", "AirOS"),
    (r"PowerBeam-5AC-Gen2", "PowerBeam 5AC Gen2", "wireless_bridge", "AirOS"),
    (r"PowerBeam", "PowerBeam", "wireless_bridge", "AirOS"),
    (r"NanoBeam-5AC-Gen2", "NanoBeam 5AC Gen2", "wireless_bridge", "AirOS"),
    (r"NanoBeam", "NanoBeam", "wireless_bridge", "AirOS"),
    (r"LiteBeam-5AC-Gen2", "LiteBeam 5AC Gen2", "wireless_bridge", "AirOS"),
    (r"LiteBeam", "LiteBeam", "wireless_bridge", "AirOS"),
    (r"NanoStation-5AC", "NanoStation 5AC", "wireless_bridge", "AirOS"),
    (r"NanoStation", "NanoStation", "wireless_bridge", "AirOS"),
    (r"LiteAP-GPS", "LiteAP GPS", "access_point", "AirOS"),
    (r"LiteAP", "LiteAP", "access_point", "AirOS"),
    (r"Rocket-5AC", "Rocket 5AC", "wireless_bridge", "AirOS"),
    (r"Rocket", "Rocket", "wireless_bridge", "AirOS"),

    # Generic patterns
    (r"UniFi[\s-]*OS\s*([\d.]+)?", "UniFi Device", "network_device", "UniFi OS"),
    (r"EdgeOS\s*([\d.]+)?", "Edge Device", "router", "EdgeOS"),
    (r"AirOS\s*([\d.]+)?", "AirMax Device", "wireless_bridge", "AirOS"),
]

# Port signatures for Ubiquiti devices
# Format: port -> (service_hint, device_type_hint)
UBIQUITI_PORT_SIGNATURES: Dict[int, Tuple[str, str]] = {
    22: ("SSH", None),  # Standard SSH
    80: ("HTTP", None),  # Web interface
    443: ("HTTPS", None),  # Secure web interface
    8443: ("UniFi Controller", "controller"),  # UniFi Network Controller
    8080: ("UniFi Inform", "access_point"),  # Device inform URL
    8880: ("UniFi HTTP Redirect", None),  # HTTP redirect
    8843: ("UniFi HTTPS Redirect", None),  # HTTPS redirect
    6789: ("UniFi Speed Test", None),  # Speed test
    10001: ("UniFi Discovery", None),  # Device discovery (UDP)
    3478: ("UniFi STUN", None),  # STUN service
    5514: ("UniFi Syslog", None),  # Remote syslog
    7080: ("UniFi Protect", "nvr"),  # Protect NVR
    7443: ("UniFi Protect HTTPS", "nvr"),  # Protect NVR HTTPS
    7444: ("UniFi Protect RTSPS", "nvr"),  # Protect RTSPS
    7447: ("UniFi Protect RTSP", "nvr"),  # Protect RTSP
}


# MIKROTIK DEVICE PATTERNS

MIKROTIK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0C:42": ("router", "Network Equipment", "MikroTik"),
    "04:F4:1C": ("network_device", "Network Equipment", "MikroTik"),
    "08:55:31": ("network_device", "Network Equipment", "MikroTik"),
    "18:FD:74": ("network_device", "Network Equipment", "MikroTik"),
    "2C:C8:1B": ("router", "Network Equipment", "MikroTik"),
    "48:8F:5A": ("router", "Network Equipment", "MikroTik"),
    "48:A9:8A": ("network_device", "Network Equipment", "MikroTik"),
    "4C:5E:0C": ("router", "Network Equipment", "MikroTik"),
    "64:D1:54": ("router", "Network Equipment", "MikroTik"),
    "6C:3B:6B": ("router", "Network Equipment", "MikroTik"),
    "74:4D:28": ("router", "Network Equipment", "MikroTik"),
    "78:9A:18": ("network_device", "Network Equipment", "MikroTik"),
    "B8:69:F4": ("router", "Network Equipment", "MikroTik"),
    "C4:AD:34": ("router", "Network Equipment", "MikroTik"),
    "CC:2D:E0": ("router", "Network Equipment", "MikroTik"),
    "D0:EA:11": ("network_device", "Network Equipment", "MikroTik"),
    "D4:01:C3": ("router", "Network Equipment", "MikroTik"),
    "D4:CA:6D": ("router", "Network Equipment", "MikroTik"),
    "DC:2C:6E": ("router", "Network Equipment", "MikroTik"),
    "E4:8D:8C": ("router", "Network Equipment", "MikroTik"),
    "F4:1E:57": ("network_device", "Network Equipment", "MikroTik"),
}

MIKROTIK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"hAP\s*ac", "hAP ac", "router", "RouterOS"),
    (r"hAP\s*lite", "hAP lite", "router", "RouterOS"),
    (r"hAP\s*mini", "hAP mini", "router", "RouterOS"),
    (r"hAP", "hAP", "router", "RouterOS"),
    (r"hEX\s*S", "hEX S", "router", "RouterOS"),
    (r"hEX\s*lite", "hEX lite", "router", "RouterOS"),
    (r"hEX\s*PoE", "hEX PoE", "router", "RouterOS"),
    (r"hEX", "hEX", "router", "RouterOS"),
    (r"RB750", "RB750", "router", "RouterOS"),
    (r"RB951", "RB951", "router", "RouterOS"),
    (r"RB1100", "RB1100", "router", "RouterOS"),
    (r"RB2011", "RB2011", "router", "RouterOS"),
    (r"RB3011", "RB3011", "router", "RouterOS"),
    (r"RB4011", "RB4011", "router", "RouterOS"),
    (r"CCR1009", "CCR1009", "router", "RouterOS"),
    (r"CCR1016", "CCR1016", "router", "RouterOS"),
    (r"CCR1036", "CCR1036", "router", "RouterOS"),
    (r"CCR1072", "CCR1072", "router", "RouterOS"),
    (r"CCR2004", "CCR2004", "router", "RouterOS"),
    (r"CCR2116", "CCR2116", "router", "RouterOS"),
    (r"CCR2216", "CCR2216", "router", "RouterOS"),
    (r"CRS309", "CRS309", "switch", "RouterOS"),
    (r"CRS312", "CRS312", "switch", "RouterOS"),
    (r"CRS317", "CRS317", "switch", "RouterOS"),
    (r"CRS326", "CRS326", "switch", "RouterOS"),
    (r"CRS328", "CRS328", "switch", "RouterOS"),
    (r"CRS354", "CRS354", "switch", "RouterOS"),
    (r"CRS504", "CRS504", "switch", "RouterOS"),
    (r"CRS518", "CRS518", "switch", "RouterOS"),
    (r"CSS610", "CSS610", "switch", "SwOS"),
    (r"CSS326", "CSS326", "switch", "SwOS"),
    (r"wAP\s*ac", "wAP ac", "access_point", "RouterOS"),
    (r"wAP", "wAP", "access_point", "RouterOS"),
    (r"cAP\s*ac", "cAP ac", "access_point", "RouterOS"),
    (r"cAP", "cAP", "access_point", "RouterOS"),
    (r"Audience", "Audience", "access_point", "RouterOS"),
    (r"SXTsq", "SXTsq", "wireless_bridge", "RouterOS"),
    (r"LHG", "LHG", "wireless_bridge", "RouterOS"),
    (r"SXT", "SXT", "wireless_bridge", "RouterOS"),
    (r"mANTBox", "mANTBox", "wireless_bridge", "RouterOS"),
    (r"NetMetal", "NetMetal", "wireless_bridge", "RouterOS"),
    (r"NetBox", "NetBox", "wireless_bridge", "RouterOS"),
    (r"RouterOS\s*([\d.]+)?", "MikroTik Router", "router", "RouterOS"),
    (r"SwOS\s*([\d.]+)?", "MikroTik Switch", "switch", "SwOS"),
]


# CISCO DEVICE PATTERNS

CISCO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Cisco foundational OUI (oldest, used across many product lines)
    "00:00:0C": ("network_device", "Network Equipment", "Cisco"),

    # Cisco Catalyst Switches
    "00:1A:2F": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:1B:54": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:1C:0E": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:21:55": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:22:55": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:23:04": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:24:C4": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:25:45": ("switch", "Network Equipment", "Cisco Catalyst"),
    "00:26:0B": ("switch", "Network Equipment", "Cisco Catalyst"),
    "34:62:88": ("switch", "Network Equipment", "Cisco Catalyst"),
    "58:97:BD": ("switch", "Network Equipment", "Cisco Catalyst"),
    "6C:41:6A": ("switch", "Network Equipment", "Cisco Catalyst"),
    "B0:AA:77": ("switch", "Network Equipment", "Cisco Catalyst"),
    "F0:29:29": ("switch", "Network Equipment", "Cisco Catalyst"),

    # Cisco Nexus Switches
    "88:1D:FC": ("switch", "Network Equipment", "Cisco Nexus"),

    # Cisco Routers (ISR/ASR)
    "00:1A:A1": ("router", "Network Equipment", "Cisco Router"),
    "00:1B:0D": ("router", "Network Equipment", "Cisco Router"),
    "00:1E:BD": ("router", "Network Equipment", "Cisco Router"),
    "00:1F:6C": ("router", "Network Equipment", "Cisco Router"),
    "00:1F:9E": ("router", "Network Equipment", "Cisco Router"),
    "00:21:D7": ("router", "Network Equipment", "Cisco Router"),
    "00:22:0D": ("router", "Network Equipment", "Cisco Router"),
    "00:22:BD": ("router", "Network Equipment", "Cisco Router"),
    "00:26:CB": ("router", "Network Equipment", "Cisco Router"),
    "70:D3:79": ("router", "Network Equipment", "Cisco Router"),

    # Cisco Aironet APs
    "00:0B:85": ("access_point", "Network Equipment", "Cisco Aironet"),
    "00:14:1B": ("access_point", "Network Equipment", "Cisco Aironet"),
    "00:1C:57": ("access_point", "Network Equipment", "Cisco Aironet"),
    "00:21:1B": ("access_point", "Network Equipment", "Cisco Aironet"),
    "00:24:13": ("access_point", "Network Equipment", "Cisco Aironet"),

    # Cisco ASA / Firepower Firewalls
    "50:87:89": ("firewall", "Network Equipment", "Cisco ASA"),
    "58:8D:09": ("firewall", "Network Equipment", "Cisco ASA"),
    "64:F6:9D": ("firewall", "Network Equipment", "Cisco ASA"),

    # Cisco IP Phones
    "00:1E:F7": ("voip_phone", "Communication", "Cisco IP Phone"),
    "00:21:A0": ("voip_phone", "Communication", "Cisco IP Phone"),
    "00:26:99": ("voip_phone", "Communication", "Cisco IP Phone"),
    "E4:C7:22": ("voip_phone", "Communication", "Cisco IP Phone"),

    # Cisco WLC (Wireless LAN Controllers)
    "44:AD:D9": ("controller", "Network Equipment", "Cisco WLC"),

    # Additional common Cisco OUIs (verified IEEE registrations)
    "04:62:73": ("network_device", "Network Equipment", "Cisco"),
    "0C:75:BD": ("network_device", "Network Equipment", "Cisco"),
    "18:33:9D": ("network_device", "Network Equipment", "Cisco"),
    "1C:DE:A7": ("network_device", "Network Equipment", "Cisco"),
    "28:6F:7F": ("network_device", "Network Equipment", "Cisco"),
    "3C:08:F6": ("network_device", "Network Equipment", "Cisco"),
    "54:A2:74": ("network_device", "Network Equipment", "Cisco"),
    "5C:83:8F": ("network_device", "Network Equipment", "Cisco"),
    "8C:60:4F": ("network_device", "Network Equipment", "Cisco"),
    "A0:3D:6F": ("network_device", "Network Equipment", "Cisco"),
    "B4:14:89": ("network_device", "Network Equipment", "Cisco"),
    "C0:25:5C": ("network_device", "Network Equipment", "Cisco"),
    "D4:6D:50": ("network_device", "Network Equipment", "Cisco"),
    "EC:1D:8B": ("network_device", "Network Equipment", "Cisco"),
    "F4:CF:E2": ("network_device", "Network Equipment", "Cisco"),
}

CISCO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Catalyst Switches
    (r"Catalyst\s*9[0-9]{3}", "Cisco Catalyst 9000", "switch", "IOS-XE"),
    (r"C9300-48P", "Cisco Catalyst 9300-48P", "switch", "IOS-XE"),
    (r"C9300-24P", "Cisco Catalyst 9300-24P", "switch", "IOS-XE"),
    (r"C9200-48P", "Cisco Catalyst 9200-48P", "switch", "IOS-XE"),
    (r"C9200-24P", "Cisco Catalyst 9200-24P", "switch", "IOS-XE"),
    (r"Catalyst\s*3[0-9]{3}", "Cisco Catalyst 3000", "switch", "IOS"),
    (r"Catalyst\s*2960", "Cisco Catalyst 2960", "switch", "IOS"),
    (r"WS-C3750", "Cisco Catalyst 3750", "switch", "IOS"),
    (r"WS-C3560", "Cisco Catalyst 3560", "switch", "IOS"),
    (r"WS-C2960", "Cisco Catalyst 2960", "switch", "IOS"),

    # Nexus Switches
    (r"Nexus\s*9[0-9]{3}", "Cisco Nexus 9000", "switch", "NX-OS"),
    (r"Nexus\s*7[0-9]{3}", "Cisco Nexus 7000", "switch", "NX-OS"),
    (r"Nexus\s*5[0-9]{3}", "Cisco Nexus 5000", "switch", "NX-OS"),
    (r"Nexus\s*3[0-9]{3}", "Cisco Nexus 3000", "switch", "NX-OS"),
    (r"N9K-", "Cisco Nexus 9000", "switch", "NX-OS"),
    (r"N7K-", "Cisco Nexus 7000", "switch", "NX-OS"),
    (r"N5K-", "Cisco Nexus 5000", "switch", "NX-OS"),

    # ISR Routers
    (r"ISR\s*4[0-9]{3}", "Cisco ISR 4000", "router", "IOS-XE"),
    (r"ISR\s*1[0-9]{3}", "Cisco ISR 1000", "router", "IOS-XE"),
    (r"CISCO\s*4[0-9]{3}", "Cisco 4000", "router", "IOS-XE"),
    (r"CISCO\s*2[0-9]{3}", "Cisco 2000", "router", "IOS"),
    (r"CISCO\s*1[0-9]{3}", "Cisco 1000", "router", "IOS"),

    # ASR Routers
    (r"ASR\s*9[0-9]{3}", "Cisco ASR 9000", "router", "IOS-XR"),
    (r"ASR\s*1[0-9]{3}", "Cisco ASR 1000", "router", "IOS-XE"),

    # Meraki
    (r"Meraki\s*MR\d+", "Cisco Meraki AP", "access_point", "Meraki OS"),
    (r"Meraki\s*MS\d+", "Cisco Meraki Switch", "switch", "Meraki OS"),
    (r"Meraki\s*MX\d+", "Cisco Meraki Security Appliance", "firewall", "Meraki OS"),
    (r"MR33", "Cisco Meraki MR33", "access_point", "Meraki OS"),
    (r"MR42", "Cisco Meraki MR42", "access_point", "Meraki OS"),
    (r"MR46", "Cisco Meraki MR46", "access_point", "Meraki OS"),
    (r"MR56", "Cisco Meraki MR56", "access_point", "Meraki OS"),
    (r"MS120", "Cisco Meraki MS120", "switch", "Meraki OS"),
    (r"MS220", "Cisco Meraki MS220", "switch", "Meraki OS"),
    (r"MS250", "Cisco Meraki MS250", "switch", "Meraki OS"),
    (r"MS350", "Cisco Meraki MS350", "switch", "Meraki OS"),
    (r"MX64", "Cisco Meraki MX64", "firewall", "Meraki OS"),
    (r"MX67", "Cisco Meraki MX67", "firewall", "Meraki OS"),
    (r"MX84", "Cisco Meraki MX84", "firewall", "Meraki OS"),
    (r"MX100", "Cisco Meraki MX100", "firewall", "Meraki OS"),
    (r"MX250", "Cisco Meraki MX250", "firewall", "Meraki OS"),

    # ASA Firewalls
    (r"ASA\s*5505", "Cisco ASA 5505", "firewall", "ASA OS"),
    (r"ASA\s*5510", "Cisco ASA 5510", "firewall", "ASA OS"),
    (r"ASA\s*5520", "Cisco ASA 5520", "firewall", "ASA OS"),
    (r"ASA\s*5540", "Cisco ASA 5540", "firewall", "ASA OS"),
    (r"ASA\s*5545", "Cisco ASA 5545-X", "firewall", "ASA OS"),
    (r"ASA\s*5555", "Cisco ASA 5555-X", "firewall", "ASA OS"),
    (r"Firepower\s*1[0-9]{3}", "Cisco Firepower 1000", "firewall", "FTD"),
    (r"Firepower\s*2[0-9]{3}", "Cisco Firepower 2000", "firewall", "FTD"),
    (r"Firepower\s*4[0-9]{3}", "Cisco Firepower 4000", "firewall", "FTD"),
    (r"FPR-1[0-9]{3}", "Cisco Firepower 1000", "firewall", "FTD"),
    (r"FPR-2[0-9]{3}", "Cisco Firepower 2000", "firewall", "FTD"),

    # Aironet APs
    (r"AIR-CAP\d+", "Cisco Aironet", "access_point", "IOS"),
    (r"AIR-AP\d+", "Cisco Aironet", "access_point", "IOS"),
    (r"Aironet\s*\d+", "Cisco Aironet", "access_point", "IOS"),

    # IP Phones
    (r"CP-\d{4}", "Cisco IP Phone", "voip_phone", None),
    (r"IP\s*Phone\s*\d{4}", "Cisco IP Phone", "voip_phone", None),
    (r"Cisco\s*7[0-9]{3}", "Cisco IP Phone 7000", "voip_phone", None),
    (r"Cisco\s*8[0-9]{3}", "Cisco IP Phone 8000", "voip_phone", None),

    # Generic
    (r"Cisco\s*IOS.*Version\s*([\d.()]+)", "Cisco IOS Device", "router", "IOS"),
    (r"IOS-XE.*Version\s*([\d.]+)", "Cisco IOS-XE Device", "router", "IOS-XE"),
    (r"NX-OS.*Version\s*([\d.]+)", "Cisco NX-OS Device", "switch", "NX-OS"),
]


# ARUBA / HPE DEVICE PATTERNS

ARUBA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Aruba Access Points (verified IEEE registrations to Aruba Networks)
    "00:0B:86": ("access_point", "Network Equipment", "Aruba AP"),
    "00:1A:1E": ("access_point", "Network Equipment", "Aruba AP"),
    "00:24:6C": ("access_point", "Network Equipment", "Aruba AP"),
    "04:BD:88": ("access_point", "Network Equipment", "Aruba AP"),
    "18:64:72": ("access_point", "Network Equipment", "Aruba AP"),
    "20:4C:03": ("access_point", "Network Equipment", "Aruba AP"),
    "24:DE:C6": ("access_point", "Network Equipment", "Aruba AP"),
    "40:E3:D6": ("access_point", "Network Equipment", "Aruba AP"),
    "6C:F3:7F": ("access_point", "Network Equipment", "Aruba AP"),
    "70:3A:0E": ("access_point", "Network Equipment", "Aruba AP"),
    "84:D4:7E": ("access_point", "Network Equipment", "Aruba AP"),
    "8C:85:C1": ("access_point", "Network Equipment", "Aruba AP"),
    "94:B4:0F": ("access_point", "Network Equipment", "Aruba AP"),
    "9C:1C:12": ("access_point", "Network Equipment", "Aruba AP"),
    "AC:A3:1E": ("access_point", "Network Equipment", "Aruba AP"),
    "D8:C7:C8": ("access_point", "Network Equipment", "Aruba AP"),
    "F0:5C:19": ("access_point", "Network Equipment", "Aruba AP"),

    # Aruba Switches
    "00:1A:4B": ("switch", "Network Equipment", "Aruba Switch"),
    "64:51:06": ("switch", "Network Equipment", "Aruba Switch"),
    "94:F1:28": ("switch", "Network Equipment", "Aruba Switch"),

    # Additional Aruba / HPE Aruba OUIs (verified IEEE registrations)
    "0C:97:5F": ("network_device", "Network Equipment", "Aruba"),
    "10:4F:58": ("network_device", "Network Equipment", "Aruba"),
    "14:AB:EC": ("network_device", "Network Equipment", "Aruba"),
    "18:7A:3B": ("network_device", "Network Equipment", "Aruba"),
    "1C:28:AF": ("network_device", "Network Equipment", "Aruba"),
    "20:9C:B4": ("network_device", "Network Equipment", "Aruba"),
    "24:62:CE": ("network_device", "Network Equipment", "Aruba"),
    "28:DE:65": ("network_device", "Network Equipment", "Aruba"),
    "34:3A:20": ("network_device", "Network Equipment", "Aruba"),
    "34:8A:12": ("network_device", "Network Equipment", "Aruba"),
    "34:C5:15": ("network_device", "Network Equipment", "Aruba"),
    "38:10:F0": ("network_device", "Network Equipment", "Aruba"),
    "38:21:C7": ("network_device", "Network Equipment", "Aruba"),
    "38:BD:7A": ("network_device", "Network Equipment", "Aruba"),
    "44:12:44": ("network_device", "Network Equipment", "Aruba"),
    "44:5B:ED": ("network_device", "Network Equipment", "Aruba"),
    "48:00:20": ("network_device", "Network Equipment", "Aruba"),
    "48:2F:6B": ("network_device", "Network Equipment", "Aruba"),
    "48:B4:C3": ("network_device", "Network Equipment", "Aruba"),
    "4C:D5:87": ("network_device", "Network Equipment", "Aruba"),
    "50:E4:E0": ("network_device", "Network Equipment", "Aruba"),
    "54:D7:E3": ("network_device", "Network Equipment", "Aruba"),
    "54:F0:B1": ("network_device", "Network Equipment", "Aruba"),
    "5C:A4:7D": ("network_device", "Network Equipment", "Aruba"),
    "60:26:EF": ("network_device", "Network Equipment", "Aruba"),
    "64:E8:81": ("network_device", "Network Equipment", "Aruba"),
    "68:28:CF": ("network_device", "Network Equipment", "Aruba"),
    "6C:C4:9F": ("network_device", "Network Equipment", "Aruba"),
    "74:9E:75": ("network_device", "Network Equipment", "Aruba"),
    "7C:57:3C": ("network_device", "Network Equipment", "Aruba"),
    "88:25:10": ("network_device", "Network Equipment", "Aruba"),
    "88:3A:30": ("network_device", "Network Equipment", "Aruba"),
    "8C:79:09": ("network_device", "Network Equipment", "Aruba"),
    "90:20:C2": ("network_device", "Network Equipment", "Aruba"),
    "94:60:D5": ("network_device", "Network Equipment", "Aruba"),
    "94:64:24": ("network_device", "Network Equipment", "Aruba"),
    "98:8F:00": ("network_device", "Network Equipment", "Aruba"),
    "9C:37:08": ("network_device", "Network Equipment", "Aruba"),
    "A0:25:D7": ("network_device", "Network Equipment", "Aruba"),
    "A0:A0:01": ("network_device", "Network Equipment", "Aruba"),
    "A4:0E:75": ("network_device", "Network Equipment", "Aruba"),
    "A8:52:D4": ("network_device", "Network Equipment", "Aruba"),
    "A8:5B:F7": ("network_device", "Network Equipment", "Aruba"),
    "B0:1F:8C": ("network_device", "Network Equipment", "Aruba"),
    "B4:5D:50": ("network_device", "Network Equipment", "Aruba"),
    "B8:37:B2": ("network_device", "Network Equipment", "Aruba"),
    "B8:3A:5A": ("network_device", "Network Equipment", "Aruba"),
    "B8:D4:E7": ("network_device", "Network Equipment", "Aruba"),
    "BC:9F:E4": ("network_device", "Network Equipment", "Aruba"),
    "BC:D7:A5": ("network_device", "Network Equipment", "Aruba"),
    "CC:88:C7": ("network_device", "Network Equipment", "Aruba"),
    "CC:D0:83": ("network_device", "Network Equipment", "Aruba"),
    "D0:15:A6": ("network_device", "Network Equipment", "Aruba"),
    "D0:4D:C6": ("network_device", "Network Equipment", "Aruba"),
    "D0:D3:E0": ("network_device", "Network Equipment", "Aruba"),
    "D4:E0:53": ("network_device", "Network Equipment", "Aruba"),
    "DC:B7:AC": ("network_device", "Network Equipment", "Aruba"),
    "E4:DE:40": ("network_device", "Network Equipment", "Aruba"),
    "E8:10:98": ("network_device", "Network Equipment", "Aruba"),
    "E8:26:89": ("network_device", "Network Equipment", "Aruba"),
    "EC:02:73": ("network_device", "Network Equipment", "Aruba"),
    "EC:50:AA": ("network_device", "Network Equipment", "Aruba"),
    "EC:67:94": ("network_device", "Network Equipment", "Aruba"),
    "EC:FC:C6": ("network_device", "Network Equipment", "Aruba"),
    "F0:1A:A0": ("network_device", "Network Equipment", "Aruba"),
    "F0:61:C0": ("network_device", "Network Equipment", "Aruba"),
    "F4:2E:7F": ("network_device", "Network Equipment", "Aruba"),
    "F8:60:F0": ("network_device", "Network Equipment", "Aruba"),
    "FC:7F:F1": ("network_device", "Network Equipment", "Aruba"),
}

ARUBA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Aruba Instant APs
    (r"IAP-\d{3}", "Aruba Instant AP", "access_point", "ArubaOS"),
    (r"IAP-205", "Aruba IAP-205", "access_point", "ArubaOS"),
    (r"IAP-225", "Aruba IAP-225", "access_point", "ArubaOS"),
    (r"IAP-305", "Aruba IAP-305", "access_point", "ArubaOS"),
    (r"IAP-315", "Aruba IAP-315", "access_point", "ArubaOS"),
    (r"IAP-325", "Aruba IAP-325", "access_point", "ArubaOS"),
    (r"IAP-335", "Aruba IAP-335", "access_point", "ArubaOS"),

    # Aruba Campus APs
    (r"AP-\d{3}", "Aruba Campus AP", "access_point", "ArubaOS"),
    (r"AP-505", "Aruba AP-505", "access_point", "ArubaOS"),
    (r"AP-515", "Aruba AP-515", "access_point", "ArubaOS"),
    (r"AP-535", "Aruba AP-535", "access_point", "ArubaOS"),
    (r"AP-555", "Aruba AP-555", "access_point", "ArubaOS"),
    (r"AP-575", "Aruba AP-575", "access_point", "ArubaOS"),
    (r"AP-615", "Aruba AP-615", "access_point", "ArubaOS"),
    (r"AP-635", "Aruba AP-635", "access_point", "ArubaOS"),

    # Aruba Controllers
    (r"Aruba\s*7[0-9]{3}", "Aruba 7000 Controller", "controller", "ArubaOS"),
    (r"7005", "Aruba 7005 Controller", "controller", "ArubaOS"),
    (r"7008", "Aruba 7008 Controller", "controller", "ArubaOS"),
    (r"7010", "Aruba 7010 Controller", "controller", "ArubaOS"),
    (r"7024", "Aruba 7024 Controller", "controller", "ArubaOS"),
    (r"7030", "Aruba 7030 Controller", "controller", "ArubaOS"),
    (r"7205", "Aruba 7205 Controller", "controller", "ArubaOS"),
    (r"7210", "Aruba 7210 Controller", "controller", "ArubaOS"),
    (r"7220", "Aruba 7220 Controller", "controller", "ArubaOS"),
    (r"7240", "Aruba 7240 Controller", "controller", "ArubaOS"),

    # Aruba CX Switches
    (r"CX\s*6[0-9]{3}", "Aruba CX 6000", "switch", "AOS-CX"),
    (r"CX\s*8[0-9]{3}", "Aruba CX 8000", "switch", "AOS-CX"),
    (r"6100", "Aruba 6100 Switch", "switch", "AOS-CX"),
    (r"6200", "Aruba 6200 Switch", "switch", "AOS-CX"),
    (r"6300", "Aruba 6300 Switch", "switch", "AOS-CX"),
    (r"6400", "Aruba 6400 Switch", "switch", "AOS-CX"),
    (r"8320", "Aruba 8320 Switch", "switch", "AOS-CX"),
    (r"8325", "Aruba 8325 Switch", "switch", "AOS-CX"),
    (r"8360", "Aruba 8360 Switch", "switch", "AOS-CX"),
    (r"8400", "Aruba 8400 Switch", "switch", "AOS-CX"),

    # Aruba Central
    (r"Aruba\s*Central", "Aruba Central", "controller", "Aruba Central"),

    # Generic
    (r"ArubaOS\s*([\d.]+)?", "Aruba Device", "access_point", "ArubaOS"),
    (r"AOS-CX\s*([\d.]+)?", "Aruba CX Switch", "switch", "AOS-CX"),
]


# FORTINET DEVICE PATTERNS

FORTINET_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Core Fortinet OUIs (verified IEEE registrations)
    "00:09:0F": ("firewall", "Network Equipment", "FortiGate"),
    "04:01:A1": ("network_device", "Network Equipment", "Fortinet"),
    "04:D5:90": ("network_device", "Network Equipment", "Fortinet"),
    "08:5B:0E": ("firewall", "Network Equipment", "FortiGate"),  # Also used for FortiAP
    "1C:D1:1A": ("network_device", "Network Equipment", "Fortinet"),
    "38:C0:EA": ("network_device", "Network Equipment", "Fortinet"),
    "48:3A:02": ("network_device", "Network Equipment", "Fortinet"),
    "68:CC:AE": ("network_device", "Network Equipment", "Fortinet"),
    "70:4C:A5": ("firewall", "Network Equipment", "FortiGate"),
    "74:78:A6": ("network_device", "Network Equipment", "Fortinet"),
    "78:18:EC": ("network_device", "Network Equipment", "Fortinet"),
    "80:80:2C": ("network_device", "Network Equipment", "Fortinet"),
    "84:39:8F": ("network_device", "Network Equipment", "Fortinet"),
    "90:6C:AC": ("firewall", "Network Equipment", "FortiGate"),
    "94:F3:92": ("network_device", "Network Equipment", "Fortinet"),
    "94:FF:3C": ("network_device", "Network Equipment", "Fortinet"),
    "AC:71:2E": ("network_device", "Network Equipment", "Fortinet"),
    "B4:B2:E9": ("network_device", "Network Equipment", "Fortinet"),
    "D4:76:A0": ("network_device", "Network Equipment", "Fortinet"),
    "D4:B4:C0": ("network_device", "Network Equipment", "Fortinet"),
    "E0:23:FF": ("network_device", "Network Equipment", "Fortinet"),
    "E8:1C:BA": ("firewall", "Network Equipment", "FortiGate"),
    "E8:ED:D6": ("network_device", "Network Equipment", "Fortinet"),
}

FORTINET_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # FortiGate Firewalls
    (r"FortiGate-\d+[A-Z]?", "FortiGate Firewall", "firewall", "FortiOS"),
    (r"FG-\d+[A-Z]?", "FortiGate Firewall", "firewall", "FortiOS"),
    (r"FortiGate-40F", "FortiGate 40F", "firewall", "FortiOS"),
    (r"FortiGate-60F", "FortiGate 60F", "firewall", "FortiOS"),
    (r"FortiGate-80F", "FortiGate 80F", "firewall", "FortiOS"),
    (r"FortiGate-100F", "FortiGate 100F", "firewall", "FortiOS"),
    (r"FortiGate-200F", "FortiGate 200F", "firewall", "FortiOS"),
    (r"FortiGate-400F", "FortiGate 400F", "firewall", "FortiOS"),
    (r"FortiGate-600F", "FortiGate 600F", "firewall", "FortiOS"),
    (r"FortiGate-1000F", "FortiGate 1000F", "firewall", "FortiOS"),
    (r"FortiGate-2000F", "FortiGate 2000F", "firewall", "FortiOS"),
    (r"FortiGate-3000F", "FortiGate 3000F", "firewall", "FortiOS"),
    (r"FortiGate-VM", "FortiGate VM", "firewall", "FortiOS"),

    # FortiWiFi
    (r"FortiWiFi-\d+[A-Z]?", "FortiWiFi", "firewall", "FortiOS"),
    (r"FWF-\d+", "FortiWiFi", "firewall", "FortiOS"),

    # FortiAP
    (r"FortiAP-\d+[A-Z]?", "FortiAP", "access_point", "FortiAP OS"),
    (r"FAP-\d+", "FortiAP", "access_point", "FortiAP OS"),
    (r"FortiAP-221E", "FortiAP 221E", "access_point", "FortiAP OS"),
    (r"FortiAP-231F", "FortiAP 231F", "access_point", "FortiAP OS"),
    (r"FortiAP-431F", "FortiAP 431F", "access_point", "FortiAP OS"),

    # FortiSwitch
    (r"FortiSwitch-\d+", "FortiSwitch", "switch", "FortiSwitch OS"),
    (r"FS-\d+", "FortiSwitch", "switch", "FortiSwitch OS"),
    (r"FortiSwitch-124E", "FortiSwitch 124E", "switch", "FortiSwitch OS"),
    (r"FortiSwitch-148E", "FortiSwitch 148E", "switch", "FortiSwitch OS"),
    (r"FortiSwitch-248E", "FortiSwitch 248E", "switch", "FortiSwitch OS"),
    (r"FortiSwitch-448E", "FortiSwitch 448E", "switch", "FortiSwitch OS"),

    # FortiManager / FortiAnalyzer
    (r"FortiManager", "FortiManager", "management", "FortiManager"),
    (r"FortiAnalyzer", "FortiAnalyzer", "management", "FortiAnalyzer"),

    # Generic
    (r"FortiOS\s*([\d.]+)?", "Fortinet Device", "firewall", "FortiOS"),
]


# SYNOLOGY NAS PATTERNS

SYNOLOGY_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:11:32": ("nas", "Storage", "Synology NAS"),
}

SYNOLOGY_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # DiskStation Models
    (r"DS\d{3,4}\+?", "Synology DiskStation", "nas", "DSM"),
    (r"DS220\+", "Synology DS220+", "nas", "DSM"),
    (r"DS420\+", "Synology DS420+", "nas", "DSM"),
    (r"DS720\+", "Synology DS720+", "nas", "DSM"),
    (r"DS920\+", "Synology DS920+", "nas", "DSM"),
    (r"DS1520\+", "Synology DS1520+", "nas", "DSM"),
    (r"DS1621\+", "Synology DS1621+", "nas", "DSM"),
    (r"DS1821\+", "Synology DS1821+", "nas", "DSM"),
    (r"DS1522\+", "Synology DS1522+", "nas", "DSM"),
    (r"DS1823xs\+", "Synology DS1823xs+", "nas", "DSM"),
    (r"DS923\+", "Synology DS923+", "nas", "DSM"),
    (r"DS423\+", "Synology DS423+", "nas", "DSM"),
    (r"DS223", "Synology DS223", "nas", "DSM"),
    (r"DS124", "Synology DS124", "nas", "DSM"),

    # RackStation Models
    (r"RS\d{3,4}\+?", "Synology RackStation", "nas", "DSM"),
    (r"RS1221\+", "Synology RS1221+", "nas", "DSM"),
    (r"RS2421\+", "Synology RS2421+", "nas", "DSM"),
    (r"RS3621xs\+", "Synology RS3621xs+", "nas", "DSM"),
    (r"RS4021xs\+", "Synology RS4021xs+", "nas", "DSM"),

    # FlashStation
    (r"FS\d{3,4}", "Synology FlashStation", "nas", "DSM"),
    (r"FS2500", "Synology FS2500", "nas", "DSM"),
    (r"FS3410", "Synology FS3410", "nas", "DSM"),
    (r"FS6400", "Synology FS6400", "nas", "DSM"),

    # Synology Router
    (r"RT\d{4}", "Synology Router", "router", "SRM"),
    (r"RT2600ac", "Synology RT2600ac", "router", "SRM"),
    (r"RT6600ax", "Synology RT6600ax", "router", "SRM"),

    # Generic
    (r"DSM\s*([\d.]+)?", "Synology NAS", "nas", "DSM"),
    (r"SRM\s*([\d.]+)?", "Synology Router", "router", "SRM"),
    (r"DiskStation", "Synology DiskStation", "nas", "DSM"),
    (r"RackStation", "Synology RackStation", "nas", "DSM"),
    (r"Synology", "Synology Device", "nas", "DSM"),
]


# QNAP NAS PATTERNS

QNAP_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "24:5E:BE": ("nas", "Storage", "QNAP NAS"),
}

QNAP_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # TS Series
    (r"TS-\d{3,4}[A-Z]*", "QNAP TS Series", "nas", "QTS"),
    (r"TS-253D", "QNAP TS-253D", "nas", "QTS"),
    (r"TS-453D", "QNAP TS-453D", "nas", "QTS"),
    (r"TS-653D", "QNAP TS-653D", "nas", "QTS"),
    (r"TS-873A", "QNAP TS-873A", "nas", "QTS"),
    (r"TS-1273AU", "QNAP TS-1273AU", "nas", "QTS"),
    (r"TS-1673AU", "QNAP TS-1673AU", "nas", "QTS"),
    (r"TS-464", "QNAP TS-464", "nas", "QTS"),
    (r"TS-664", "QNAP TS-664", "nas", "QTS"),

    # TVS Series
    (r"TVS-\d{3,4}[A-Z]*", "QNAP TVS Series", "nas", "QTS"),
    (r"TVS-472XT", "QNAP TVS-472XT", "nas", "QTS"),
    (r"TVS-672XT", "QNAP TVS-672XT", "nas", "QTS"),
    (r"TVS-872XT", "QNAP TVS-872XT", "nas", "QTS"),
    (r"TVS-h1288X", "QNAP TVS-h1288X", "nas", "QuTS hero"),
    (r"TVS-h1688X", "QNAP TVS-h1688X", "nas", "QuTS hero"),

    # TS-hxxx QuTS Hero Series
    (r"TS-h\d{3,4}", "QNAP QuTS hero", "nas", "QuTS hero"),
    (r"TS-h973AX", "QNAP TS-h973AX", "nas", "QuTS hero"),
    (r"TS-h1277AXU", "QNAP TS-h1277AXU", "nas", "QuTS hero"),
    (r"TS-h1886XU", "QNAP TS-h1886XU", "nas", "QuTS hero"),

    # Generic
    (r"QTS\s*([\d.]+)?", "QNAP NAS", "nas", "QTS"),
    (r"QuTS\s*hero\s*([\d.]+)?", "QNAP NAS", "nas", "QuTS hero"),
    (r"QNAP", "QNAP Device", "nas", "QTS"),
]


# TP-LINK DEVICE PATTERNS

TPLINK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # TP-Link Consumer Routers/APs (TP-Link Corporation Limited OUIs)
    "00:1D:0F": ("network_device", "Network Equipment", "TP-Link"),
    "00:31:92": ("network_device", "Network Equipment", "TP-Link"),
    "14:CC:20": ("network_device", "Network Equipment", "TP-Link"),
    "14:CF:92": ("network_device", "Network Equipment", "TP-Link"),
    "14:EB:B6": ("network_device", "Network Equipment", "TP-Link"),
    "18:A6:F7": ("network_device", "Network Equipment", "TP-Link"),
    "1C:3B:F3": ("network_device", "Network Equipment", "TP-Link"),
    "24:69:68": ("network_device", "Network Equipment", "TP-Link"),
    "30:B5:C2": ("network_device", "Network Equipment", "TP-Link"),
    "30:DE:4B": ("network_device", "Network Equipment", "TP-Link"),
    "34:60:F9": ("network_device", "Network Equipment", "TP-Link"),
    "3C:84:6A": ("network_device", "Network Equipment", "TP-Link"),
    "48:22:54": ("network_device", "Network Equipment", "TP-Link"),
    "50:3E:AA": ("network_device", "Network Equipment", "TP-Link"),
    "50:C7:BF": ("network_device", "Network Equipment", "TP-Link"),
    "54:AF:97": ("network_device", "Network Equipment", "TP-Link"),
    "54:C8:0F": ("network_device", "Network Equipment", "TP-Link"),
    "5C:A6:E6": ("network_device", "Network Equipment", "TP-Link"),
    "60:32:B1": ("network_device", "Network Equipment", "TP-Link"),
    "60:A4:B7": ("network_device", "Network Equipment", "TP-Link"),
    "64:66:B3": ("network_device", "Network Equipment", "TP-Link"),
    "64:70:02": ("network_device", "Network Equipment", "TP-Link"),
    "68:FF:7B": ("network_device", "Network Equipment", "TP-Link"),
    "6C:5A:B0": ("network_device", "Network Equipment", "TP-Link"),
    "70:4F:57": ("network_device", "Network Equipment", "TP-Link"),
    "78:44:76": ("network_device", "Network Equipment", "TP-Link"),
    "7C:8B:CA": ("network_device", "Network Equipment", "TP-Link"),
    "80:7D:14": ("network_device", "Network Equipment", "TP-Link"),
    "84:16:F9": ("network_device", "Network Equipment", "TP-Link"),
    "84:D8:1B": ("network_device", "Network Equipment", "TP-Link"),
    "90:9A:4A": ("network_device", "Network Equipment", "TP-Link"),
    "94:D9:B3": ("network_device", "Network Equipment", "TP-Link"),
    "98:DA:C4": ("network_device", "Network Equipment", "TP-Link"),
    "A0:F3:C1": ("network_device", "Network Equipment", "TP-Link"),
    "AC:15:A2": ("network_device", "Network Equipment", "TP-Link"),
    "AC:84:C6": ("network_device", "Network Equipment", "TP-Link"),
    "B0:4E:26": ("network_device", "Network Equipment", "TP-Link"),
    "B0:95:75": ("network_device", "Network Equipment", "TP-Link"),
    "B0:A7:B9": ("network_device", "Network Equipment", "TP-Link"),
    "B0:BE:76": ("network_device", "Network Equipment", "TP-Link"),
    "C0:06:C3": ("network_device", "Network Equipment", "TP-Link"),
    "C0:25:E9": ("network_device", "Network Equipment", "TP-Link"),
    "C0:E4:2D": ("network_device", "Network Equipment", "TP-Link"),
    "CC:32:E5": ("network_device", "Network Equipment", "TP-Link"),
    "D4:6E:0E": ("network_device", "Network Equipment", "TP-Link"),
    "D8:07:B6": ("network_device", "Network Equipment", "TP-Link"),
    "D8:47:32": ("network_device", "Network Equipment", "TP-Link"),
    "E4:C3:2A": ("network_device", "Network Equipment", "TP-Link"),
    "E8:48:B8": ("network_device", "Network Equipment", "TP-Link"),
    "E8:94:F6": ("network_device", "Network Equipment", "TP-Link"),
    "EC:08:6B": ("network_device", "Network Equipment", "TP-Link"),
    "EC:60:73": ("network_device", "Network Equipment", "TP-Link"),
    "F0:A7:31": ("network_device", "Network Equipment", "TP-Link"),
    "F4:EC:38": ("network_device", "Network Equipment", "TP-Link"),
    "F4:F2:6D": ("network_device", "Network Equipment", "TP-Link"),
    "F8:8C:21": ("network_device", "Network Equipment", "TP-Link"),

    # TP-Link Kasa/Tapo Smart Home
    "1C:61:B4": ("smart_plug", "Smart Home", "TP-Link Tapo"),
    "5C:62:8B": ("smart_plug", "Smart Home", "TP-Link Kasa"),
    "78:8C:B5": ("smart_plug", "Smart Home", "TP-Link Tapo"),
    "98:25:4A": ("ip_camera", "Smart Home", "TP-Link Tapo"),
    "B4:B0:24": ("smart_plug", "Smart Home", "TP-Link Tapo"),

    # TP-Link Omada Business
    "10:27:F5": ("access_point", "Network Equipment", "TP-Link Omada"),
    "5C:E9:31": ("access_point", "Network Equipment", "TP-Link Omada"),

    # Additional TP-Link Systems Inc OUIs
    "04:C8:45": ("network_device", "Network Equipment", "TP-Link"),
    "30:68:93": ("network_device", "Network Equipment", "TP-Link"),
    "58:D8:12": ("network_device", "Network Equipment", "TP-Link"),
    "80:3C:04": ("network_device", "Network Equipment", "TP-Link"),
    "8C:86:DD": ("network_device", "Network Equipment", "TP-Link"),
    "B4:C0:C3": ("network_device", "Network Equipment", "TP-Link"),
    "B8:FB:B3": ("network_device", "Network Equipment", "TP-Link"),
    "D8:F1:2E": ("network_device", "Network Equipment", "TP-Link"),
    "E0:D3:62": ("network_device", "Network Equipment", "TP-Link"),
}

TPLINK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Archer WiFi 7 (BE) Routers
    (r"Archer\s*BE900", "TP-Link Archer BE900", "router", None),
    (r"Archer\s*BE800", "TP-Link Archer BE800", "router", None),
    (r"Archer\s*BE550", "TP-Link Archer BE550", "router", None),
    (r"Archer\s*BE450", "TP-Link Archer BE450", "router", None),
    (r"Archer\s*BE\d+", "TP-Link Archer BE WiFi 7", "router", None),

    # Archer WiFi 6E (AXE) Routers
    (r"Archer\s*AXE300", "TP-Link Archer AXE300", "router", None),
    (r"Archer\s*AXE200", "TP-Link Archer AXE200 Omada", "router", "Omada"),
    (r"Archer\s*AXE95", "TP-Link Archer AXE95", "router", None),
    (r"Archer\s*AXE75", "TP-Link Archer AXE75", "router", None),
    (r"Archer\s*AXE\d+", "TP-Link Archer AXE WiFi 6E", "router", None),

    # Archer WiFi 6 (AX) Routers
    (r"Archer\s*AX11000", "TP-Link Archer AX11000", "router", None),
    (r"Archer\s*AX10000", "TP-Link Archer AX10000", "router", None),
    (r"Archer\s*AX6600", "TP-Link Archer AX6600", "router", None),
    (r"Archer\s*AX6000", "TP-Link Archer AX6000", "router", None),
    (r"Archer\s*AX5400", "TP-Link Archer AX5400", "router", None),
    (r"Archer\s*AX4400", "TP-Link Archer AX4400", "router", None),
    (r"Archer\s*AX3000", "TP-Link Archer AX3000", "router", None),
    (r"Archer\s*AX1800", "TP-Link Archer AX1800", "router", None),
    (r"Archer\s*AX1500", "TP-Link Archer AX1500", "router", None),
    (r"Archer\s*AX90", "TP-Link Archer AX90", "router", None),
    (r"Archer\s*AX80", "TP-Link Archer AX80", "router", None),
    (r"Archer\s*AX73", "TP-Link Archer AX73", "router", None),
    (r"Archer\s*AX55", "TP-Link Archer AX55", "router", None),
    (r"Archer\s*AX50", "TP-Link Archer AX50", "router", None),
    (r"Archer\s*AX21", "TP-Link Archer AX21", "router", None),
    (r"Archer\s*AX20", "TP-Link Archer AX20", "router", None),
    (r"Archer\s*AX10", "TP-Link Archer AX10", "router", None),
    (r"Archer\s*AX\d+", "TP-Link Archer AX WiFi 6", "router", None),

    # Archer WiFi 5 (AC/C/A) Routers
    (r"Archer\s*C5400X", "TP-Link Archer C5400X", "router", None),
    (r"Archer\s*C5400", "TP-Link Archer C5400", "router", None),
    (r"Archer\s*C4000", "TP-Link Archer C4000", "router", None),
    (r"Archer\s*C3200", "TP-Link Archer C3200", "router", None),
    (r"Archer\s*C2700", "TP-Link Archer C2700", "router", None),
    (r"Archer\s*C2300", "TP-Link Archer C2300", "router", None),
    (r"Archer\s*C1900", "TP-Link Archer C1900", "router", None),
    (r"Archer\s*C1200", "TP-Link Archer C1200", "router", None),
    (r"Archer\s*C80", "TP-Link Archer C80", "router", None),
    (r"Archer\s*C64", "TP-Link Archer C64", "router", None),
    (r"Archer\s*C60", "TP-Link Archer C60", "router", None),
    (r"Archer\s*C50", "TP-Link Archer C50", "router", None),
    (r"Archer\s*C20", "TP-Link Archer C20", "router", None),
    (r"Archer\s*C\d+", "TP-Link Archer C", "router", None),
    (r"Archer\s*A\d+", "TP-Link Archer A", "router", None),

    # Deco Mesh WiFi Systems
    # Deco WiFi 7 (BE)
    (r"Deco\s*BE85", "TP-Link Deco BE85", "mesh_router", None),
    (r"Deco\s*BE65", "TP-Link Deco BE65", "mesh_router", None),
    (r"Deco\s*BE63", "TP-Link Deco BE63", "mesh_router", None),
    (r"Deco\s*BE\d+", "TP-Link Deco BE WiFi 7", "mesh_router", None),

    # Deco WiFi 6E (XE)
    (r"Deco\s*XE200", "TP-Link Deco XE200", "mesh_router", None),
    (r"Deco\s*XE75\s*Pro", "TP-Link Deco XE75 Pro", "mesh_router", None),
    (r"Deco\s*XE75", "TP-Link Deco XE75", "mesh_router", None),
    (r"Deco\s*XE\d+", "TP-Link Deco XE WiFi 6E", "mesh_router", None),

    # Deco WiFi 6 (X)
    (r"Deco\s*X95", "TP-Link Deco X95", "mesh_router", None),
    (r"Deco\s*X90", "TP-Link Deco X90", "mesh_router", None),
    (r"Deco\s*X80", "TP-Link Deco X80", "mesh_router", None),
    (r"Deco\s*X73", "TP-Link Deco X73", "mesh_router", None),
    (r"Deco\s*X68", "TP-Link Deco X68", "mesh_router", None),
    (r"Deco\s*X60", "TP-Link Deco X60", "mesh_router", None),
    (r"Deco\s*X55", "TP-Link Deco X55", "mesh_router", None),
    (r"Deco\s*X50", "TP-Link Deco X50", "mesh_router", None),
    (r"Deco\s*X20", "TP-Link Deco X20", "mesh_router", None),
    (r"Deco\s*X10", "TP-Link Deco X10", "mesh_router", None),
    (r"Deco\s*X\d+", "TP-Link Deco X WiFi 6", "mesh_router", None),

    # Deco WiFi 5 (M/P/S/W)
    (r"Deco\s*M9\s*Plus", "TP-Link Deco M9 Plus", "mesh_router", None),
    (r"Deco\s*M5", "TP-Link Deco M5", "mesh_router", None),
    (r"Deco\s*M4", "TP-Link Deco M4", "mesh_router", None),
    (r"Deco\s*M3", "TP-Link Deco M3", "mesh_router", None),
    (r"Deco\s*P7", "TP-Link Deco P7", "mesh_router", None),
    (r"Deco\s*S7", "TP-Link Deco S7", "mesh_router", None),
    (r"Deco\s*S4", "TP-Link Deco S4", "mesh_router", None),
    (r"Deco\s*W\d+", "TP-Link Deco W", "mesh_router", None),
    (r"Deco\s*[A-Z]\d+", "TP-Link Deco", "mesh_router", None),

    # Omada Business SDN (EAP Access Points)
    # WiFi 7 APs
    (r"EAP783", "TP-Link Omada EAP783 WiFi 7", "access_point", "Omada"),
    (r"EAP773", "TP-Link Omada EAP773 WiFi 7", "access_point", "Omada"),

    # WiFi 6E APs
    (r"EAP690E", "TP-Link Omada EAP690E HD WiFi 6E", "access_point", "Omada"),
    (r"EAP680", "TP-Link Omada EAP680 WiFi 6E", "access_point", "Omada"),
    (r"EAP673", "TP-Link Omada EAP673 WiFi 6E", "access_point", "Omada"),

    # WiFi 6 APs
    (r"EAP670", "TP-Link Omada EAP670", "access_point", "Omada"),
    (r"EAP660\s*HD", "TP-Link Omada EAP660 HD", "access_point", "Omada"),
    (r"EAP660", "TP-Link Omada EAP660", "access_point", "Omada"),
    (r"EAP653", "TP-Link Omada EAP653", "access_point", "Omada"),
    (r"EAP650", "TP-Link Omada EAP650", "access_point", "Omada"),
    (r"EAP620\s*HD", "TP-Link Omada EAP620 HD", "access_point", "Omada"),
    (r"EAP615-Wall", "TP-Link Omada EAP615-Wall", "access_point", "Omada"),
    (r"EAP610", "TP-Link Omada EAP610", "access_point", "Omada"),

    # WiFi 5 APs
    (r"EAP265\s*HD", "TP-Link Omada EAP265 HD", "access_point", "Omada"),
    (r"EAP245", "TP-Link Omada EAP245", "access_point", "Omada"),
    (r"EAP235-Wall", "TP-Link Omada EAP235-Wall", "access_point", "Omada"),
    (r"EAP230-Wall", "TP-Link Omada EAP230-Wall", "access_point", "Omada"),
    (r"EAP225", "TP-Link Omada EAP225", "access_point", "Omada"),
    (r"EAP225-Outdoor", "TP-Link Omada EAP225-Outdoor", "access_point", "Omada"),
    (r"EAP225-Wall", "TP-Link Omada EAP225-Wall", "access_point", "Omada"),
    (r"EAP115", "TP-Link Omada EAP115", "access_point", "Omada"),
    (r"EAP110", "TP-Link Omada EAP110", "access_point", "Omada"),
    (r"EAP\d{3}", "TP-Link Omada EAP", "access_point", "Omada"),

    # Outdoor APs
    (r"EAP650-Outdoor", "TP-Link Omada EAP650-Outdoor", "access_point", "Omada"),
    (r"EAP610-Outdoor", "TP-Link Omada EAP610-Outdoor", "access_point", "Omada"),
    (r"EAP\d+-Outdoor", "TP-Link Omada Outdoor AP", "access_point", "Omada"),

    # Omada Business SDN (Switches)
    # JetStream L3 Managed
    (r"TL-SX3016F", "TP-Link JetStream TL-SX3016F 10G L3", "switch", "Omada"),
    (r"TL-SX3008F", "TP-Link JetStream TL-SX3008F 10G L3", "switch", "Omada"),
    (r"TL-SG3452XP", "TP-Link JetStream TL-SG3452XP PoE+", "switch", "Omada"),
    (r"TL-SG3452X", "TP-Link JetStream TL-SG3452X", "switch", "Omada"),
    (r"TL-SG3452P", "TP-Link JetStream TL-SG3452P PoE+", "switch", "Omada"),
    (r"TL-SG3452", "TP-Link JetStream TL-SG3452", "switch", "Omada"),
    (r"TL-SG3428XMP", "TP-Link JetStream TL-SG3428XMP PoE+", "switch", "Omada"),
    (r"TL-SG3428XPP", "TP-Link JetStream TL-SG3428XPP-M2 PoE++", "switch", "Omada"),
    (r"TL-SG3428X", "TP-Link JetStream TL-SG3428X", "switch", "Omada"),
    (r"TL-SG3428MP", "TP-Link JetStream TL-SG3428MP PoE+", "switch", "Omada"),
    (r"TL-SG3428", "TP-Link JetStream TL-SG3428", "switch", "Omada"),
    (r"TL-SG3210XHP-M2", "TP-Link JetStream TL-SG3210XHP-M2 PoE+", "switch", "Omada"),

    # JetStream L2+ Smart Managed
    (r"TL-SG2428P", "TP-Link JetStream TL-SG2428P PoE+", "switch", "Omada"),
    (r"TL-SG2218", "TP-Link JetStream TL-SG2218", "switch", "Omada"),
    (r"TL-SG2210MP", "TP-Link JetStream TL-SG2210MP PoE+", "switch", "Omada"),
    (r"TL-SG2210P", "TP-Link JetStream TL-SG2210P PoE+", "switch", "Omada"),
    (r"TL-SG2008P", "TP-Link JetStream TL-SG2008P PoE+", "switch", "Omada"),
    (r"TL-SG2008", "TP-Link JetStream TL-SG2008", "switch", "Omada"),

    # Unmanaged/Easy Smart
    (r"TL-SG108PE", "TP-Link TL-SG108PE Easy Smart PoE", "switch", None),
    (r"TL-SG108E", "TP-Link TL-SG108E Easy Smart", "switch", None),
    (r"TL-SG105PE", "TP-Link TL-SG105PE Easy Smart PoE", "switch", None),
    (r"TL-SG105E", "TP-Link TL-SG105E Easy Smart", "switch", None),
    (r"TL-SG\d+PE", "TP-Link Easy Smart PoE Switch", "switch", None),
    (r"TL-SG\d+E", "TP-Link Easy Smart Switch", "switch", None),
    (r"TL-SG\d+P", "TP-Link PoE Switch", "switch", None),
    (r"TL-SG\d+", "TP-Link Gigabit Switch", "switch", None),
    (r"TL-SF\d+", "TP-Link Fast Ethernet Switch", "switch", None),

    # 10G/2.5G Switches
    (r"TL-SX3206HPP", "TP-Link TL-SX3206HPP 10G PoE++", "switch", "Omada"),
    (r"TL-SX105", "TP-Link TL-SX105 10G Switch", "switch", None),
    (r"TL-SX1008", "TP-Link TL-SX1008 10G Switch", "switch", None),
    (r"TL-SX\d+", "TP-Link 10G Switch", "switch", None),

    # Omada Business SDN (Routers/Gateways)
    (r"ER8411", "TP-Link Omada ER8411 VPN Router", "router", "Omada"),
    (r"ER7412-M2", "TP-Link Omada ER7412-M2 VPN Router", "router", "Omada"),
    (r"ER7206", "TP-Link Omada ER7206 VPN Router", "router", "Omada"),
    (r"ER706W", "TP-Link Omada ER706W WiFi VPN Router", "router", "Omada"),
    (r"ER706W-4G", "TP-Link Omada ER706W-4G LTE Router", "router", "Omada"),
    (r"ER605", "TP-Link Omada ER605 VPN Router", "router", "Omada"),
    (r"ER605\s*v2", "TP-Link Omada ER605 v2", "router", "Omada"),
    (r"ER\d+", "TP-Link Omada VPN Router", "router", "Omada"),

    # Omada Controller
    (r"OC300", "TP-Link Omada OC300 Controller", "controller", "Omada"),
    (r"OC200", "TP-Link Omada OC200 Controller", "controller", "Omada"),
    (r"Omada\s*Controller", "TP-Link Omada Controller", "controller", "Omada"),
    (r"Omada\s*SDN", "TP-Link Omada SDN", "controller", "Omada"),

    # VPN Routers (SafeStream)
    (r"TL-ER6120", "TP-Link SafeStream TL-ER6120", "router", None),
    (r"TL-ER6020", "TP-Link SafeStream TL-ER6020", "router", None),
    (r"TL-R605", "TP-Link SafeStream TL-R605", "router", None),
    (r"TL-R480T\+", "TP-Link TL-R480T+ Load Balance Router", "router", None),
    (r"TL-R470T\+", "TP-Link TL-R470T+ Load Balance Router", "router", None),
    (r"SafeStream", "TP-Link SafeStream Router", "router", None),

    # PON/xDSL Gateways
    (r"XC220-G3v", "TP-Link XC220-G3v GPON Router", "ont", None),
    (r"XC220", "TP-Link XC220 GPON", "ont", None),
    (r"XN020-G3v", "TP-Link XN020-G3v 10G PON ONT", "ont", None),
    (r"XZ000-G3", "TP-Link XZ000-G3 XPON Router", "ont", None),
    (r"Archer\s*VR\d+", "TP-Link Archer VR VDSL", "router", None),
    (r"TD-W\d+", "TP-Link TD-W ADSL/VDSL", "router", None),
    (r"VX\d+", "TP-Link VX VDSL", "router", None),

    # Wireless Adapters/Range Extenders
    (r"RE\d+X", "TP-Link RE WiFi 6 Range Extender", "range_extender", None),
    (r"RE\d+", "TP-Link RE Range Extender", "range_extender", None),
    (r"TL-WA\d+", "TP-Link TL-WA Access Point", "access_point", None),
    (r"CPE\d+", "TP-Link CPE Outdoor AP", "access_point", None),
    (r"CPE510", "TP-Link CPE510 Outdoor AP", "access_point", None),
    (r"CPE210", "TP-Link CPE210 Outdoor AP", "access_point", None),
    (r"WBS\d+", "TP-Link WBS Base Station", "access_point", None),

    # Kasa Smart Home
    # Smart Plugs
    (r"Kasa\s*EP40", "TP-Link Kasa EP40 Outdoor Plug", "smart_plug", None),
    (r"Kasa\s*EP25", "TP-Link Kasa EP25 Ultra Mini Plug", "smart_plug", None),
    (r"Kasa\s*EP10", "TP-Link Kasa EP10 Mini Plug", "smart_plug", None),
    (r"Kasa\s*HS103", "TP-Link Kasa HS103 Lite Plug", "smart_plug", None),
    (r"Kasa\s*HS105", "TP-Link Kasa HS105 Mini Plug", "smart_plug", None),
    (r"Kasa\s*KP125M", "TP-Link Kasa KP125M Matter Plug", "smart_plug", None),
    (r"Kasa\s*KP125", "TP-Link Kasa KP125 Plug", "smart_plug", None),
    (r"Kasa\s*KP115", "TP-Link Kasa KP115 Energy Monitoring", "smart_plug", None),
    (r"Kasa\s*KP401", "TP-Link Kasa KP401 Outdoor Plug", "smart_plug", None),
    (r"Kasa\s*KP400", "TP-Link Kasa KP400 Outdoor Plug", "smart_plug", None),
    (r"Kasa\s*KP303", "TP-Link Kasa KP303 Power Strip", "smart_plug", None),
    (r"Kasa\s*KP200", "TP-Link Kasa KP200 In-Wall Outlet", "smart_plug", None),
    (r"EP\d+", "TP-Link Kasa EP Smart Plug", "smart_plug", None),
    (r"HS\d{3}", "TP-Link Kasa HS Smart Plug", "smart_plug", None),
    (r"KP\d{3}", "TP-Link Kasa KP Smart Plug", "smart_plug", None),

    # Smart Switches
    (r"Kasa\s*HS220", "TP-Link Kasa HS220 Dimmer Switch", "smart_switch", None),
    (r"Kasa\s*HS210", "TP-Link Kasa HS210 3-Way Switch", "smart_switch", None),
    (r"Kasa\s*HS200", "TP-Link Kasa HS200 Smart Switch", "smart_switch", None),
    (r"Kasa\s*ES20M", "TP-Link Kasa ES20M Motion Switch", "smart_switch", None),
    (r"ES\d+", "TP-Link Kasa ES Smart Switch", "smart_switch", None),

    # Smart Bulbs
    (r"Kasa\s*KL\d+", "TP-Link Kasa KL Smart Bulb", "smart_bulb", None),
    (r"Kasa\s*LB\d+", "TP-Link Kasa LB Smart Bulb", "smart_bulb", None),
    (r"KL\d+", "TP-Link Kasa KL Smart Bulb", "smart_bulb", None),
    (r"LB\d+", "TP-Link Kasa LB Smart Bulb", "smart_bulb", None),

    # Smart Cameras
    (r"Kasa\s*KC\d+", "TP-Link Kasa KC Spot Camera", "ip_camera", None),
    (r"Kasa\s*EC\d+", "TP-Link Kasa EC Outdoor Camera", "ip_camera", None),
    (r"KC\d+", "TP-Link Kasa Spot Camera", "ip_camera", None),
    (r"EC\d+", "TP-Link Kasa Outdoor Camera", "ip_camera", None),

    # Kasa Doorbell
    (r"Kasa\s*KD110", "TP-Link Kasa KD110 Doorbell", "doorbell_camera", None),

    # Generic Kasa
    (r"Kasa\s*Smart", "TP-Link Kasa Smart Device", "smart_plug", None),
    (r"Kasa", "TP-Link Kasa Device", "iot_device", None),

    # Tapo Smart Home
    # Tapo Cameras (Indoor)
    (r"Tapo\s*C225", "TP-Link Tapo C225 Pan/Tilt AI", "ip_camera", None),
    (r"Tapo\s*C220", "TP-Link Tapo C220 Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C212", "TP-Link Tapo C212 Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C211", "TP-Link Tapo C211 Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C210", "TP-Link Tapo C210 Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C200", "TP-Link Tapo C200 Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C125", "TP-Link Tapo C125 AI Home", "ip_camera", None),
    (r"Tapo\s*C120", "TP-Link Tapo C120 Indoor/Outdoor", "ip_camera", None),
    (r"Tapo\s*C110", "TP-Link Tapo C110 Home", "ip_camera", None),
    (r"Tapo\s*C100", "TP-Link Tapo C100 Home", "ip_camera", None),

    # Tapo Cameras (Outdoor)
    (r"Tapo\s*C720", "TP-Link Tapo C720 2K QHD Outdoor", "ip_camera", None),
    (r"Tapo\s*C520WS", "TP-Link Tapo C520WS Outdoor Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C510W", "TP-Link Tapo C510W Outdoor Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C500", "TP-Link Tapo C500 Outdoor Pan/Tilt", "ip_camera", None),
    (r"Tapo\s*C420S2", "TP-Link Tapo C420S2 Wire-Free", "ip_camera", None),
    (r"Tapo\s*C420", "TP-Link Tapo C420 Wire-Free", "ip_camera", None),
    (r"Tapo\s*C410", "TP-Link Tapo C410 Outdoor", "ip_camera", None),
    (r"Tapo\s*C400", "TP-Link Tapo C400 Wire-Free", "ip_camera", None),
    (r"Tapo\s*C325WB", "TP-Link Tapo C325WB ColorPro Outdoor", "ip_camera", None),
    (r"Tapo\s*C320WS", "TP-Link Tapo C320WS Outdoor", "ip_camera", None),
    (r"Tapo\s*C310", "TP-Link Tapo C310 Outdoor", "ip_camera", None),

    # Tapo Doorbell
    (r"Tapo\s*D230S1", "TP-Link Tapo D230S1 Battery Doorbell", "doorbell_camera", None),
    (r"Tapo\s*D225", "TP-Link Tapo D225 2K Doorbell", "doorbell_camera", None),
    (r"Tapo\s*D210", "TP-Link Tapo D210 Battery Doorbell", "doorbell_camera", None),
    (r"Tapo\s*D\d+", "TP-Link Tapo Doorbell", "doorbell_camera", None),

    # Tapo Hub
    (r"Tapo\s*H200", "TP-Link Tapo H200 Smart Hub", "iot_hub", None),
    (r"Tapo\s*H100", "TP-Link Tapo H100 Smart Hub", "iot_hub", None),

    # Tapo Smart Plugs
    (r"Tapo\s*P125M", "TP-Link Tapo P125M Matter Plug", "smart_plug", None),
    (r"Tapo\s*P115", "TP-Link Tapo P115 Mini Plug", "smart_plug", None),
    (r"Tapo\s*P110M", "TP-Link Tapo P110M Matter Plug", "smart_plug", None),
    (r"Tapo\s*P110", "TP-Link Tapo P110 Mini Plug", "smart_plug", None),
    (r"Tapo\s*P105", "TP-Link Tapo P105 Mini Plug", "smart_plug", None),
    (r"Tapo\s*P100", "TP-Link Tapo P100 Mini Plug", "smart_plug", None),
    (r"Tapo\s*P400M", "TP-Link Tapo P400M Matter Outdoor Plug", "smart_plug", None),
    (r"Tapo\s*P400", "TP-Link Tapo P400 Outdoor Plug", "smart_plug", None),
    (r"Tapo\s*P300", "TP-Link Tapo P300 Power Strip", "smart_plug", None),
    (r"Tapo\s*P\d+", "TP-Link Tapo Smart Plug", "smart_plug", None),

    # Tapo Smart Lights
    (r"Tapo\s*L930", "TP-Link Tapo L930 Light Strip", "smart_bulb", None),
    (r"Tapo\s*L920", "TP-Link Tapo L920 Light Strip", "smart_bulb", None),
    (r"Tapo\s*L900", "TP-Link Tapo L900 Light Strip", "smart_bulb", None),
    (r"Tapo\s*L630", "TP-Link Tapo L630 Smart Bulb", "smart_bulb", None),
    (r"Tapo\s*L535E", "TP-Link Tapo L535E Multicolor Bulb", "smart_bulb", None),
    (r"Tapo\s*L530E", "TP-Link Tapo L530E Multicolor Bulb", "smart_bulb", None),
    (r"Tapo\s*L520E", "TP-Link Tapo L520E Smart Bulb", "smart_bulb", None),
    (r"Tapo\s*L510E", "TP-Link Tapo L510E Smart Bulb", "smart_bulb", None),
    (r"Tapo\s*L\d+", "TP-Link Tapo Smart Light", "smart_bulb", None),

    # Tapo Sensors
    (r"Tapo\s*T315", "TP-Link Tapo T315 Temp/Humidity Sensor", "sensor", None),
    (r"Tapo\s*T310", "TP-Link Tapo T310 Temp/Humidity Sensor", "sensor", None),
    (r"Tapo\s*T300", "TP-Link Tapo T300 Water Leak Sensor", "sensor", None),
    (r"Tapo\s*T110", "TP-Link Tapo T110 Contact Sensor", "sensor", None),
    (r"Tapo\s*T100", "TP-Link Tapo T100 Motion Sensor", "sensor", None),
    (r"Tapo\s*T\d+", "TP-Link Tapo Sensor", "sensor", None),

    # Tapo Smart Switches
    (r"Tapo\s*S505D", "TP-Link Tapo S505D Dimmer Switch", "smart_switch", None),
    (r"Tapo\s*S505", "TP-Link Tapo S505 Smart Switch", "smart_switch", None),
    (r"Tapo\s*S500D", "TP-Link Tapo S500D Dimmer Switch", "smart_switch", None),
    (r"Tapo\s*S500", "TP-Link Tapo S500 Smart Switch", "smart_switch", None),
    (r"Tapo\s*S220", "TP-Link Tapo S220 Smart Switch", "smart_switch", None),
    (r"Tapo\s*S210", "TP-Link Tapo S210 Smart Switch", "smart_switch", None),
    (r"Tapo\s*S200D", "TP-Link Tapo S200D Dimmer", "smart_switch", None),
    (r"Tapo\s*S200B", "TP-Link Tapo S200B Smart Button", "smart_switch", None),
    (r"Tapo\s*S\d+", "TP-Link Tapo Smart Switch", "smart_switch", None),

    # Tapo Robot Vacuum
    (r"Tapo\s*RV30\s*Plus", "TP-Link Tapo RV30 Plus Robot Vacuum", "robot_vacuum", None),
    (r"Tapo\s*RV30", "TP-Link Tapo RV30 Robot Vacuum", "robot_vacuum", None),
    (r"Tapo\s*RV20\s*Mop\s*Plus", "TP-Link Tapo RV20 Mop Plus", "robot_vacuum", None),
    (r"Tapo\s*RV20", "TP-Link Tapo RV20 Robot Vacuum", "robot_vacuum", None),
    (r"Tapo\s*RV10\s*Plus", "TP-Link Tapo RV10 Plus Robot Vacuum", "robot_vacuum", None),
    (r"Tapo\s*RV10", "TP-Link Tapo RV10 Robot Vacuum", "robot_vacuum", None),
    (r"Tapo\s*RV\d+", "TP-Link Tapo Robot Vacuum", "robot_vacuum", None),

    # Generic Tapo
    (r"Tapo\s*C\d+", "TP-Link Tapo Camera", "ip_camera", None),
    (r"Tapo", "TP-Link Tapo Device", "iot_device", None),

    # VIGI Security (Business Surveillance)
    (r"VIGI\s*C\d+", "TP-Link VIGI Camera", "ip_camera", None),
    (r"VIGI\s*NVR\d+", "TP-Link VIGI NVR", "nvr", None),
    (r"VIGI\s*C540V", "TP-Link VIGI C540V PTZ", "ptz_camera", None),
    (r"VIGI\s*C540", "TP-Link VIGI C540 Dome", "ip_camera", None),
    (r"VIGI\s*C455", "TP-Link VIGI C455 Bullet", "ip_camera", None),
    (r"VIGI\s*C450", "TP-Link VIGI C450 Turret", "ip_camera", None),
    (r"VIGI\s*C440", "TP-Link VIGI C440 Dome", "ip_camera", None),
    (r"VIGI\s*C350", "TP-Link VIGI C350 Turret", "ip_camera", None),
    (r"VIGI\s*C340", "TP-Link VIGI C340 ColorPro Bullet", "ip_camera", None),
    (r"VIGI\s*C330", "TP-Link VIGI C330 Bullet", "ip_camera", None),
    (r"VIGI\s*C320I", "TP-Link VIGI C320I Bullet", "ip_camera", None),
    (r"VIGI\s*C240", "TP-Link VIGI C240 Dome", "ip_camera", None),
    (r"VIGI\s*C230", "TP-Link VIGI C230 Turret", "ip_camera", None),
    (r"VIGI\s*C220I", "TP-Link VIGI C220I Dome", "ip_camera", None),
    (r"VIGI\s*NVR2016H", "TP-Link VIGI NVR2016H 16CH", "nvr", None),
    (r"VIGI\s*NVR1008H", "TP-Link VIGI NVR1008H 8CH", "nvr", None),
    (r"VIGI\s*NVR1004H", "TP-Link VIGI NVR1004H 4CH", "nvr", None),
    (r"VIGI", "TP-Link VIGI Security", "ip_camera", None),

    # Generic TP-Link
    (r"TP-Link.*Router", "TP-Link Router", "router", None),
    (r"TP-Link.*AP", "TP-Link Access Point", "access_point", None),
    (r"TP-Link.*Switch", "TP-Link Switch", "switch", None),
    (r"TP-Link", "TP-Link Device", "router", None),
    (r"Omada", "TP-Link Omada", "network_device", "Omada"),
]


# NETGEAR DEVICE PATTERNS

NETGEAR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:09:5B": ("network_device", "Network Equipment", "Netgear"),
    "00:0F:B5": ("network_device", "Network Equipment", "Netgear"),
    "00:14:6C": ("network_device", "Network Equipment", "Netgear"),
    "00:18:4D": ("network_device", "Network Equipment", "Netgear"),
    "00:1B:2F": ("network_device", "Network Equipment", "Netgear"),
    "00:1E:2A": ("network_device", "Network Equipment", "Netgear"),
    "00:1F:33": ("network_device", "Network Equipment", "Netgear"),
    "00:22:3F": ("network_device", "Network Equipment", "Netgear"),
    "00:24:B2": ("network_device", "Network Equipment", "Netgear"),
    "00:26:F2": ("network_device", "Network Equipment", "Netgear"),
    "00:8E:F2": ("network_device", "Network Equipment", "Netgear"),
    "04:A1:51": ("network_device", "Network Equipment", "Netgear"),
    "08:02:8E": ("network_device", "Network Equipment", "Netgear"),
    "08:36:C9": ("network_device", "Network Equipment", "Netgear"),
    "08:BD:43": ("network_device", "Network Equipment", "Netgear"),
    "10:0C:6B": ("network_device", "Network Equipment", "Netgear"),
    "10:0D:7F": ("network_device", "Network Equipment", "Netgear"),
    "10:DA:43": ("network_device", "Network Equipment", "Netgear"),
    "14:59:C0": ("network_device", "Network Equipment", "Netgear"),
    "20:0C:C8": ("network_device", "Network Equipment", "Netgear"),
    "20:4E:7F": ("network_device", "Network Equipment", "Netgear"),
    "20:E5:2A": ("network_device", "Network Equipment", "Netgear"),
    "28:80:88": ("network_device", "Network Equipment", "Netgear"),
    "28:94:01": ("network_device", "Network Equipment", "Netgear"),
    "28:C6:8E": ("nas", "Storage", "Netgear ReadyNAS"),
    "2C:30:33": ("network_device", "Network Equipment", "Netgear"),
    "2C:B0:5D": ("network_device", "Network Equipment", "Netgear"),
    "30:46:9A": ("network_device", "Network Equipment", "Netgear"),
    "34:98:B5": ("network_device", "Network Equipment", "Netgear"),
    "38:94:ED": ("network_device", "Network Equipment", "Netgear"),
    "3C:37:86": ("network_device", "Network Equipment", "Netgear"),
    "40:5D:82": ("network_device", "Network Equipment", "Netgear"),
    "44:94:FC": ("network_device", "Network Equipment", "Netgear"),
    "44:A5:6E": ("network_device", "Network Equipment", "Netgear"),
    "4C:60:DE": ("network_device", "Network Equipment", "Netgear"),
    "50:4A:6E": ("network_device", "Network Equipment", "Netgear"),
    "50:6A:03": ("network_device", "Network Equipment", "Netgear"),
    "54:07:7D": ("network_device", "Network Equipment", "Netgear"),
    "6C:B0:CE": ("network_device", "Network Equipment", "Netgear"),
    "6C:CD:D6": ("network_device", "Network Equipment", "Netgear"),
    "74:44:01": ("network_device", "Network Equipment", "Netgear"),
    "78:D2:94": ("network_device", "Network Equipment", "Netgear"),
    "80:37:73": ("network_device", "Network Equipment", "Netgear"),
    "80:CC:9C": ("network_device", "Network Equipment", "Netgear"),
    "84:1B:5E": ("network_device", "Network Equipment", "Netgear"),
    "8C:3B:AD": ("network_device", "Network Equipment", "Netgear"),
    "94:18:65": ("network_device", "Network Equipment", "Netgear"),
    "94:3B:22": ("network_device", "Network Equipment", "Netgear"),
    "94:A6:7E": ("network_device", "Network Equipment", "Netgear"),
    "9C:3D:CF": ("network_device", "Network Equipment", "Netgear"),
    "9C:C9:EB": ("network_device", "Network Equipment", "Netgear"),
    "9C:D3:6D": ("network_device", "Network Equipment", "Netgear"),
    "A0:04:60": ("network_device", "Network Equipment", "Netgear"),
    "A0:21:B7": ("network_device", "Network Equipment", "Netgear"),
    "A0:40:A0": ("network_device", "Network Equipment", "Netgear"),
    "A0:63:91": ("network_device", "Network Equipment", "Netgear"),
    "A4:2B:8C": ("network_device", "Network Equipment", "Netgear"),
    "B0:39:56": ("network_device", "Network Equipment", "Netgear"),
    "B0:7F:B9": ("network_device", "Network Equipment", "Netgear"),
    "B0:B9:8A": ("network_device", "Network Equipment", "Netgear"),
    "BC:A5:11": ("network_device", "Network Equipment", "Netgear"),
    "C0:3F:0E": ("network_device", "Network Equipment", "Netgear"),
    "C0:FF:D4": ("network_device", "Network Equipment", "Netgear"),
    "C4:04:15": ("network_device", "Network Equipment", "Netgear"),
    "C4:3D:C7": ("network_device", "Network Equipment", "Netgear"),
    "C8:10:2F": ("network_device", "Network Equipment", "Netgear"),
    "C8:9E:43": ("network_device", "Network Equipment", "Netgear"),
    "CC:40:D0": ("network_device", "Network Equipment", "Netgear"),
    "DC:EF:09": ("network_device", "Network Equipment", "Netgear"),
    "E0:46:9A": ("network_device", "Network Equipment", "Netgear"),
    "E0:46:EE": ("network_device", "Network Equipment", "Netgear"),
    "E0:91:F5": ("network_device", "Network Equipment", "Netgear"),
    "E0:C2:50": ("network_device", "Network Equipment", "Netgear"),
    "E4:F4:C6": ("network_device", "Network Equipment", "Netgear"),
    "E8:FC:AF": ("network_device", "Network Equipment", "Netgear"),
    "F8:73:94": ("network_device", "Network Equipment", "Netgear"),
}

NETGEAR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Nighthawk Routers
    (r"Nighthawk\s*[A-Z]*\d*", "Netgear Nighthawk", "router", None),
    (r"RAX\d+", "Netgear Nighthawk AX", "router", None),
    (r"RAX200", "Netgear Nighthawk RAX200", "router", None),
    (r"RAX120", "Netgear Nighthawk RAX120", "router", None),
    (r"RAX80", "Netgear Nighthawk RAX80", "router", None),
    (r"RAX50", "Netgear Nighthawk RAX50", "router", None),
    (r"R8000", "Netgear Nighthawk R8000", "router", None),
    (r"R7000", "Netgear Nighthawk R7000", "router", None),

    # Orbi Mesh WiFi System
    (r"Orbi\s*[A-Z]*\d*", "Netgear Orbi", "mesh_router", None),
    (r"RBK\d+", "Netgear Orbi Kit", "mesh_router", None),
    (r"RBR\d+", "Netgear Orbi Router", "mesh_router", None),
    (r"RBS\d+", "Netgear Orbi Satellite", "range_extender", None),
    (r"RBE\d+", "Netgear Orbi Outdoor", "mesh_router", None),

    # Switches
    (r"GS\d{3}", "Netgear Smart Switch", "switch", None),
    (r"GS108", "Netgear GS108", "switch", None),
    (r"GS116", "Netgear GS116", "switch", None),
    (r"GS308", "Netgear GS308", "switch", None),
    (r"GS316", "Netgear GS316", "switch", None),
    (r"GS324", "Netgear GS324", "switch", None),
    (r"GS748", "Netgear GS748", "switch", None),
    (r"JGS\d+", "Netgear ProSafe Switch", "switch", None),
    (r"M4\d{3}", "Netgear M4 Managed Switch", "switch", None),

    # ReadyNAS
    (r"ReadyNAS", "Netgear ReadyNAS", "nas", "ReadyNAS OS"),
    (r"RN\d{3}", "Netgear ReadyNAS", "nas", "ReadyNAS OS"),
    (r"RN212", "Netgear ReadyNAS 212", "nas", "ReadyNAS OS"),
    (r"RN214", "Netgear ReadyNAS 214", "nas", "ReadyNAS OS"),
    (r"RN424", "Netgear ReadyNAS 424", "nas", "ReadyNAS OS"),
    (r"RN426", "Netgear ReadyNAS 426", "nas", "ReadyNAS OS"),

    # WAX APs
    (r"WAX\d+", "Netgear WAX", "access_point", None),
    (r"WAX610", "Netgear WAX610", "access_point", None),
    (r"WAX620", "Netgear WAX620", "access_point", None),
    (r"WAX630", "Netgear WAX630", "access_point", None),

    # Generic
    (r"NETGEAR", "Netgear Device", "router", None),
]


# HIKVISION CAMERA PATTERNS

HIKVISION_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "18:68:CB": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "2C:A5:9C": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "44:19:B6": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "4C:BD:8F": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "54:C4:15": ("ip_camera", "Surveillance", "Hikvision Camera"),
    # REMOVED: 5C:E2:8C - IEEE assigns to Unknown, not HIKVISION
    # REMOVED: 64:D1:54 - IEEE assigns to Unknown, not HIKVISION
    "8C:E7:48": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "94:E1:AC": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "A4:14:37": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "B4:A3:82": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "BC:AD:28": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "C0:56:E3": ("ip_camera", "Surveillance", "Hikvision Camera"),
    "C4:2F:90": ("ip_camera", "Surveillance", "Hikvision Camera"),
}

HIKVISION_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # IP Cameras
    (r"DS-2CD\d+", "Hikvision IP Camera", "ip_camera", None),
    (r"DS-2CD2143G2", "Hikvision DS-2CD2143G2", "ip_camera", None),
    (r"DS-2CD2183G2", "Hikvision DS-2CD2183G2", "ip_camera", None),
    (r"DS-2CD2347G2", "Hikvision DS-2CD2347G2", "ip_camera", None),
    (r"DS-2CD2387G2", "Hikvision DS-2CD2387G2", "ip_camera", None),
    (r"DS-2CD2T47G2", "Hikvision DS-2CD2T47G2", "ip_camera", None),
    (r"DS-2CD2T87G2", "Hikvision DS-2CD2T87G2", "ip_camera", None),

    # PTZ Cameras
    (r"DS-2DE\d+", "Hikvision PTZ Camera", "ip_camera", None),
    (r"DS-2DF\d+", "Hikvision PTZ Camera", "ip_camera", None),

    # NVRs
    (r"DS-7\d+", "Hikvision NVR", "nvr", None),
    (r"DS-8\d+", "Hikvision NVR", "nvr", None),
    (r"DS-7608NI", "Hikvision DS-7608NI", "nvr", None),
    (r"DS-7616NI", "Hikvision DS-7616NI", "nvr", None),
    (r"DS-7732NI", "Hikvision DS-7732NI", "nvr", None),
    (r"DS-9632NI", "Hikvision DS-9632NI", "nvr", None),

    # DVRs
    (r"DS-7[0-4]\d+", "Hikvision DVR", "dvr", None),
    (r"iDS-\d+", "Hikvision AcuSense", "nvr", None),

    # Doorbells
    (r"DS-KV\d+", "Hikvision Video Intercom", "doorbell", None),
    (r"DS-HD1", "Hikvision Doorbell", "doorbell", None),

    # Generic
    (r"Hikvision", "Hikvision Device", "ip_camera", None),
    (r"HIKVISION", "Hikvision Device", "ip_camera", None),
]


# DAHUA CAMERA PATTERNS

DAHUA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "14:A7:8B": ("ip_camera", "Surveillance", "Dahua Camera"),
    "3C:EF:8C": ("ip_camera", "Surveillance", "Dahua Camera"),
    "40:DB:32": ("ip_camera", "Surveillance", "Dahua Camera"),
    "4C:11:BF": ("ip_camera", "Surveillance", "Dahua Camera"),
    "78:A9:AE": ("ip_camera", "Surveillance", "Dahua Camera"),
    "90:02:A9": ("ip_camera", "Surveillance", "Dahua Camera"),
    "9C:14:63": ("ip_camera", "Surveillance", "Dahua Camera"),
    "A0:BD:1D": ("ip_camera", "Surveillance", "Dahua Camera"),
    # REMOVED: E0:50:8B - IEEE assigns to Unknown, not DAHUA
    "E4:24:6C": ("ip_camera", "Surveillance", "Dahua Camera"),
}

DAHUA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # IP Cameras - DH- and IPC- prefixes are Dahua-specific
    (r"IPC-HDW\d+", "Dahua IP Camera", "ip_camera", None),
    (r"IPC-HFW\d+", "Dahua Bullet Camera", "ip_camera", None),
    (r"IPC-HDBW\d+", "Dahua Dome Camera", "ip_camera", None),
    (r"DH-IPC-HDW", "Dahua IP Camera", "ip_camera", None),
    (r"DH-IPC-HFW", "Dahua Bullet Camera", "ip_camera", None),

    # PTZ Cameras - require DH- or Dahua prefix to avoid conflict with other SD patterns
    (r"DH-SD\d+", "Dahua PTZ Camera", "ptz_camera", None),
    (r"Dahua\s*SD\d+", "Dahua PTZ Camera", "ptz_camera", None),

    # NVRs - DHI- prefix is Dahua-specific
    (r"DHI-NVR\d+", "Dahua NVR", "nvr", None),
    (r"Dahua\s*NVR\d+", "Dahua NVR", "nvr", None),
    (r"DHI-NVR4208", "Dahua NVR4208", "nvr", None),
    (r"DHI-NVR4216", "Dahua NVR4216", "nvr", None),
    (r"DHI-NVR4232", "Dahua NVR4232", "nvr", None),
    (r"DHI-NVR5208", "Dahua NVR5208", "nvr", None),
    (r"DHI-NVR5216", "Dahua NVR5216", "nvr", None),
    (r"DHI-NVR5232", "Dahua NVR5232", "nvr", None),

    # XVRs (Hybrid)
    (r"DHI-XVR\d+", "Dahua XVR", "dvr", None),
    (r"Dahua\s*XVR\d+", "Dahua XVR", "dvr", None),

    # Doorbells
    (r"DHI-VTO\d+", "Dahua Video Doorbell", "doorbell", None),
    (r"VTO\d+", "Dahua Video Doorbell", "doorbell", None),

    # Generic
    (r"Dahua", "Dahua Device", "ip_camera", None),
]


# PFSENSE / OPNSENSE FIREWALL PATTERNS

PFSENSE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"pfSense\s*([\d.]+)?", "pfSense Firewall", "firewall", "pfSense"),
    (r"pfSense-CE", "pfSense CE", "firewall", "pfSense"),
    (r"pfSense-Plus", "pfSense Plus", "firewall", "pfSense Plus"),
    (r"Netgate\s*\d+", "Netgate Appliance", "firewall", "pfSense"),
    (r"SG-\d+", "Netgate SG", "firewall", "pfSense"),
    (r"XG-\d+", "Netgate XG", "firewall", "pfSense"),
]

OPNSENSE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"OPNsense\s*([\d.]+)?", "OPNsense Firewall", "firewall", "OPNsense"),
    (r"Deciso\s*DEC\d+", "Deciso Appliance", "firewall", "OPNsense"),
]


# RUCKUS WIRELESS PATTERNS

RUCKUS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:13:92": ("access_point", "Network Equipment", "Ruckus AP"),
    "00:22:7F": ("access_point", "Network Equipment", "Ruckus AP"),
    "00:24:82": ("access_point", "Network Equipment", "Ruckus AP"),
    "00:25:C4": ("access_point", "Network Equipment", "Ruckus AP"),
    "24:79:2A": ("access_point", "Network Equipment", "Ruckus AP"),
    "2C:E6:CC": ("access_point", "Network Equipment", "Ruckus AP"),
    "58:B6:33": ("access_point", "Network Equipment", "Ruckus AP"),
    # REMOVED: 5C:AA:FD - IEEE assigns to Sonos Inc., not Ruckus
    "6C:AA:B3": ("access_point", "Network Equipment", "Ruckus AP"),
    "74:91:1A": ("access_point", "Network Equipment", "Ruckus AP"),
    "84:18:3A": ("access_point", "Network Equipment", "Ruckus AP"),
    "8C:0C:90": ("access_point", "Network Equipment", "Ruckus AP"),
    "90:3E:AB": ("access_point", "Network Equipment", "Ruckus AP"),
    "9C:F4:46": ("access_point", "Network Equipment", "Ruckus AP"),
    "A4:E3:C4": ("access_point", "Network Equipment", "Ruckus AP"),
    "B4:79:C8": ("access_point", "Network Equipment", "Ruckus AP"),
    "C8:46:56": ("access_point", "Network Equipment", "Ruckus AP"),
    "DC:AE:EB": ("access_point", "Network Equipment", "Ruckus AP"),
    "E0:22:04": ("access_point", "Network Equipment", "Ruckus AP"),
    "EC:58:EA": ("access_point", "Network Equipment", "Ruckus AP"),
    "F0:B0:52": ("access_point", "Network Equipment", "Ruckus AP"),
}

RUCKUS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # R Series APs
    (r"R\d{3}", "Ruckus R Series", "access_point", None),
    (r"R310", "Ruckus R310", "access_point", None),
    (r"R510", "Ruckus R510", "access_point", None),
    (r"R610", "Ruckus R610", "access_point", None),
    (r"R650", "Ruckus R650", "access_point", None),
    (r"R710", "Ruckus R710", "access_point", None),
    (r"R720", "Ruckus R720", "access_point", None),
    (r"R730", "Ruckus R730", "access_point", None),
    (r"R750", "Ruckus R750", "access_point", None),
    (r"R850", "Ruckus R850", "access_point", None),

    # T Series Outdoor APs
    (r"T\d{3}", "Ruckus T Series", "access_point", None),
    (r"T301", "Ruckus T301", "access_point", None),
    (r"T310", "Ruckus T310", "access_point", None),
    (r"T610", "Ruckus T610", "access_point", None),
    (r"T710", "Ruckus T710", "access_point", None),

    # Controllers
    (r"SmartZone\s*([\d.]+)?", "Ruckus SmartZone", "controller", "SmartZone"),
    (r"ZoneDirector\s*([\d.]+)?", "Ruckus ZoneDirector", "controller", None),
    (r"Unleashed\s*([\d.]+)?", "Ruckus Unleashed", "access_point", "Unleashed"),
    (r"vSZ", "Ruckus Virtual SmartZone", "controller", "SmartZone"),
    (r"SZ\d{3}", "Ruckus SmartZone", "controller", "SmartZone"),

    # ICX Switches
    (r"ICX\d+", "Ruckus ICX Switch", "switch", None),
    (r"ICX7150", "Ruckus ICX 7150", "switch", None),
    (r"ICX7250", "Ruckus ICX 7250", "switch", None),
    (r"ICX7450", "Ruckus ICX 7450", "switch", None),
    (r"ICX7650", "Ruckus ICX 7650", "switch", None),
    (r"ICX7850", "Ruckus ICX 7850", "switch", None),

    # Generic
    (r"Ruckus", "Ruckus Device", "access_point", None),
]


# JUNIPER DEVICE PATTERNS

JUNIPER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verified Juniper Networks IEEE OUI registrations (comprehensive)
    "00:05:85": ("router", "Network Equipment", "Juniper"),
    "00:10:DB": ("router", "Network Equipment", "Juniper"),
    "00:12:1E": ("router", "Network Equipment", "Juniper"),
    "00:14:F6": ("router", "Network Equipment", "Juniper"),
    "00:17:CB": ("router", "Network Equipment", "Juniper"),
    "00:19:E2": ("router", "Network Equipment", "Juniper"),
    "00:1B:C0": ("router", "Network Equipment", "Juniper"),
    "00:1D:B5": ("router", "Network Equipment", "Juniper"),
    "00:1F:12": ("router", "Network Equipment", "Juniper"),
    "00:21:59": ("router", "Network Equipment", "Juniper"),
    "00:22:83": ("router", "Network Equipment", "Juniper"),
    "00:23:9C": ("router", "Network Equipment", "Juniper"),
    "00:24:DC": ("router", "Network Equipment", "Juniper"),
    "00:26:88": ("router", "Network Equipment", "Juniper"),
    "00:31:46": ("network_device", "Network Equipment", "Juniper"),
    "00:90:69": ("network_device", "Network Equipment", "Juniper"),
    "00:C5:2C": ("network_device", "Network Equipment", "Juniper"),
    "00:CC:34": ("network_device", "Network Equipment", "Juniper"),
    "04:5C:6C": ("network_device", "Network Equipment", "Juniper"),
    "04:69:8F": ("network_device", "Network Equipment", "Juniper"),
    "08:05:E2": ("network_device", "Network Equipment", "Juniper"),
    "08:76:71": ("network_device", "Network Equipment", "Juniper"),
    "08:81:F4": ("network_device", "Network Equipment", "Juniper"),
    "08:B2:58": ("network_device", "Network Equipment", "Juniper"),
    "08:D0:1E": ("network_device", "Network Equipment", "Juniper"),
    "0C:59:9C": ("network_device", "Network Equipment", "Juniper"),
    "0C:81:26": ("network_device", "Network Equipment", "Juniper"),
    "0C:86:10": ("network_device", "Network Equipment", "Juniper"),
    "10:0E:7E": ("network_device", "Network Equipment", "Juniper"),
    "10:39:E9": ("network_device", "Network Equipment", "Juniper"),
    "14:B3:A1": ("network_device", "Network Equipment", "Juniper"),
    "18:2A:D3": ("network_device", "Network Equipment", "Juniper"),
    "1C:9C:8C": ("network_device", "Network Equipment", "Juniper"),
    "20:1B:C9": ("network_device", "Network Equipment", "Juniper"),
    "20:4E:71": ("network_device", "Network Equipment", "Juniper"),
    "20:93:39": ("network_device", "Network Equipment", "Juniper"),
    "20:D8:0B": ("network_device", "Network Equipment", "Juniper"),
    "20:ED:47": ("network_device", "Network Equipment", "Juniper"),
    "24:5D:92": ("network_device", "Network Equipment", "Juniper"),
    "24:DB:94": ("network_device", "Network Equipment", "Juniper"),
    "24:FC:4E": ("network_device", "Network Equipment", "Juniper"),
    "28:8A:1C": ("router", "Network Equipment", "Juniper"),
    "28:A2:4B": ("network_device", "Network Equipment", "Juniper"),
    "28:B8:29": ("network_device", "Network Equipment", "Juniper"),
    "28:C0:DA": ("router", "Network Equipment", "Juniper"),
    "2C:21:31": ("router", "Network Equipment", "Juniper"),
    "2C:21:72": ("network_device", "Network Equipment", "Juniper"),
    "2C:4C:15": ("network_device", "Network Equipment", "Juniper"),
    "2C:6B:F5": ("router", "Network Equipment", "Juniper"),
    "30:63:EA": ("network_device", "Network Equipment", "Juniper"),
    "30:7C:5E": ("network_device", "Network Equipment", "Juniper"),
    "30:B6:4F": ("network_device", "Network Equipment", "Juniper"),
    "34:28:65": ("network_device", "Network Equipment", "Juniper"),
    "34:93:6F": ("network_device", "Network Equipment", "Juniper"),
    "38:4F:49": ("network_device", "Network Equipment", "Juniper"),
    "38:6D:ED": ("network_device", "Network Equipment", "Juniper"),
    "38:F2:0D": ("network_device", "Network Equipment", "Juniper"),
    "3C:08:CD": ("network_device", "Network Equipment", "Juniper"),
    "3C:61:04": ("router", "Network Equipment", "Juniper"),
    "3C:8A:B0": ("router", "Network Equipment", "Juniper"),
    "3C:8C:93": ("network_device", "Network Equipment", "Juniper"),
    "3C:94:D5": ("network_device", "Network Equipment", "Juniper"),
    "40:36:B7": ("network_device", "Network Equipment", "Juniper"),
    "40:71:83": ("router", "Network Equipment", "Juniper"),
    "40:7F:5F": ("network_device", "Network Equipment", "Juniper"),
    "40:8F:9D": ("network_device", "Network Equipment", "Juniper"),
    "40:9E:A4": ("network_device", "Network Equipment", "Juniper"),
    "40:A6:77": ("router", "Network Equipment", "Juniper"),
    "40:B4:F0": ("network_device", "Network Equipment", "Juniper"),
    "40:DE:AD": ("network_device", "Network Equipment", "Juniper"),
    "44:AA:50": ("router", "Network Equipment", "Juniper"),
    "44:EC:CE": ("network_device", "Network Equipment", "Juniper"),
    "44:F4:77": ("router", "Network Equipment", "Juniper"),
    "48:5A:0D": ("network_device", "Network Equipment", "Juniper"),
    "48:73:10": ("network_device", "Network Equipment", "Juniper"),
    "4C:16:FC": ("network_device", "Network Equipment", "Juniper"),
    "4C:6D:58": ("network_device", "Network Equipment", "Juniper"),
    "4C:73:4F": ("network_device", "Network Equipment", "Juniper"),
    "4C:96:14": ("network_device", "Network Equipment", "Juniper"),
    "50:C5:8D": ("router", "Network Equipment", "Juniper"),
    "50:C7:09": ("network_device", "Network Equipment", "Juniper"),
    "54:1E:56": ("router", "Network Equipment", "Juniper"),
    "54:4B:8C": ("router", "Network Equipment", "Juniper"),
    "54:E0:32": ("network_device", "Network Equipment", "Juniper"),
    "58:00:BB": ("network_device", "Network Equipment", "Juniper"),
    "58:86:70": ("network_device", "Network Equipment", "Juniper"),
    "58:E4:34": ("network_device", "Network Equipment", "Juniper"),
    "5C:39:77": ("network_device", "Network Equipment", "Juniper"),
    "5C:45:27": ("router", "Network Equipment", "Juniper"),
    "5C:5E:AB": ("router", "Network Equipment", "Juniper"),
    "60:C7:8D": ("network_device", "Network Equipment", "Juniper"),
    "64:64:9B": ("router", "Network Equipment", "Juniper"),
    "64:87:88": ("router", "Network Equipment", "Juniper"),
    "64:AC:2B": ("network_device", "Network Equipment", "Juniper"),
    "64:C3:D6": ("network_device", "Network Equipment", "Juniper"),
    "68:22:8E": ("network_device", "Network Equipment", "Juniper"),
    "68:ED:57": ("network_device", "Network Equipment", "Juniper"),
    "68:F3:8E": ("network_device", "Network Equipment", "Juniper"),
    "6C:62:FE": ("network_device", "Network Equipment", "Juniper"),
    "6C:78:C1": ("network_device", "Network Equipment", "Juniper"),
    "74:29:72": ("network_device", "Network Equipment", "Juniper"),
    "74:E7:98": ("network_device", "Network Equipment", "Juniper"),
    "78:19:F7": ("router", "Network Equipment", "Juniper"),
    "78:4F:9B": ("network_device", "Network Equipment", "Juniper"),
    "78:50:7C": ("network_device", "Network Equipment", "Juniper"),
    "78:FE:3D": ("router", "Network Equipment", "Juniper"),
    "7C:25:86": ("network_device", "Network Equipment", "Juniper"),
    "7C:E2:CA": ("network_device", "Network Equipment", "Juniper"),
    "80:13:BE": ("network_device", "Network Equipment", "Juniper"),
    "80:43:3F": ("network_device", "Network Equipment", "Juniper"),
    "80:71:1F": ("router", "Network Equipment", "Juniper"),
    "80:7F:F8": ("network_device", "Network Equipment", "Juniper"),
    "80:AC:AC": ("router", "Network Equipment", "Juniper"),
    "80:DB:17": ("network_device", "Network Equipment", "Juniper"),
    "84:03:28": ("network_device", "Network Equipment", "Juniper"),
    "84:18:88": ("router", "Network Equipment", "Juniper"),
    "84:52:34": ("network_device", "Network Equipment", "Juniper"),
    "84:B5:9C": ("router", "Network Equipment", "Juniper"),
    "84:C1:C1": ("router", "Network Equipment", "Juniper"),
    "88:0A:A3": ("network_device", "Network Equipment", "Juniper"),
    "88:28:FB": ("network_device", "Network Equipment", "Juniper"),
    "88:30:37": ("network_device", "Network Equipment", "Juniper"),
    "88:90:09": ("network_device", "Network Equipment", "Juniper"),
    "88:A2:5E": ("router", "Network Equipment", "Juniper"),
    "88:D9:8F": ("network_device", "Network Equipment", "Juniper"),
    "88:E0:F3": ("router", "Network Equipment", "Juniper"),
    "88:E6:4B": ("network_device", "Network Equipment", "Juniper"),
    "94:BF:94": ("network_device", "Network Equipment", "Juniper"),
    "94:F7:AD": ("network_device", "Network Equipment", "Juniper"),
    "98:49:25": ("network_device", "Network Equipment", "Juniper"),
    "98:86:8B": ("network_device", "Network Equipment", "Juniper"),
    "9C:5A:80": ("network_device", "Network Equipment", "Juniper"),
    "9C:8A:CB": ("network_device", "Network Equipment", "Juniper"),
    "9C:C8:93": ("network_device", "Network Equipment", "Juniper"),
    "9C:CC:83": ("router", "Network Equipment", "Juniper"),
    "A4:51:5E": ("network_device", "Network Equipment", "Juniper"),
    "A4:7F:1B": ("network_device", "Network Equipment", "Juniper"),
    "A4:E1:1A": ("network_device", "Network Equipment", "Juniper"),
    "A8:D0:E5": ("router", "Network Equipment", "Juniper"),
    "AC:4B:C8": ("router", "Network Equipment", "Juniper"),
    "AC:78:D1": ("network_device", "Network Equipment", "Juniper"),
    "AC:A0:9D": ("network_device", "Network Equipment", "Juniper"),
    "B0:33:A6": ("network_device", "Network Equipment", "Juniper"),
    "B0:A8:6E": ("router", "Network Equipment", "Juniper"),
    "B0:C6:9A": ("router", "Network Equipment", "Juniper"),
    "B0:EB:7F": ("network_device", "Network Equipment", "Juniper"),
    "B4:16:78": ("network_device", "Network Equipment", "Juniper"),
    "B4:8A:5F": ("network_device", "Network Equipment", "Juniper"),
    "B4:F9:5D": ("network_device", "Network Equipment", "Juniper"),
    "B8:61:FC": ("network_device", "Network Equipment", "Juniper"),
    "B8:C2:53": ("network_device", "Network Equipment", "Juniper"),
    "B8:F0:15": ("network_device", "Network Equipment", "Juniper"),
    "BC:0F:FE": ("network_device", "Network Equipment", "Juniper"),
    "C0:03:80": ("network_device", "Network Equipment", "Juniper"),
    "C0:19:44": ("network_device", "Network Equipment", "Juniper"),
    "C0:42:D0": ("network_device", "Network Equipment", "Juniper"),
    "C0:BF:A7": ("network_device", "Network Equipment", "Juniper"),
    "C0:DF:ED": ("network_device", "Network Equipment", "Juniper"),
    "C4:09:B7": ("network_device", "Network Equipment", "Juniper"),
    "C8:13:37": ("network_device", "Network Equipment", "Juniper"),
    "C8:D9:95": ("network_device", "Network Equipment", "Juniper"),
    "C8:E7:F0": ("network_device", "Network Equipment", "Juniper"),
    "C8:FE:6A": ("network_device", "Network Equipment", "Juniper"),
    "CC:E1:7F": ("router", "Network Equipment", "Juniper"),
    "CC:E1:94": ("network_device", "Network Equipment", "Juniper"),
    "D0:07:CA": ("network_device", "Network Equipment", "Juniper"),
    "D0:48:A1": ("network_device", "Network Equipment", "Juniper"),
    "D0:81:C5": ("network_device", "Network Equipment", "Juniper"),
    "D0:DD:49": ("network_device", "Network Equipment", "Juniper"),
    "D4:04:FF": ("router", "Network Equipment", "Juniper"),
    "D4:5A:3F": ("network_device", "Network Equipment", "Juniper"),
    "D4:99:6C": ("network_device", "Network Equipment", "Juniper"),
    "D8:18:D3": ("network_device", "Network Equipment", "Juniper"),
    "D8:53:9A": ("network_device", "Network Equipment", "Juniper"),
    "D8:B1:22": ("network_device", "Network Equipment", "Juniper"),
    "DC:38:E1": ("router", "Network Equipment", "Juniper"),
    "E0:30:F9": ("network_device", "Network Equipment", "Juniper"),
    "E0:F6:2D": ("network_device", "Network Equipment", "Juniper"),
    "E4:23:3C": ("network_device", "Network Equipment", "Juniper"),
    "E4:5D:37": ("network_device", "Network Equipment", "Juniper"),
    "E4:5E:CC": ("network_device", "Network Equipment", "Juniper"),
    "E4:79:3F": ("network_device", "Network Equipment", "Juniper"),
    "E4:F2:7C": ("network_device", "Network Equipment", "Juniper"),
    "E4:FC:82": ("network_device", "Network Equipment", "Juniper"),
    "E8:24:A6": ("network_device", "Network Equipment", "Juniper"),
    "E8:A2:45": ("network_device", "Network Equipment", "Juniper"),
    "E8:A5:5A": ("network_device", "Network Equipment", "Juniper"),
    "E8:B6:C2": ("network_device", "Network Equipment", "Juniper"),
    "EC:13:DB": ("router", "Network Equipment", "Juniper"),
    "EC:38:73": ("network_device", "Network Equipment", "Juniper"),
    "EC:3E:F7": ("router", "Network Equipment", "Juniper"),
    "EC:7C:5C": ("network_device", "Network Equipment", "Juniper"),
    "EC:94:D5": ("network_device", "Network Equipment", "Juniper"),
    "F0:1C:2D": ("router", "Network Equipment", "Juniper"),
    "F0:4B:3A": ("network_device", "Network Equipment", "Juniper"),
    "F0:7C:C7": ("network_device", "Network Equipment", "Juniper"),
    "F0:D3:2B": ("network_device", "Network Equipment", "Juniper"),
    "F4:A7:39": ("router", "Network Equipment", "Juniper"),
    "F4:B5:2F": ("network_device", "Network Equipment", "Juniper"),
    "F4:BF:A8": ("network_device", "Network Equipment", "Juniper"),
    "F4:CC:55": ("router", "Network Equipment", "Juniper"),
    "F8:C0:01": ("router", "Network Equipment", "Juniper"),
    "F8:C1:16": ("network_device", "Network Equipment", "Juniper"),
    "FC:33:42": ("network_device", "Network Equipment", "Juniper"),
    "FC:96:43": ("network_device", "Network Equipment", "Juniper"),
}

JUNIPER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # SRX Firewalls
    (r"SRX\d+", "Juniper SRX", "firewall", "Junos"),
    (r"SRX300", "Juniper SRX300", "firewall", "Junos"),
    (r"SRX320", "Juniper SRX320", "firewall", "Junos"),
    (r"SRX340", "Juniper SRX340", "firewall", "Junos"),
    (r"SRX345", "Juniper SRX345", "firewall", "Junos"),
    (r"SRX380", "Juniper SRX380", "firewall", "Junos"),
    (r"SRX550", "Juniper SRX550", "firewall", "Junos"),
    (r"SRX1500", "Juniper SRX1500", "firewall", "Junos"),
    (r"SRX4100", "Juniper SRX4100", "firewall", "Junos"),
    (r"SRX4200", "Juniper SRX4200", "firewall", "Junos"),
    (r"SRX4600", "Juniper SRX4600", "firewall", "Junos"),
    (r"SRX5400", "Juniper SRX5400", "firewall", "Junos"),
    (r"SRX5600", "Juniper SRX5600", "firewall", "Junos"),
    (r"SRX5800", "Juniper SRX5800", "firewall", "Junos"),

    # MX Routers
    (r"MX\d+", "Juniper MX", "router", "Junos"),
    (r"MX80", "Juniper MX80", "router", "Junos"),
    (r"MX104", "Juniper MX104", "router", "Junos"),
    (r"MX150", "Juniper MX150", "router", "Junos"),
    (r"MX204", "Juniper MX204", "router", "Junos"),
    (r"MX240", "Juniper MX240", "router", "Junos"),
    (r"MX480", "Juniper MX480", "router", "Junos"),
    (r"MX960", "Juniper MX960", "router", "Junos"),
    (r"MX10003", "Juniper MX10003", "router", "Junos"),
    (r"MX10008", "Juniper MX10008", "router", "Junos"),
    (r"MX10016", "Juniper MX10016", "router", "Junos"),

    # EX Switches
    (r"EX\d+", "Juniper EX", "switch", "Junos"),
    (r"EX2200", "Juniper EX2200", "switch", "Junos"),
    (r"EX2300", "Juniper EX2300", "switch", "Junos"),
    (r"EX3300", "Juniper EX3300", "switch", "Junos"),
    (r"EX3400", "Juniper EX3400", "switch", "Junos"),
    (r"EX4200", "Juniper EX4200", "switch", "Junos"),
    (r"EX4300", "Juniper EX4300", "switch", "Junos"),
    (r"EX4400", "Juniper EX4400", "switch", "Junos"),
    (r"EX4600", "Juniper EX4600", "switch", "Junos"),
    (r"EX4650", "Juniper EX4650", "switch", "Junos"),
    (r"EX9200", "Juniper EX9200", "switch", "Junos"),
    (r"EX9250", "Juniper EX9250", "switch", "Junos"),

    # QFX Switches
    (r"QFX\d+", "Juniper QFX", "switch", "Junos"),
    (r"QFX5100", "Juniper QFX5100", "switch", "Junos"),
    (r"QFX5110", "Juniper QFX5110", "switch", "Junos"),
    (r"QFX5120", "Juniper QFX5120", "switch", "Junos"),
    (r"QFX5200", "Juniper QFX5200", "switch", "Junos"),
    (r"QFX5210", "Juniper QFX5210", "switch", "Junos"),
    (r"QFX5220", "Juniper QFX5220", "switch", "Junos"),
    (r"QFX10002", "Juniper QFX10002", "switch", "Junos"),
    (r"QFX10008", "Juniper QFX10008", "switch", "Junos"),
    (r"QFX10016", "Juniper QFX10016", "switch", "Junos"),

    # Mist APs
    (r"AP\d+", "Juniper Mist AP", "access_point", "Mist"),
    (r"AP12", "Juniper Mist AP12", "access_point", "Mist"),
    (r"AP21", "Juniper Mist AP21", "access_point", "Mist"),
    (r"AP32", "Juniper Mist AP32", "access_point", "Mist"),
    (r"AP33", "Juniper Mist AP33", "access_point", "Mist"),
    (r"AP34", "Juniper Mist AP34", "access_point", "Mist"),
    (r"AP41", "Juniper Mist AP41", "access_point", "Mist"),
    (r"AP43", "Juniper Mist AP43", "access_point", "Mist"),
    (r"AP45", "Juniper Mist AP45", "access_point", "Mist"),
    (r"AP61", "Juniper Mist AP61", "access_point", "Mist"),
    (r"AP63", "Juniper Mist AP63", "access_point", "Mist"),

    # Generic
    (r"JUNOS\s*([\d.]+)?", "Juniper Device", "router", "Junos"),
    (r"Junos\s*([\d.]+)?", "Juniper Device", "router", "Junos"),
    (r"Juniper", "Juniper Device", "router", "Junos"),
]


# DELL / DELL EMC PATTERNS

DELL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Dell Servers/Workstations
    "00:06:5B": ("server", "Computing", "Dell Server"),
    "00:08:74": ("server", "Computing", "Dell Server"),
    "00:0B:DB": ("server", "Computing", "Dell Server"),
    "00:0D:56": ("server", "Computing", "Dell Server"),
    "00:0F:1F": ("server", "Computing", "Dell Server"),
    "00:11:43": ("server", "Computing", "Dell Server"),
    "00:13:72": ("server", "Computing", "Dell Server"),
    "00:14:22": ("server", "Computing", "Dell Server"),
    "00:15:C5": ("server", "Computing", "Dell Server"),
    "00:18:8B": ("server", "Computing", "Dell Server"),
    "00:19:B9": ("server", "Computing", "Dell Server"),
    "00:1A:A0": ("server", "Computing", "Dell Server"),
    "00:1C:23": ("server", "Computing", "Dell Server"),
    "00:1D:09": ("server", "Computing", "Dell Server"),
    "00:1E:4F": ("server", "Computing", "Dell Server"),
    "00:1E:C9": ("server", "Computing", "Dell Server"),
    "00:21:9B": ("server", "Computing", "Dell Server"),
    "00:21:70": ("server", "Computing", "Dell Server"),
    "00:22:19": ("server", "Computing", "Dell Server"),
    "00:23:AE": ("server", "Computing", "Dell Server"),
    "00:24:E8": ("server", "Computing", "Dell Server"),
    "00:25:64": ("server", "Computing", "Dell Server"),
    "00:26:B9": ("server", "Computing", "Dell Server"),
    "14:18:77": ("server", "Computing", "Dell Server"),
    "14:B3:1F": ("server", "Computing", "Dell Server"),
    "14:FE:B5": ("server", "Computing", "Dell Server"),
    "18:03:73": ("server", "Computing", "Dell Server"),
    "18:66:DA": ("server", "Computing", "Dell Server"),
    "18:A9:9B": ("server", "Computing", "Dell Server"),
    "18:DB:F2": ("server", "Computing", "Dell Server"),
    "1C:40:24": ("server", "Computing", "Dell Server"),
    "20:47:47": ("server", "Computing", "Dell Server"),
    "24:6E:96": ("server", "Computing", "Dell Server"),
    "24:B6:FD": ("server", "Computing", "Dell Server"),
    "28:F1:0E": ("server", "Computing", "Dell Server"),
    "34:17:EB": ("server", "Computing", "Dell Server"),
    "34:48:ED": ("server", "Computing", "Dell Server"),
    "40:5C:FD": ("server", "Computing", "Dell Server"),
    "44:A8:42": ("server", "Computing", "Dell Server"),
    "4C:76:25": ("server", "Computing", "Dell Server"),
    "50:9A:4C": ("server", "Computing", "Dell Server"),
    "54:9F:35": ("server", "Computing", "Dell Server"),
    "5C:26:0A": ("server", "Computing", "Dell Server"),
    "5C:F9:DD": ("server", "Computing", "Dell Server"),
    "64:00:6A": ("server", "Computing", "Dell Server"),
    "74:86:7A": ("server", "Computing", "Dell Server"),
    "78:2B:CB": ("server", "Computing", "Dell Server"),
    "78:45:C4": ("server", "Computing", "Dell Server"),
    "80:18:44": ("server", "Computing", "Dell Server"),
    "84:2B:2B": ("server", "Computing", "Dell Server"),
    "84:7B:EB": ("server", "Computing", "Dell Server"),
    "88:6F:D4": ("server", "Computing", "Dell Server"),
    "90:B1:1C": ("server", "Computing", "Dell Server"),
    "98:90:96": ("server", "Computing", "Dell Server"),
    "A4:BA:DB": ("server", "Computing", "Dell Server"),
    "B0:83:FE": ("server", "Computing", "Dell Server"),
    "B4:E1:0F": ("server", "Computing", "Dell Server"),
    "B8:2A:72": ("server", "Computing", "Dell Server"),
    "B8:AC:6F": ("server", "Computing", "Dell Server"),
    "B8:CA:3A": ("server", "Computing", "Dell Server"),
    "BC:30:5B": ("server", "Computing", "Dell Server"),
    # REMOVED: C8:1F:66 - IEEE assigns to Unknown, not DELL
    "D0:67:E5": ("server", "Computing", "Dell Server"),
    "D4:81:D7": ("server", "Computing", "Dell Server"),
    "D4:AE:52": ("server", "Computing", "Dell Server"),
    "D4:BE:D9": ("server", "Computing", "Dell Server"),
    "E4:43:4B": ("server", "Computing", "Dell Server"),
    "EC:F4:BB": ("server", "Computing", "Dell Server"),
    "F0:1F:AF": ("server", "Computing", "Dell Server"),
    "F4:8E:38": ("server", "Computing", "Dell Server"),
    "F8:B1:56": ("server", "Computing", "Dell Server"),
    "F8:BC:12": ("server", "Computing", "Dell Server"),
    "F8:CA:B8": ("server", "Computing", "Dell Server"),
    "F8:DB:88": ("server", "Computing", "Dell Server"),

    # Dell Networking (switches)
    "00:01:E8": ("switch", "Network Equipment", "Dell Switch"),
    "00:1E:C9": ("switch", "Network Equipment", "Dell Switch"),
    "34:17:EB": ("switch", "Network Equipment", "Dell Switch"),
    "4C:76:25": ("switch", "Network Equipment", "Dell Switch"),
    "F4:8E:38": ("switch", "Network Equipment", "Dell Switch"),
}

DELL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # PowerEdge Servers
    (r"PowerEdge\s*[A-Z]?\d+", "Dell PowerEdge", "server", None),
    (r"PowerEdge\s*R\d+", "Dell PowerEdge Rack", "server", None),
    (r"PowerEdge\s*T\d+", "Dell PowerEdge Tower", "server", None),
    (r"PowerEdge\s*M\d+", "Dell PowerEdge Blade", "server", None),
    (r"PowerEdge\s*C\d+", "Dell PowerEdge Cloud", "server", None),
    (r"R640", "Dell PowerEdge R640", "server", None),
    (r"R740", "Dell PowerEdge R740", "server", None),
    (r"R750", "Dell PowerEdge R750", "server", None),
    (r"R760", "Dell PowerEdge R760", "server", None),
    (r"T640", "Dell PowerEdge T640", "server", None),
    (r"T440", "Dell PowerEdge T440", "server", None),

    # Dell Networking
    (r"Dell\s*N\d{4}", "Dell N-Series Switch", "switch", None),
    (r"Dell\s*S\d{4}", "Dell S-Series Switch", "switch", None),
    (r"S4048", "Dell S4048-ON", "switch", None),
    (r"S5248", "Dell S5248F-ON", "switch", None),
    (r"N1548", "Dell N1548", "switch", None),
    (r"N3048", "Dell N3048", "switch", None),
    (r"PowerSwitch", "Dell PowerSwitch", "switch", None),

    # iDRAC
    (r"iDRAC\d?", "Dell iDRAC", "management", "iDRAC"),
    (r"Integrated Dell Remote Access", "Dell iDRAC", "management", "iDRAC"),

    # Storage
    (r"PowerVault", "Dell PowerVault", "storage", None),
    (r"EqualLogic", "Dell EqualLogic", "storage", None),
    (r"Compellent", "Dell Compellent", "storage", None),
    (r"PowerScale", "Dell PowerScale", "storage", None),
    (r"PowerStore", "Dell PowerStore", "storage", None),

    # Generic
    (r"Dell\s*Inc", "Dell Device", "server", None),
    (r"Dell\s*EMC", "Dell EMC Device", "storage", None),
]


# HPE (HP ENTERPRISE) PATTERNS

HPE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # HPE Servers
    "00:11:0A": ("server", "Computing", "HPE Server"),
    "00:14:38": ("server", "Computing", "HPE Server"),
    "00:17:A4": ("server", "Computing", "HPE Server"),
    "00:18:71": ("server", "Computing", "HPE Server"),
    "00:1B:78": ("server", "Computing", "HPE Server"),
    "00:1E:0B": ("server", "Computing", "HPE Server"),
    "00:1F:29": ("server", "Computing", "HPE Server"),
    "00:21:5A": ("server", "Computing", "HPE Server"),
    "00:22:64": ("server", "Computing", "HPE Server"),
    "00:23:7D": ("server", "Computing", "HPE Server"),
    "00:24:81": ("server", "Computing", "HPE Server"),
    "00:25:B3": ("server", "Computing", "HPE Server"),
    "00:26:55": ("server", "Computing", "HPE Server"),
    "08:2E:5F": ("server", "Computing", "HPE Server"),
    "14:02:EC": ("server", "Computing", "HPE Server"),
    "14:58:D0": ("server", "Computing", "HPE Server"),
    "1C:98:EC": ("server", "Computing", "HPE Server"),
    "2C:44:FD": ("server", "Computing", "HPE Server"),
    "2C:59:E5": ("server", "Computing", "HPE Server"),
    "38:63:BB": ("server", "Computing", "HPE Server"),
    "3C:4A:92": ("server", "Computing", "HPE Server"),
    "48:0F:CF": ("server", "Computing", "HPE Server"),
    "48:DF:37": ("server", "Computing", "HPE Server"),
    # REMOVED: 64:51:06 - IEEE assigns to Unknown, not HPE
    "6C:3B:E5": ("server", "Computing", "HPE Server"),
    "70:10:6F": ("server", "Computing", "HPE Server"),
    "80:30:E0": ("server", "Computing", "HPE Server"),
    "84:34:97": ("server", "Computing", "HPE Server"),
    "8C:DC:D4": ("server", "Computing", "HPE Server"),
    "94:18:82": ("server", "Computing", "HPE Server"),
    "98:4B:E1": ("server", "Computing", "HPE Server"),
    "98:E7:F4": ("server", "Computing", "HPE Server"),
    "9C:8E:99": ("server", "Computing", "HPE Server"),
    "A0:1D:48": ("server", "Computing", "HPE Server"),
    "A4:5D:36": ("server", "Computing", "HPE Server"),
    "B0:5A:DA": ("server", "Computing", "HPE Server"),
    "B4:99:BA": ("server", "Computing", "HPE Server"),
    "BC:EA:FA": ("server", "Computing", "HPE Server"),
    "D0:7E:28": ("server", "Computing", "HPE Server"),
    "D4:C9:EF": ("server", "Computing", "HPE Server"),
    "D8:9D:67": ("server", "Computing", "HPE Server"),
    "E4:11:5B": ("server", "Computing", "HPE Server"),
    "EC:B1:D7": ("server", "Computing", "HPE Server"),
    "F0:92:1C": ("server", "Computing", "HPE Server"),

    # HPE Networking
    "00:08:83": ("switch", "Network Equipment", "HPE Switch"),
    "00:0B:CD": ("switch", "Network Equipment", "HPE Switch"),
    "00:0D:9D": ("switch", "Network Equipment", "HPE Switch"),
    "00:0F:20": ("switch", "Network Equipment", "HPE Switch"),
    "00:11:85": ("switch", "Network Equipment", "HPE Switch"),
    "00:12:79": ("switch", "Network Equipment", "HPE Switch"),
    "00:13:21": ("switch", "Network Equipment", "HPE Switch"),
    "00:15:60": ("switch", "Network Equipment", "HPE Switch"),
    "00:17:08": ("switch", "Network Equipment", "HPE Switch"),
    "00:18:FE": ("switch", "Network Equipment", "HPE Switch"),
    # REMOVED: 00:1A:4B - IEEE assigns to Unknown, not HPE
    "00:1E:0B": ("switch", "Network Equipment", "HPE Switch"),
    "2C:27:D7": ("switch", "Network Equipment", "HPE Switch"),
    "30:8D:99": ("switch", "Network Equipment", "HPE Switch"),
    "5C:B9:01": ("switch", "Network Equipment", "HPE Switch"),
    # REMOVED: 64:51:06 - IEEE assigns to Unknown, not HPE
    "78:AC:C0": ("switch", "Network Equipment", "HPE Switch"),
    "80:C1:6E": ("switch", "Network Equipment", "HPE Switch"),
    "94:57:A5": ("switch", "Network Equipment", "HPE Switch"),
}

HPE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ProLiant Servers
    (r"ProLiant\s*[A-Z]{2}\d+", "HPE ProLiant", "server", None),
    (r"ProLiant\s*DL\d+", "HPE ProLiant Rack", "server", None),
    (r"ProLiant\s*ML\d+", "HPE ProLiant Tower", "server", None),
    (r"ProLiant\s*BL\d+", "HPE ProLiant Blade", "server", None),
    (r"DL380", "HPE ProLiant DL380", "server", None),
    (r"DL360", "HPE ProLiant DL360", "server", None),
    (r"DL560", "HPE ProLiant DL560", "server", None),
    (r"ML350", "HPE ProLiant ML350", "server", None),
    (r"BL460", "HPE ProLiant BL460", "server", None),

    # HPE Networking (ProCurve/OfficeConnect)
    (r"ProCurve\s*\d+", "HPE ProCurve Switch", "switch", None),
    (r"OfficeConnect\s*\d+", "HPE OfficeConnect", "switch", None),
    (r"FlexFabric\s*\d+", "HPE FlexFabric Switch", "switch", None),
    (r"5130", "HPE 5130 Switch", "switch", None),
    (r"5940", "HPE 5940 Switch", "switch", None),
    (r"5945", "HPE 5945 Switch", "switch", None),
    (r"5950", "HPE 5950 Switch", "switch", None),
    (r"5710", "HPE 5710 Switch", "switch", None),
    (r"5510", "HPE 5510 Switch", "switch", None),
    (r"2930F", "HPE 2930F Switch", "switch", None),
    (r"2930M", "HPE 2930M Switch", "switch", None),
    (r"2920", "HPE 2920 Switch", "switch", None),

    # iLO
    (r"iLO\s*\d?", "HPE iLO", "management", "iLO"),
    (r"Integrated Lights-Out", "HPE iLO", "management", "iLO"),

    # Storage
    (r"Nimble", "HPE Nimble", "storage", None),
    (r"StoreServ", "HPE StoreServ", "storage", None),
    (r"3PAR", "HPE 3PAR", "storage", None),
    (r"Primera", "HPE Primera", "storage", None),
    (r"Alletra", "HPE Alletra", "storage", None),
    (r"MSA\s*\d+", "HPE MSA", "storage", None),
    (r"StoreVirtual", "HPE StoreVirtual", "storage", None),

    # Generic
    (r"HPE", "HPE Device", "server", None),
    (r"Hewlett\s*Packard\s*Enterprise", "HPE Device", "server", None),
]


# AXIS COMMUNICATIONS CAMERA PATTERNS

AXIS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Axis Communications OUI assignments
    "00:40:8C": ("ip_camera", "Surveillance", "Axis Camera"),
    "AC:CC:8E": ("ip_camera", "Surveillance", "Axis Camera"),
    "B8:A4:4F": ("ip_camera", "Surveillance", "Axis Camera"),
}

AXIS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Fixed cameras - P series (Professional)
    (r"AXIS\s*P3255-LVE", "Axis P3255-LVE", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P3265-LVE", "Axis P3265-LVE", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P3268-SLVE", "Axis P3268-SLVE", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P3245-V", "Axis P3245-V", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P3245-LVE", "Axis P3245-LVE", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P32\d{2}", "Axis P32xx Camera", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P14\d{2}", "Axis P14xx Camera", "ip_camera", "AXIS OS"),
    (r"AXIS\s*P55\d{2}", "Axis P55xx PTZ Camera", "ptz_camera", "AXIS OS"),

    # Fixed cameras - M series (Main line)
    (r"AXIS\s*M3115-LVE", "Axis M3115-LVE", "ip_camera", "AXIS OS"),
    (r"AXIS\s*M3116-LVE", "Axis M3116-LVE", "ip_camera", "AXIS OS"),
    (r"AXIS\s*M3106-L", "Axis M3106-L", "ip_camera", "AXIS OS"),
    (r"AXIS\s*M3085-V", "Axis M3085-V", "ip_camera", "AXIS OS"),
    (r"AXIS\s*M31\d{2}", "Axis M31xx Camera", "ip_camera", "AXIS OS"),
    (r"AXIS\s*M30\d{2}", "Axis M30xx Camera", "ip_camera", "AXIS OS"),
    (r"AXIS\s*M20\d{2}", "Axis M20xx Camera", "ip_camera", "AXIS OS"),

    # PTZ cameras - Q series
    (r"AXIS\s*Q6135-LE", "Axis Q6135-LE PTZ", "ptz_camera", "AXIS OS"),
    (r"AXIS\s*Q6128-E", "Axis Q6128-E PTZ", "ptz_camera", "AXIS OS"),
    (r"AXIS\s*Q6125-LE", "Axis Q6125-LE PTZ", "ptz_camera", "AXIS OS"),
    (r"AXIS\s*Q61\d{2}", "Axis Q61xx PTZ", "ptz_camera", "AXIS OS"),
    (r"AXIS\s*Q60\d{2}", "Axis Q60xx PTZ", "ptz_camera", "AXIS OS"),

    # Thermal cameras
    (r"AXIS\s*Q19\d{2}", "Axis Q19xx Thermal", "thermal_camera", "AXIS OS"),
    (r"AXIS\s*Q29\d{2}", "Axis Q29xx Thermal", "thermal_camera", "AXIS OS"),

    # Video encoders
    (r"AXIS\s*M7116", "Axis M7116 Encoder", "video_encoder", "AXIS OS"),
    (r"AXIS\s*P7316", "Axis P7316 Encoder", "video_encoder", "AXIS OS"),
    (r"AXIS\s*P72\d{2}", "Axis P72xx Encoder", "video_encoder", "AXIS OS"),

    # Network video recorders
    (r"AXIS\s*S30\d{2}", "Axis S30xx Recorder", "nvr", "AXIS OS"),
    (r"AXIS\s*S22\d{2}", "Axis S22xx Recorder", "nvr", "AXIS OS"),

    # Door controllers / Access control
    (r"AXIS\s*A16\d{2}", "Axis A16xx Door Controller", "access_controller", "AXIS OS"),
    (r"AXIS\s*A12\d{2}", "Axis A12xx Door Controller", "access_controller", "AXIS OS"),

    # Audio devices
    (r"AXIS\s*C14\d{2}", "Axis C14xx Speaker", "speaker", "AXIS OS"),
    (r"AXIS\s*C12\d{2}", "Axis C12xx Speaker", "speaker", "AXIS OS"),

    # Generic Axis
    (r"AXIS\s*[A-Z]\d{4}", "Axis Device", "ip_camera", "AXIS OS"),
    (r"Axis\s*Communications", "Axis Device", "ip_camera", "AXIS OS"),
]


# PALO ALTO NETWORKS FIREWALL PATTERNS

PALOALTO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verified Palo Alto Networks IEEE OUI registrations
    "00:1B:17": ("firewall", "Network Equipment", "Palo Alto Firewall"),  # Confirmed PA Networks OUI
    "00:86:9C": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "00:DA:27": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "04:47:2A": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "08:03:42": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "08:30:6B": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "08:66:1F": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "1C:CF:82": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "24:0B:0A": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "34:E5:EC": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "3C:FA:30": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "58:49:3B": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "58:76:9C": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "5C:58:E6": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "60:15:2B": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "64:7C:E8": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "78:6D:94": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "7C:89:C1": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "7C:C0:25": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "7C:C7:90": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "84:D4:12": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "8C:36:7A": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "94:56:41": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "A4:27:A5": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "B4:0C:25": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "C4:24:56": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "C8:29:C8": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "CC:38:D0": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "CC:5E:A5": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "D4:1D:71": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "D4:9C:F4": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "D4:F4:BE": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "DC:0E:96": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "E4:A7:49": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "E8:98:6D": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "EC:68:81": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "F4:D5:8A": ("firewall", "Network Equipment", "Palo Alto Firewall"),
    "FC:10:1A": ("firewall", "Network Equipment", "Palo Alto Firewall"),
}

PALOALTO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # PA Series firewalls
    (r"PA-220", "Palo Alto PA-220", "firewall", "PAN-OS"),
    (r"PA-440", "Palo Alto PA-440", "firewall", "PAN-OS"),
    (r"PA-450", "Palo Alto PA-450", "firewall", "PAN-OS"),
    (r"PA-460", "Palo Alto PA-460", "firewall", "PAN-OS"),
    (r"PA-820", "Palo Alto PA-820", "firewall", "PAN-OS"),
    (r"PA-850", "Palo Alto PA-850", "firewall", "PAN-OS"),
    (r"PA-3220", "Palo Alto PA-3220", "firewall", "PAN-OS"),
    (r"PA-3250", "Palo Alto PA-3250", "firewall", "PAN-OS"),
    (r"PA-3260", "Palo Alto PA-3260", "firewall", "PAN-OS"),
    (r"PA-5220", "Palo Alto PA-5220", "firewall", "PAN-OS"),
    (r"PA-5250", "Palo Alto PA-5250", "firewall", "PAN-OS"),
    (r"PA-5260", "Palo Alto PA-5260", "firewall", "PAN-OS"),
    (r"PA-5280", "Palo Alto PA-5280", "firewall", "PAN-OS"),
    (r"PA-5450", "Palo Alto PA-5450", "firewall", "PAN-OS"),
    (r"PA-7050", "Palo Alto PA-7050", "firewall", "PAN-OS"),
    (r"PA-7080", "Palo Alto PA-7080", "firewall", "PAN-OS"),

    # VM Series virtual firewalls
    (r"VM-50", "Palo Alto VM-50", "virtual_firewall", "PAN-OS"),
    (r"VM-100", "Palo Alto VM-100", "virtual_firewall", "PAN-OS"),
    (r"VM-300", "Palo Alto VM-300", "virtual_firewall", "PAN-OS"),
    (r"VM-500", "Palo Alto VM-500", "virtual_firewall", "PAN-OS"),
    (r"VM-700", "Palo Alto VM-700", "virtual_firewall", "PAN-OS"),
    (r"VM-1000-HV", "Palo Alto VM-1000-HV", "virtual_firewall", "PAN-OS"),

    # Prisma Access
    (r"Prisma\s*Access", "Palo Alto Prisma Access", "cloud_firewall", "Prisma"),
    (r"GlobalProtect", "Palo Alto GlobalProtect", "vpn", "PAN-OS"),

    # Panorama management
    (r"Panorama", "Palo Alto Panorama", "management", "PAN-OS"),
    (r"M-[125]00", "Palo Alto Panorama M-Series", "management", "PAN-OS"),

    # Generic PAN-OS
    (r"PAN-OS", "Palo Alto Device", "firewall", "PAN-OS"),
    (r"Palo\s*Alto\s*Networks", "Palo Alto Device", "firewall", "PAN-OS"),
]


# SOPHOS / WATCHGUARD FIREWALL PATTERNS

SOPHOS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verified Sophos Ltd IEEE OUI registrations
    "00:1A:8C": ("firewall", "Network Equipment", "Sophos Firewall"),
    "7C:5A:1C": ("firewall", "Network Equipment", "Sophos Firewall"),
    "A8:91:62": ("firewall", "Network Equipment", "Sophos Firewall"),
    "C8:4F:86": ("firewall", "Network Equipment", "Sophos Firewall"),
}

SOPHOS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # XG/XGS Series
    (r"XGS\s*87", "Sophos XGS 87", "firewall", "SFOS"),
    (r"XGS\s*107", "Sophos XGS 107", "firewall", "SFOS"),
    (r"XGS\s*116", "Sophos XGS 116", "firewall", "SFOS"),
    (r"XGS\s*126", "Sophos XGS 126", "firewall", "SFOS"),
    (r"XGS\s*136", "Sophos XGS 136", "firewall", "SFOS"),
    (r"XGS\s*2100", "Sophos XGS 2100", "firewall", "SFOS"),
    (r"XGS\s*2300", "Sophos XGS 2300", "firewall", "SFOS"),
    (r"XGS\s*3100", "Sophos XGS 3100", "firewall", "SFOS"),
    (r"XGS\s*3300", "Sophos XGS 3300", "firewall", "SFOS"),
    (r"XGS\s*4300", "Sophos XGS 4300", "firewall", "SFOS"),
    (r"XGS\s*4500", "Sophos XGS 4500", "firewall", "SFOS"),
    (r"XG\s*\d+", "Sophos XG Firewall", "firewall", "SFOS"),

    # SG Series (UTM)
    (r"SG\s*105", "Sophos SG 105", "firewall", "UTM"),
    (r"SG\s*115", "Sophos SG 115", "firewall", "UTM"),
    (r"SG\s*125", "Sophos SG 125", "firewall", "UTM"),
    (r"SG\s*135", "Sophos SG 135", "firewall", "UTM"),
    (r"SG\s*210", "Sophos SG 210", "firewall", "UTM"),
    (r"SG\s*230", "Sophos SG 230", "firewall", "UTM"),
    (r"SG\s*310", "Sophos SG 310", "firewall", "UTM"),
    (r"SG\s*330", "Sophos SG 330", "firewall", "UTM"),
    (r"SG\s*430", "Sophos SG 430", "firewall", "UTM"),
    (r"SG\s*450", "Sophos SG 450", "firewall", "UTM"),
    (r"SG\s*550", "Sophos SG 550", "firewall", "UTM"),
    (r"SG\s*650", "Sophos SG 650", "firewall", "UTM"),

    # Access Points
    (r"AP\s*6\d{2}", "Sophos AP6 Series", "access_point", "Sophos Central"),
    (r"APX\s*\d+", "Sophos APX Series", "access_point", "Sophos Central"),

    # Sophos Central
    (r"Sophos\s*Central", "Sophos Central", "management", "Sophos Central"),
    (r"Sophos\s*Firewall", "Sophos Firewall", "firewall", "SFOS"),
    (r"Sophos\s*UTM", "Sophos UTM", "firewall", "UTM"),
]

WATCHGUARD_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:90:7F": ("firewall", "Network Equipment", "WatchGuard Firewall"),
    # REMOVED: 00:0C:43 - IEEE assigns to Ralink Technology (MediaTek), not WatchGuard
}

WATCHGUARD_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Firebox Series
    (r"Firebox\s*T20", "WatchGuard Firebox T20", "firewall", "Fireware"),
    (r"Firebox\s*T40", "WatchGuard Firebox T40", "firewall", "Fireware"),
    (r"Firebox\s*T55", "WatchGuard Firebox T55", "firewall", "Fireware"),
    (r"Firebox\s*T80", "WatchGuard Firebox T80", "firewall", "Fireware"),
    (r"Firebox\s*M290", "WatchGuard Firebox M290", "firewall", "Fireware"),
    (r"Firebox\s*M390", "WatchGuard Firebox M390", "firewall", "Fireware"),
    (r"Firebox\s*M490", "WatchGuard Firebox M490", "firewall", "Fireware"),
    (r"Firebox\s*M590", "WatchGuard Firebox M590", "firewall", "Fireware"),
    (r"Firebox\s*M690", "WatchGuard Firebox M690", "firewall", "Fireware"),
    (r"Firebox\s*M4800", "WatchGuard Firebox M4800", "firewall", "Fireware"),
    (r"Firebox\s*M5800", "WatchGuard Firebox M5800", "firewall", "Fireware"),

    # Cloud/Virtual
    (r"FireboxV", "WatchGuard FireboxV", "virtual_firewall", "Fireware"),
    (r"Firebox\s*Cloud", "WatchGuard Firebox Cloud", "cloud_firewall", "Fireware"),

    # Access Points
    (r"AP\s*120", "WatchGuard AP120", "access_point", "Fireware"),
    (r"AP\s*125", "WatchGuard AP125", "access_point", "Fireware"),
    (r"AP\s*130", "WatchGuard AP130", "access_point", "Fireware"),
    (r"AP\s*230", "WatchGuard AP230", "access_point", "Fireware"),
    (r"AP\s*330", "WatchGuard AP330", "access_point", "Fireware"),
    (r"AP\s*430CR", "WatchGuard AP430CR", "access_point", "Fireware"),

    # Generic
    (r"WatchGuard", "WatchGuard Device", "firewall", "Fireware"),
    (r"Fireware", "WatchGuard Device", "firewall", "Fireware"),
]


# EXTREME NETWORKS PATTERNS

EXTREME_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:01:30": ("switch", "Network Equipment", "Extreme Switch"),
    "00:04:96": ("switch", "Network Equipment", "Extreme Switch"),
    "00:E0:2B": ("switch", "Network Equipment", "Extreme Switch"),
    "B4:C7:99": ("switch", "Network Equipment", "Extreme Switch"),
    "B8:50:01": ("switch", "Network Equipment", "Extreme Switch"),
    # REMOVED: D8:84:66 - IEEE assigns to Unknown, not EXTREME
    # Aerohive (acquired)
    # REMOVED: 00:19:77 - IEEE assigns to Unknown, not EXTREME
    # REMOVED: 04:BD:88 - IEEE assigns to Unknown, not EXTREME
    # REMOVED: 40:18:B1 - IEEE assigns to Unknown, not EXTREME
    # REMOVED: 88:5B:DD - IEEE assigns to Unknown, not EXTREME
    # REMOVED: E0:1C:41 - IEEE assigns to Unknown, not EXTREME
}

EXTREME_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ExtremeXOS switches
    (r"X4\d{2}", "Extreme X4xx Switch", "switch", "ExtremeXOS"),
    (r"X4\d{2}G", "Extreme X4xx Switch", "switch", "ExtremeXOS"),
    (r"X460", "Extreme X460 Switch", "switch", "ExtremeXOS"),
    (r"X465", "Extreme X465 Switch", "switch", "ExtremeXOS"),
    (r"X590", "Extreme X590 Switch", "switch", "ExtremeXOS"),
    (r"X620", "Extreme X620 Switch", "switch", "ExtremeXOS"),
    (r"X690", "Extreme X690 Switch", "switch", "ExtremeXOS"),
    (r"X695", "Extreme X695 Switch", "switch", "ExtremeXOS"),
    (r"X870", "Extreme X870 Switch", "switch", "ExtremeXOS"),

    # VSP (Fabric Engine)
    (r"VSP\s*4450", "Extreme VSP 4450", "switch", "Fabric Engine"),
    (r"VSP\s*4900", "Extreme VSP 4900", "switch", "Fabric Engine"),
    (r"VSP\s*7200", "Extreme VSP 7200", "switch", "Fabric Engine"),
    (r"VSP\s*7400", "Extreme VSP 7400", "switch", "Fabric Engine"),
    (r"VSP\s*8200", "Extreme VSP 8200", "switch", "Fabric Engine"),
    (r"VSP\s*8400", "Extreme VSP 8400", "switch", "Fabric Engine"),
    (r"VSP\s*8600", "Extreme VSP 8600", "switch", "Fabric Engine"),

    # SLX (Data Center)
    (r"SLX\s*9030", "Extreme SLX 9030", "switch", "SLX-OS"),
    (r"SLX\s*9140", "Extreme SLX 9140", "switch", "SLX-OS"),
    (r"SLX\s*9150", "Extreme SLX 9150", "switch", "SLX-OS"),
    (r"SLX\s*9250", "Extreme SLX 9250", "switch", "SLX-OS"),
    (r"SLX\s*9540", "Extreme SLX 9540", "switch", "SLX-OS"),
    (r"SLX\s*9640", "Extreme SLX 9640", "switch", "SLX-OS"),
    (r"SLX\s*9740", "Extreme SLX 9740", "switch", "SLX-OS"),

    # Access Points (Aerohive)
    (r"AP\s*121", "Extreme AP121", "access_point", "HiveOS"),
    (r"AP\s*122", "Extreme AP122", "access_point", "HiveOS"),
    (r"AP\s*130", "Extreme AP130", "access_point", "HiveOS"),
    (r"AP\s*230", "Extreme AP230", "access_point", "HiveOS"),
    (r"AP\s*250", "Extreme AP250", "access_point", "HiveOS"),
    (r"AP\s*302W", "Extreme AP302W", "access_point", "HiveOS"),
    (r"AP\s*305C", "Extreme AP305C", "access_point", "HiveOS"),
    (r"AP\s*360", "Extreme AP360", "access_point", "HiveOS"),
    (r"AP\s*460", "Extreme AP460", "access_point", "HiveOS"),
    (r"AP\s*560", "Extreme AP560", "access_point", "HiveOS"),

    # ExtremeCloud IQ
    (r"ExtremeCloud\s*IQ", "Extreme Cloud IQ", "management", "ExtremeCloud"),
    (r"XIQ", "Extreme Cloud IQ", "management", "ExtremeCloud"),

    # Generic
    (r"ExtremeXOS", "Extreme Switch", "switch", "ExtremeXOS"),
    (r"Extreme\s*Networks", "Extreme Device", "switch", "ExtremeXOS"),
]


# CHECK POINT FIREWALL PATTERNS

CHECKPOINT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verified Check Point Software Technologies IEEE OUI registrations
    "00:12:C1": ("firewall", "Network Security", "Check Point"),
    "00:1C:7F": ("firewall", "Network Security", "Check Point"),
    "00:A0:8E": ("firewall", "Network Security", "Check Point"),
}

CHECKPOINT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Quantum Security Gateways
    (r"Quantum\s*Maestro", "Check Point Quantum Maestro", "firewall", "Gaia"),
    (r"Quantum\s*Spark\s*1\d{3}", "Check Point Quantum Spark", "firewall", "Gaia"),
    (r"Quantum\s*6\d{3}", "Check Point Quantum 6000 Series", "firewall", "Gaia"),
    (r"Quantum\s*\d{5}", "Check Point Quantum Gateway", "firewall", "Gaia"),
    (r"Quantum\s*Gateway", "Check Point Quantum Gateway", "firewall", "Gaia"),
    (r"Quantum\s*Spark", "Check Point Quantum Spark", "firewall", "Gaia"),
    # Gaia OS versions
    (r"Gaia\s*R81\.20", "Check Point Gaia R81.20", "firewall", "Gaia R81.20"),
    (r"Gaia\s*R81\.10", "Check Point Gaia R81.10", "firewall", "Gaia R81.10"),
    (r"Gaia\s*R81", "Check Point Gaia R81", "firewall", "Gaia R81"),
    (r"Gaia\s*R80\.40", "Check Point Gaia R80.40", "firewall", "Gaia R80.40"),
    (r"Gaia\s*R80", "Check Point Gaia R80", "firewall", "Gaia R80"),
    (r"Gaia\s*R77", "Check Point Gaia R77", "firewall", "Gaia R77"),
    (r"Gaia\s*OS", "Check Point Gaia", "firewall", "Gaia"),
    # Management
    (r"SmartConsole", "Check Point SmartConsole", "management", "SmartConsole"),
    (r"Smart-1\s*Cloud", "Check Point Smart-1 Cloud", "management", "Smart-1"),
    (r"SmartCenter", "Check Point SmartCenter", "management", "SmartCenter"),
    # CloudGuard
    (r"CloudGuard\s*Network", "Check Point CloudGuard Network", "virtual_firewall", "CloudGuard"),
    (r"CloudGuard", "Check Point CloudGuard", "cloud_security", "CloudGuard"),
    # Generic
    (r"Check\s*Point", "Check Point", "firewall", "Gaia"),
    (r"CPMI", "Check Point Management", "management", "Gaia"),
]

# SONICWALL FIREWALL PATTERNS

SONICWALL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verified Sonicwall IEEE OUI registrations
    # NOTE: 00:40:10 was removed - IEEE assigns it to Sonic Systems Inc (different company)
    "00:06:B1": ("firewall", "Network Security", "SonicWall"),
    "00:17:C5": ("firewall", "Network Security", "SonicWall"),
    "18:B1:69": ("firewall", "Network Security", "SonicWall"),
    "18:C2:41": ("firewall", "Network Security", "SonicWall"),
    "2C:B8:ED": ("firewall", "Network Security", "SonicWall"),
    "C0:EA:E4": ("firewall", "Network Security", "SonicWall"),
    "FC:39:5A": ("firewall", "Network Security", "SonicWall"),
}

SONICWALL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # TZ Series
    (r"TZ\s*[2-6]70", "SonicWall TZ Series", "firewall", "SonicOS"),
    (r"TZ\s*[3-6]00", "SonicWall TZ Series", "firewall", "SonicOS"),
    (r"SOHO\s*250", "SonicWall SOHO 250", "firewall", "SonicOS"),
    # NSa Series
    (r"NSa\s*[2-6]700", "SonicWall NSa Series", "firewall", "SonicOS"),
    (r"NSa\s*[2-6]650", "SonicWall NSa Series", "firewall", "SonicOS"),
    (r"NSa\s*9\d{3}", "SonicWall NSa 9000 Series", "firewall", "SonicOS"),
    # NSsp Series
    (r"NSsp\s*1[0-5]700", "SonicWall NSsp Series", "firewall", "SonicOS"),
    (r"NSsp\s*12[48]00", "SonicWall NSsp Series", "firewall", "SonicOS"),
    # NSv Virtual
    (r"NSv\s*\d+", "SonicWall NSv Virtual", "virtual_firewall", "SonicOS"),
    # SonicOS versions
    (r"SonicOS\s*7\.", "SonicWall SonicOS 7.x", "firewall", "SonicOS 7"),
    (r"SonicOS\s*6\.", "SonicWall SonicOS 6.x", "firewall", "SonicOS 6"),
    (r"SonicOS", "SonicWall", "firewall", "SonicOS"),
    # SMA VPN
    (r"SMA\s*1000", "SonicWall SMA 1000", "vpn_gateway", "SMA"),
    (r"SMA\s*\d+", "SonicWall SMA", "vpn_gateway", "SMA"),
    # Generic
    (r"SonicWall", "SonicWall", "firewall", "SonicOS"),
]


# VMWARE VIRTUALIZATION PATTERNS (Comprehensive)

VMWARE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # --- 3-byte OUI fallbacks (MA-L) ---
    # 00:50:56 is used by both ESXi hosts and VMs; sub-ranges below override.
    # Default to virtual_machine since the vast majority of traffic from this
    # OUI comes from guest VMs, not the management vmknic.
    "00:50:56": ("virtual_machine", "Virtualization", "VMware VM"),
    "00:0C:29": ("virtual_machine", "Virtualization", "VMware VM"),
    "00:1C:14": ("hypervisor", "Virtualization", "VMware ESXi"),
    "00:05:69": ("hypervisor", "Virtualization", "VMware ESXi"),
    # --- 4-byte sub-ranges within 00:50:56 (matched before the 3-byte fallback) ---
    # 00-3F: statically assigned by Workstation / Fusion / Player
    "00:50:56:00": ("virtual_machine", "Virtualization", "VMware Workstation/Fusion VM"),
    "00:50:56:3F": ("virtual_machine", "Virtualization", "VMware Workstation/Fusion VM"),
    # 80-BF: dynamically assigned by vCenter / ESXi to guest VMs
    "00:50:56:80": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:81": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:82": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:83": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:84": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:85": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:86": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:87": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:88": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:89": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:8A": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:8B": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:8C": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:8D": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:8E": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:8F": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:90": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:91": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:92": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:93": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:94": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:95": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:96": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:97": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:98": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:99": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:9A": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:9B": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:9C": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:9D": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:9E": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:9F": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A0": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A1": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A2": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A3": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A4": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A5": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A6": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A7": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A8": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:A9": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:AA": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:AB": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:AC": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:AD": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:AE": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:AF": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B0": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B1": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B2": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B3": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B4": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B5": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B6": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B7": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B8": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:B9": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:BA": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:BB": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:BC": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:BD": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:BE": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    "00:50:56:BF": ("virtual_machine", "Virtualization", "VMware vSphere VM"),
    # C0-FF: Workstation VMnet host-only / NAT adapter MACs
    "00:50:56:C0": ("virtual_machine", "Virtualization", "VMware Workstation VM"),
    # NSX virtual infrastructure
    "02:50:56": ("virtual_router", "Virtualization", "VMware NSX"),
}

# QEMU / KVM / libvirt VIRTUAL MAC PREFIXES

QEMU_KVM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "52:54:00": ("virtual_machine", "Virtualization", "QEMU/KVM VM"),
}

# DOCKER / CONTAINER MAC PREFIXES

DOCKER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # 02:42 is used by Docker and Podman (default bridge mode)
    "02:42": ("container", "Container", "Docker/Podman Container"),
}

# LXC / LXD CONTAINER MAC PREFIXES

LXC_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # LXC/LXD default prefix (Proxmox also uses this range)
    "BC:24:11": ("container", "Container", "LXC Container"),
    # Note: 00:16:3E is in XCPNG_MAC_PREFIXES (Xen VM) — LXC on Proxmox
    # also uses this range but Xen is the IEEE-assigned owner
}

# PARALLELS MAC PREFIXES

PARALLELS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:1C:42": ("virtual_machine", "Virtualization", "Parallels VM"),
}

# BHYVE (FreeBSD) MAC PREFIXES

BHYVE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "58:9C:FC": ("virtual_machine", "Virtualization", "bhyve VM"),
}

# AWS FIRECRACKER MICROVM MAC PREFIXES

FIRECRACKER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Firecracker microVMs (AWS Lambda, Fargate, etc.)
    "AA:FC:00": ("virtual_machine", "Cloud", "Firecracker microVM"),
}

VMWARE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # VMware ESXi (all versions)
    # ESXi 8.x (vSphere 8)
    (r"ESXi\s*8\.0\s*U3", "VMware ESXi 8.0 Update 3", "hypervisor", "ESXi 8.0 U3"),
    (r"ESXi\s*8\.0\s*U2", "VMware ESXi 8.0 Update 2", "hypervisor", "ESXi 8.0 U2"),
    (r"ESXi\s*8\.0\s*U1", "VMware ESXi 8.0 Update 1", "hypervisor", "ESXi 8.0 U1"),
    (r"ESXi\s*8\.0", "VMware ESXi 8.0", "hypervisor", "ESXi 8.0"),
    (r"ESXi\s*8\.", "VMware ESXi 8.x", "hypervisor", "ESXi 8"),

    # ESXi 7.x (vSphere 7)
    (r"ESXi\s*7\.0\s*U3", "VMware ESXi 7.0 Update 3", "hypervisor", "ESXi 7.0 U3"),
    (r"ESXi\s*7\.0\s*U2", "VMware ESXi 7.0 Update 2", "hypervisor", "ESXi 7.0 U2"),
    (r"ESXi\s*7\.0\s*U1", "VMware ESXi 7.0 Update 1", "hypervisor", "ESXi 7.0 U1"),
    (r"ESXi\s*7\.0", "VMware ESXi 7.0", "hypervisor", "ESXi 7.0"),
    (r"ESXi\s*7\.", "VMware ESXi 7.x", "hypervisor", "ESXi 7"),

    # ESXi 6.x (vSphere 6)
    (r"ESXi\s*6\.7\s*U3", "VMware ESXi 6.7 Update 3", "hypervisor", "ESXi 6.7 U3"),
    (r"ESXi\s*6\.7\s*U2", "VMware ESXi 6.7 Update 2", "hypervisor", "ESXi 6.7 U2"),
    (r"ESXi\s*6\.7\s*U1", "VMware ESXi 6.7 Update 1", "hypervisor", "ESXi 6.7 U1"),
    (r"ESXi\s*6\.7", "VMware ESXi 6.7", "hypervisor", "ESXi 6.7"),
    (r"ESXi\s*6\.5\s*U3", "VMware ESXi 6.5 Update 3", "hypervisor", "ESXi 6.5 U3"),
    (r"ESXi\s*6\.5\s*U2", "VMware ESXi 6.5 Update 2", "hypervisor", "ESXi 6.5 U2"),
    (r"ESXi\s*6\.5\s*U1", "VMware ESXi 6.5 Update 1", "hypervisor", "ESXi 6.5 U1"),
    (r"ESXi\s*6\.5", "VMware ESXi 6.5", "hypervisor", "ESXi 6.5"),
    (r"ESXi\s*6\.0\s*U3", "VMware ESXi 6.0 Update 3", "hypervisor", "ESXi 6.0 U3"),
    (r"ESXi\s*6\.0\s*U2", "VMware ESXi 6.0 Update 2", "hypervisor", "ESXi 6.0 U2"),
    (r"ESXi\s*6\.0\s*U1", "VMware ESXi 6.0 Update 1", "hypervisor", "ESXi 6.0 U1"),
    (r"ESXi\s*6\.0", "VMware ESXi 6.0", "hypervisor", "ESXi 6.0"),

    # ESXi 5.x (legacy)
    (r"ESXi\s*5\.5\s*U3", "VMware ESXi 5.5 Update 3", "hypervisor", "ESXi 5.5 U3"),
    (r"ESXi\s*5\.5\s*U2", "VMware ESXi 5.5 Update 2", "hypervisor", "ESXi 5.5 U2"),
    (r"ESXi\s*5\.5\s*U1", "VMware ESXi 5.5 Update 1", "hypervisor", "ESXi 5.5 U1"),
    (r"ESXi\s*5\.5", "VMware ESXi 5.5", "hypervisor", "ESXi 5.5"),
    (r"ESXi\s*5\.1", "VMware ESXi 5.1", "hypervisor", "ESXi 5.1"),
    (r"ESXi\s*5\.0", "VMware ESXi 5.0", "hypervisor", "ESXi 5.0"),
    (r"ESXi\s*5\.", "VMware ESXi 5.x", "hypervisor", "ESXi 5"),

    # ESXi 4.x (very legacy)
    (r"ESXi\s*4\.1", "VMware ESXi 4.1", "hypervisor", "ESXi 4.1"),
    (r"ESXi\s*4\.0", "VMware ESXi 4.0", "hypervisor", "ESXi 4.0"),

    # Generic ESXi detection
    (r"VMware\s*ESXi", "VMware ESXi", "hypervisor", "ESXi"),
    (r"VMkernel", "VMware ESXi", "hypervisor", "ESXi"),
    (r"esxupdate", "VMware ESXi", "hypervisor", "ESXi"),

    # vCenter Server (all versions)
    # vCenter 8.x
    (r"vCenter\s*Server\s*8\.0\s*U3", "VMware vCenter Server 8.0 U3", "management", "vCenter 8.0 U3"),
    (r"vCenter\s*Server\s*8\.0\s*U2", "VMware vCenter Server 8.0 U2", "management", "vCenter 8.0 U2"),
    (r"vCenter\s*Server\s*8\.0\s*U1", "VMware vCenter Server 8.0 U1", "management", "vCenter 8.0 U1"),
    (r"vCenter\s*Server\s*8\.0", "VMware vCenter Server 8.0", "management", "vCenter 8.0"),
    (r"vCenter\s*8\.", "VMware vCenter Server 8.x", "management", "vCenter 8"),

    # vCenter 7.x
    (r"vCenter\s*Server\s*7\.0\s*U3", "VMware vCenter Server 7.0 U3", "management", "vCenter 7.0 U3"),
    (r"vCenter\s*Server\s*7\.0\s*U2", "VMware vCenter Server 7.0 U2", "management", "vCenter 7.0 U2"),
    (r"vCenter\s*Server\s*7\.0\s*U1", "VMware vCenter Server 7.0 U1", "management", "vCenter 7.0 U1"),
    (r"vCenter\s*Server\s*7\.0", "VMware vCenter Server 7.0", "management", "vCenter 7.0"),
    (r"vCenter\s*7\.", "VMware vCenter Server 7.x", "management", "vCenter 7"),

    # vCenter 6.x
    (r"vCenter\s*Server\s*6\.7", "VMware vCenter Server 6.7", "management", "vCenter 6.7"),
    (r"vCenter\s*Server\s*6\.5", "VMware vCenter Server 6.5", "management", "vCenter 6.5"),
    (r"vCenter\s*Server\s*6\.0", "VMware vCenter Server 6.0", "management", "vCenter 6.0"),
    (r"vCenter\s*6\.", "VMware vCenter Server 6.x", "management", "vCenter 6"),

    # vCenter 5.x (legacy)
    (r"vCenter\s*Server\s*5\.5", "VMware vCenter Server 5.5", "management", "vCenter 5.5"),
    (r"vCenter\s*Server\s*5\.1", "VMware vCenter Server 5.1", "management", "vCenter 5.1"),
    (r"vCenter\s*5\.", "VMware vCenter Server 5.x", "management", "vCenter 5"),

    # VCSA (vCenter Server Appliance)
    (r"VCSA\s*8\.", "VMware vCenter Server Appliance 8.x", "management", "VCSA 8"),
    (r"VCSA\s*7\.", "VMware vCenter Server Appliance 7.x", "management", "VCSA 7"),
    (r"VCSA\s*6\.", "VMware vCenter Server Appliance 6.x", "management", "VCSA 6"),
    (r"VCSA", "VMware vCenter Server Appliance", "management", "VCSA"),
    (r"vCenter\s*Server\s*Appliance", "VMware vCenter Server Appliance", "management", "VCSA"),

    # Generic vCenter
    (r"vCenter\s*Server", "VMware vCenter Server", "management", "vCenter"),
    (r"VMware\s*vCenter", "VMware vCenter Server", "management", "vCenter"),
    (r"vpxd", "VMware vCenter Server", "management", "vCenter"),

    # vSphere Client/Web Console
    (r"vSphere\s*Client\s*8", "VMware vSphere Client 8.x", "management", "vSphere Client 8"),
    (r"vSphere\s*Client\s*7", "VMware vSphere Client 7.x", "management", "vSphere Client 7"),
    (r"vSphere\s*Client\s*6", "VMware vSphere Client 6.x", "management", "vSphere Client 6"),
    (r"vSphere\s*Client", "VMware vSphere Client", "management", "vSphere Client"),
    (r"vSphere\s*Web\s*Client", "VMware vSphere Web Client", "management", "vSphere Web Client"),
    (r"vSphere\s*HTML5", "VMware vSphere HTML5 Client", "management", "vSphere HTML5 Client"),
    (r"vSphere\s*8", "VMware vSphere 8", "management", "vSphere 8"),
    (r"vSphere\s*7", "VMware vSphere 7", "management", "vSphere 7"),
    (r"vSphere\s*6", "VMware vSphere 6", "management", "vSphere 6"),
    (r"vSphere\s*\d", "VMware vSphere", "management", "vSphere"),

    # NSX (Network Virtualization)
    # NSX 4.x (NSX-T replacement)
    (r"NSX\s*4\.\d", "VMware NSX 4.x", "sdn_controller", "NSX 4"),
    (r"NSX\s*4\.1", "VMware NSX 4.1", "sdn_controller", "NSX 4.1"),
    (r"NSX\s*4\.0", "VMware NSX 4.0", "sdn_controller", "NSX 4.0"),

    # NSX-T Data Center
    (r"NSX-T\s*Data\s*Center\s*3\.2", "VMware NSX-T Data Center 3.2", "sdn_controller", "NSX-T 3.2"),
    (r"NSX-T\s*Data\s*Center\s*3\.1", "VMware NSX-T Data Center 3.1", "sdn_controller", "NSX-T 3.1"),
    (r"NSX-T\s*Data\s*Center\s*3\.0", "VMware NSX-T Data Center 3.0", "sdn_controller", "NSX-T 3.0"),
    (r"NSX-T\s*Data\s*Center\s*2\.5", "VMware NSX-T Data Center 2.5", "sdn_controller", "NSX-T 2.5"),
    (r"NSX-T\s*Data\s*Center", "VMware NSX-T Data Center", "sdn_controller", "NSX-T"),
    (r"NSX-T\s*3\.", "VMware NSX-T 3.x", "sdn_controller", "NSX-T 3"),
    (r"NSX-T\s*2\.", "VMware NSX-T 2.x", "sdn_controller", "NSX-T 2"),
    (r"NSX-T", "VMware NSX-T", "sdn_controller", "NSX-T"),

    # NSX-V (legacy)
    (r"NSX-V\s*6\.4", "VMware NSX-V 6.4", "sdn_controller", "NSX-V 6.4"),
    (r"NSX-V\s*6\.3", "VMware NSX-V 6.3", "sdn_controller", "NSX-V 6.3"),
    (r"NSX-V", "VMware NSX-V", "sdn_controller", "NSX-V"),
    (r"NSX\s*for\s*vSphere", "VMware NSX for vSphere", "sdn_controller", "NSX-V"),

    # NSX Components
    (r"NSX\s*Manager", "VMware NSX Manager", "sdn_controller", "NSX Manager"),
    (r"NSX\s*Controller", "VMware NSX Controller", "sdn_controller", "NSX Controller"),
    (r"NSX\s*Edge", "VMware NSX Edge", "virtual_router", "NSX Edge"),
    (r"NSX\s*Gateway", "VMware NSX Gateway", "virtual_router", "NSX Gateway"),
    (r"NSX\s*Advanced\s*Load\s*Balancer", "VMware NSX ALB", "load_balancer", "NSX ALB"),
    (r"NSX\s*ALB", "VMware NSX ALB", "load_balancer", "NSX ALB"),
    (r"Avi\s*Networks", "VMware NSX ALB (Avi)", "load_balancer", "NSX ALB"),
    (r"Avi\s*Vantage", "VMware NSX ALB (Avi Vantage)", "load_balancer", "NSX ALB"),

    # vSAN (Storage)
    (r"vSAN\s*8", "VMware vSAN 8", "storage", "vSAN 8"),
    (r"vSAN\s*7", "VMware vSAN 7", "storage", "vSAN 7"),
    (r"vSAN\s*6\.7", "VMware vSAN 6.7", "storage", "vSAN 6.7"),
    (r"vSAN\s*6\.6", "VMware vSAN 6.6", "storage", "vSAN 6.6"),
    (r"vSAN\s*ESA", "VMware vSAN ESA", "storage", "vSAN ESA"),
    (r"vSAN\s*HCI\s*Mesh", "VMware vSAN HCI Mesh", "storage", "vSAN HCI Mesh"),
    (r"vSAN", "VMware vSAN", "storage", "vSAN"),

    # Horizon (VDI)
    # Horizon versions
    (r"Horizon\s*8\s*2\d{3}", "VMware Horizon 8", "vdi", "Horizon 8"),
    (r"Horizon\s*8", "VMware Horizon 8", "vdi", "Horizon 8"),
    (r"Horizon\s*7\.13", "VMware Horizon 7.13", "vdi", "Horizon 7.13"),
    (r"Horizon\s*7\.12", "VMware Horizon 7.12", "vdi", "Horizon 7.12"),
    (r"Horizon\s*7\.11", "VMware Horizon 7.11", "vdi", "Horizon 7.11"),
    (r"Horizon\s*7\.10", "VMware Horizon 7.10", "vdi", "Horizon 7.10"),
    (r"Horizon\s*7\.", "VMware Horizon 7.x", "vdi", "Horizon 7"),
    (r"Horizon\s*6\.", "VMware Horizon 6.x", "vdi", "Horizon 6"),

    # Horizon Components
    (r"Horizon\s*Connection\s*Server", "VMware Horizon Connection Server", "vdi", "Horizon Connection Server"),
    (r"Horizon\s*Composer", "VMware Horizon Composer", "vdi", "Horizon Composer"),
    (r"Horizon\s*Agent", "VMware Horizon Agent", "vdi_client", "Horizon Agent"),
    (r"Horizon\s*Client", "VMware Horizon Client", "vdi_client", "Horizon Client"),
    (r"Horizon\s*Unified\s*Access\s*Gateway", "VMware UAG", "gateway", "UAG"),
    (r"Unified\s*Access\s*Gateway", "VMware UAG", "gateway", "UAG"),
    (r"UAG\s*\d", "VMware UAG", "gateway", "UAG"),
    (r"VMware\s*View\s*Connection", "VMware Horizon View", "vdi", "Horizon View"),
    (r"VMware\s*View\s*Composer", "VMware Horizon Composer", "vdi", "Horizon Composer"),
    (r"VMware\s*View", "VMware Horizon View", "vdi", "Horizon View"),
    (r"Horizon\s*Workspace", "VMware Workspace ONE", "vdi", "Workspace ONE"),
    (r"Horizon\s*DaaS", "VMware Horizon DaaS", "vdi", "Horizon DaaS"),
    (r"Horizon\s*Cloud", "VMware Horizon Cloud", "vdi", "Horizon Cloud"),

    # Workspace ONE / AirWatch
    (r"Workspace\s*ONE\s*UEM", "VMware Workspace ONE UEM", "mdm", "Workspace ONE UEM"),
    (r"Workspace\s*ONE\s*Access", "VMware Workspace ONE Access", "identity", "Workspace ONE Access"),
    (r"Workspace\s*ONE\s*Intelligence", "VMware Workspace ONE Intelligence", "analytics", "Workspace ONE Intelligence"),
    (r"Workspace\s*ONE", "VMware Workspace ONE", "mdm", "Workspace ONE"),
    (r"AirWatch", "VMware AirWatch", "mdm", "AirWatch"),

    # vRealize Suite / Aria Suite
    # Aria (new branding)
    (r"Aria\s*Operations", "VMware Aria Operations", "management", "Aria Operations"),
    (r"Aria\s*Automation", "VMware Aria Automation", "automation", "Aria Automation"),
    (r"Aria\s*Operations\s*for\s*Logs", "VMware Aria Ops for Logs", "logging", "Aria Logs"),
    (r"Aria\s*Operations\s*for\s*Networks", "VMware Aria Ops for Networks", "monitoring", "Aria Networks"),
    (r"Aria\s*Suite", "VMware Aria Suite", "management", "Aria Suite"),

    # vRealize (legacy branding)
    (r"vRealize\s*Operations\s*8", "VMware vRealize Operations 8.x", "management", "vROps 8"),
    (r"vRealize\s*Operations\s*7", "VMware vRealize Operations 7.x", "management", "vROps 7"),
    (r"vRealize\s*Operations", "VMware vRealize Operations", "management", "vROps"),
    (r"vROps\s*8", "VMware vRealize Operations 8.x", "management", "vROps 8"),
    (r"vROps", "VMware vRealize Operations", "management", "vROps"),
    (r"vRealize\s*Automation\s*8", "VMware vRealize Automation 8.x", "automation", "vRA 8"),
    (r"vRealize\s*Automation\s*7", "VMware vRealize Automation 7.x", "automation", "vRA 7"),
    (r"vRealize\s*Automation", "VMware vRealize Automation", "automation", "vRA"),
    (r"vRA\s*8", "VMware vRealize Automation 8.x", "automation", "vRA 8"),
    (r"vRA", "VMware vRealize Automation", "automation", "vRA"),
    (r"vRealize\s*Log\s*Insight", "VMware vRealize Log Insight", "logging", "vRLI"),
    (r"vRLI", "VMware vRealize Log Insight", "logging", "vRLI"),
    (r"vRealize\s*Network\s*Insight", "VMware vRealize Network Insight", "monitoring", "vRNI"),
    (r"vRNI", "VMware vRealize Network Insight", "monitoring", "vRNI"),
    (r"vRealize\s*Orchestrator", "VMware vRealize Orchestrator", "automation", "vRO"),
    (r"vRO\s*\d", "VMware vRealize Orchestrator", "automation", "vRO"),
    (r"vRealize\s*Business", "VMware vRealize Business", "management", "vRB"),
    (r"vRealize\s*Suite", "VMware vRealize Suite", "management", "vRealize Suite"),
    (r"vRealize", "VMware vRealize", "management", "vRealize"),

    # Cloud Foundation (VCF)
    (r"VMware\s*Cloud\s*Foundation\s*5", "VMware Cloud Foundation 5", "hci", "VCF 5"),
    (r"VMware\s*Cloud\s*Foundation\s*4", "VMware Cloud Foundation 4", "hci", "VCF 4"),
    (r"VMware\s*Cloud\s*Foundation", "VMware Cloud Foundation", "hci", "VCF"),
    (r"VCF\s*5", "VMware Cloud Foundation 5", "hci", "VCF 5"),
    (r"VCF\s*4", "VMware Cloud Foundation 4", "hci", "VCF 4"),
    (r"VCF\s*SDDC", "VMware VCF SDDC", "hci", "VCF"),
    (r"SDDC\s*Manager", "VMware SDDC Manager", "management", "SDDC Manager"),

    # Tanzu (Kubernetes)
    (r"Tanzu\s*Kubernetes\s*Grid", "VMware Tanzu Kubernetes Grid", "kubernetes", "TKG"),
    (r"Tanzu\s*Mission\s*Control", "VMware Tanzu Mission Control", "kubernetes", "TMC"),
    (r"Tanzu\s*Application\s*Platform", "VMware Tanzu Application Platform", "kubernetes", "TAP"),
    (r"Tanzu\s*Application\s*Service", "VMware Tanzu Application Service", "paas", "TAS"),
    (r"TKG\s*\d", "VMware Tanzu Kubernetes Grid", "kubernetes", "TKG"),
    (r"Tanzu", "VMware Tanzu", "kubernetes", "Tanzu"),
    (r"vSphere\s*with\s*Tanzu", "VMware vSphere with Tanzu", "kubernetes", "vSphere Tanzu"),

    # VMware Desktop Products
    (r"VMware\s*Workstation\s*Pro\s*17", "VMware Workstation Pro 17", "hypervisor", "Workstation 17"),
    (r"VMware\s*Workstation\s*Pro\s*16", "VMware Workstation Pro 16", "hypervisor", "Workstation 16"),
    (r"VMware\s*Workstation\s*Pro\s*15", "VMware Workstation Pro 15", "hypervisor", "Workstation 15"),
    (r"VMware\s*Workstation\s*Pro", "VMware Workstation Pro", "hypervisor", "Workstation Pro"),
    (r"VMware\s*Workstation\s*Player\s*17", "VMware Workstation Player 17", "hypervisor", "Workstation Player 17"),
    (r"VMware\s*Workstation\s*Player\s*16", "VMware Workstation Player 16", "hypervisor", "Workstation Player 16"),
    (r"VMware\s*Workstation\s*Player", "VMware Workstation Player", "hypervisor", "Workstation Player"),
    (r"VMware\s*Workstation\s*17", "VMware Workstation 17", "hypervisor", "Workstation 17"),
    (r"VMware\s*Workstation\s*16", "VMware Workstation 16", "hypervisor", "Workstation 16"),
    (r"VMware\s*Workstation\s*15", "VMware Workstation 15", "hypervisor", "Workstation 15"),
    (r"VMware\s*Workstation", "VMware Workstation", "hypervisor", "Workstation"),
    (r"VMware\s*Fusion\s*Pro\s*13", "VMware Fusion Pro 13", "hypervisor", "Fusion 13"),
    (r"VMware\s*Fusion\s*Pro\s*12", "VMware Fusion Pro 12", "hypervisor", "Fusion 12"),
    (r"VMware\s*Fusion\s*Pro", "VMware Fusion Pro", "hypervisor", "Fusion Pro"),
    (r"VMware\s*Fusion\s*13", "VMware Fusion 13", "hypervisor", "Fusion 13"),
    (r"VMware\s*Fusion\s*12", "VMware Fusion 12", "hypervisor", "Fusion 12"),
    (r"VMware\s*Fusion", "VMware Fusion", "hypervisor", "Fusion"),

    # Other VMware Products
    (r"VMware\s*Site\s*Recovery\s*Manager", "VMware Site Recovery Manager", "dr", "SRM"),
    (r"SRM\s*\d", "VMware Site Recovery Manager", "dr", "SRM"),
    (r"VMware\s*HCX", "VMware HCX", "migration", "HCX"),
    (r"HCX\s*Cloud", "VMware HCX Cloud", "migration", "HCX Cloud"),
    (r"VMware\s*vSphere\s*Replication", "VMware vSphere Replication", "dr", "vSphere Replication"),
    (r"VMware\s*Data\s*Protection", "VMware Data Protection", "backup", "VDP"),
    (r"VDP\s*Advanced", "VMware Data Protection Advanced", "backup", "VDP Advanced"),
    (r"VMware\s*Tools", "VMware Tools", "guest_agent", "VMware Tools"),
    (r"open-vm-tools", "VMware open-vm-tools", "guest_agent", "open-vm-tools"),
    (r"VMware\s*vShield", "VMware vShield", "security", "vShield"),
    (r"VMware\s*AppDefense", "VMware AppDefense", "security", "AppDefense"),
    (r"VMware\s*Carbon\s*Black", "VMware Carbon Black", "security", "Carbon Black"),

    # Generic VMware detection
    (r"vmware-hostd", "VMware ESXi", "hypervisor", "ESXi"),
    (r"vmware-vpxd", "VMware vCenter", "management", "vCenter"),
    (r"VMware", "VMware Product", "hypervisor", "VMware"),
]

# PROXMOX VIRTUALIZATION PATTERNS (Comprehensive)

PROXMOX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Proxmox VE versions
    (r"Proxmox\s*VE\s*8\.3", "Proxmox VE 8.3", "hypervisor", "Proxmox VE 8.3"),
    (r"Proxmox\s*VE\s*8\.2", "Proxmox VE 8.2", "hypervisor", "Proxmox VE 8.2"),
    (r"Proxmox\s*VE\s*8\.1", "Proxmox VE 8.1", "hypervisor", "Proxmox VE 8.1"),
    (r"Proxmox\s*VE\s*8\.0", "Proxmox VE 8.0", "hypervisor", "Proxmox VE 8.0"),
    (r"Proxmox\s*VE\s*8", "Proxmox VE 8.x", "hypervisor", "Proxmox VE 8"),
    (r"Proxmox\s*VE\s*7\.4", "Proxmox VE 7.4", "hypervisor", "Proxmox VE 7.4"),
    (r"Proxmox\s*VE\s*7\.3", "Proxmox VE 7.3", "hypervisor", "Proxmox VE 7.3"),
    (r"Proxmox\s*VE\s*7\.2", "Proxmox VE 7.2", "hypervisor", "Proxmox VE 7.2"),
    (r"Proxmox\s*VE\s*7\.1", "Proxmox VE 7.1", "hypervisor", "Proxmox VE 7.1"),
    (r"Proxmox\s*VE\s*7\.0", "Proxmox VE 7.0", "hypervisor", "Proxmox VE 7.0"),
    (r"Proxmox\s*VE\s*7", "Proxmox VE 7.x", "hypervisor", "Proxmox VE 7"),
    (r"Proxmox\s*VE\s*6\.4", "Proxmox VE 6.4", "hypervisor", "Proxmox VE 6.4"),
    (r"Proxmox\s*VE\s*6\.3", "Proxmox VE 6.3", "hypervisor", "Proxmox VE 6.3"),
    (r"Proxmox\s*VE\s*6\.2", "Proxmox VE 6.2", "hypervisor", "Proxmox VE 6.2"),
    (r"Proxmox\s*VE\s*6\.1", "Proxmox VE 6.1", "hypervisor", "Proxmox VE 6.1"),
    (r"Proxmox\s*VE\s*6\.0", "Proxmox VE 6.0", "hypervisor", "Proxmox VE 6.0"),
    (r"Proxmox\s*VE\s*6", "Proxmox VE 6.x", "hypervisor", "Proxmox VE 6"),
    (r"Proxmox\s*VE\s*5", "Proxmox VE 5.x", "hypervisor", "Proxmox VE 5"),
    (r"Proxmox\s*Virtual\s*Environment", "Proxmox VE", "hypervisor", "Proxmox VE"),
    (r"pve-manager/(\d+\.\d+)", "Proxmox VE", "hypervisor", "Proxmox VE"),
    (r"pve-manager", "Proxmox VE", "hypervisor", "Proxmox VE"),
    (r"PVE\s*\d", "Proxmox VE", "hypervisor", "Proxmox VE"),

    # Proxmox Backup Server versions
    (r"Proxmox\s*Backup\s*Server\s*3", "Proxmox Backup Server 3.x", "backup", "PBS 3"),
    (r"Proxmox\s*Backup\s*Server\s*2\.4", "Proxmox Backup Server 2.4", "backup", "PBS 2.4"),
    (r"Proxmox\s*Backup\s*Server\s*2\.3", "Proxmox Backup Server 2.3", "backup", "PBS 2.3"),
    (r"Proxmox\s*Backup\s*Server\s*2\.2", "Proxmox Backup Server 2.2", "backup", "PBS 2.2"),
    (r"Proxmox\s*Backup\s*Server\s*2", "Proxmox Backup Server 2.x", "backup", "PBS 2"),
    (r"Proxmox\s*Backup\s*Server", "Proxmox Backup Server", "backup", "PBS"),
    (r"proxmox-backup-server", "Proxmox Backup Server", "backup", "PBS"),
    (r"proxmox-backup", "Proxmox Backup Server", "backup", "PBS"),
    (r"PBS\s*\d", "Proxmox Backup Server", "backup", "PBS"),

    # Proxmox Mail Gateway versions
    (r"Proxmox\s*Mail\s*Gateway\s*8", "Proxmox Mail Gateway 8.x", "mail_gateway", "PMG 8"),
    (r"Proxmox\s*Mail\s*Gateway\s*7", "Proxmox Mail Gateway 7.x", "mail_gateway", "PMG 7"),
    (r"Proxmox\s*Mail\s*Gateway\s*6", "Proxmox Mail Gateway 6.x", "mail_gateway", "PMG 6"),
    (r"Proxmox\s*Mail\s*Gateway", "Proxmox Mail Gateway", "mail_gateway", "PMG"),
    (r"pmg-api", "Proxmox Mail Gateway", "mail_gateway", "PMG"),
    (r"PMG\s*\d", "Proxmox Mail Gateway", "mail_gateway", "PMG"),

    # Proxmox components
    (r"pve-qemu", "Proxmox QEMU/KVM", "hypervisor", "Proxmox QEMU"),
    (r"pve-lxc", "Proxmox LXC", "container", "Proxmox LXC"),
    (r"pve-cluster", "Proxmox Cluster", "cluster", "Proxmox Cluster"),
    (r"pve-ha-manager", "Proxmox HA Manager", "ha", "Proxmox HA"),
    (r"pve-firewall", "Proxmox Firewall", "firewall", "Proxmox Firewall"),
    (r"ceph\s*.*proxmox", "Proxmox Ceph", "storage", "Proxmox Ceph"),
    (r"Proxmox", "Proxmox", "hypervisor", "Proxmox"),
]

# XCP-NG / XENSERVER PATTERNS (Comprehensive)

XCPNG_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # XenServer/XCP-ng generated MACs
    "00:16:3E": ("virtual_machine", "Virtualization", "Xen VM"),
    # XCP-ng appliances
    "2E:3E:3E": ("hypervisor", "Virtualization", "XCP-ng"),
}

XCPNG_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # XCP-ng versions
    (r"XCP-ng\s*8\.3", "XCP-ng 8.3", "hypervisor", "XCP-ng 8.3"),
    (r"XCP-ng\s*8\.2\.1", "XCP-ng 8.2.1 LTS", "hypervisor", "XCP-ng 8.2.1 LTS"),
    (r"XCP-ng\s*8\.2", "XCP-ng 8.2", "hypervisor", "XCP-ng 8.2"),
    (r"XCP-ng\s*8\.1", "XCP-ng 8.1", "hypervisor", "XCP-ng 8.1"),
    (r"XCP-ng\s*8\.0", "XCP-ng 8.0", "hypervisor", "XCP-ng 8.0"),
    (r"XCP-ng\s*8", "XCP-ng 8.x", "hypervisor", "XCP-ng 8"),
    (r"XCP-ng\s*7\.6", "XCP-ng 7.6", "hypervisor", "XCP-ng 7.6"),
    (r"XCP-ng\s*7\.5", "XCP-ng 7.5", "hypervisor", "XCP-ng 7.5"),
    (r"XCP-ng\s*7\.4", "XCP-ng 7.4", "hypervisor", "XCP-ng 7.4"),
    (r"XCP-ng\s*7", "XCP-ng 7.x", "hypervisor", "XCP-ng 7"),
    (r"XCP-ng", "XCP-ng", "hypervisor", "XCP-ng"),

    # Xen Orchestra (management)
    (r"Xen\s*Orchestra\s*5\.9\d", "Xen Orchestra 5.9x", "management", "XO 5.9x"),
    (r"Xen\s*Orchestra\s*5\.8\d", "Xen Orchestra 5.8x", "management", "XO 5.8x"),
    (r"Xen\s*Orchestra\s*5\.", "Xen Orchestra 5.x", "management", "XO 5"),
    (r"Xen\s*Orchestra", "Xen Orchestra", "management", "Xen Orchestra"),
    (r"XOA\s*\d", "Xen Orchestra Appliance", "management", "XOA"),
    (r"XOA", "Xen Orchestra Appliance", "management", "XOA"),
    (r"xo-server", "Xen Orchestra Server", "management", "XO Server"),
    (r"xo-web", "Xen Orchestra Web", "management", "XO Web"),

    # XAPI (XenServer/XCP-ng API)
    (r"xapi/(\d+\.\d+)", "XAPI", "hypervisor", "XAPI"),
    (r"xapi", "XAPI", "hypervisor", "XAPI"),
    (r"XenAPI", "XenAPI", "hypervisor", "XenAPI"),

    # Xen Hypervisor
    (r"Xen\s*4\.17", "Xen Hypervisor 4.17", "hypervisor", "Xen 4.17"),
    (r"Xen\s*4\.16", "Xen Hypervisor 4.16", "hypervisor", "Xen 4.16"),
    (r"Xen\s*4\.15", "Xen Hypervisor 4.15", "hypervisor", "Xen 4.15"),
    (r"Xen\s*4\.14", "Xen Hypervisor 4.14", "hypervisor", "Xen 4.14"),
    (r"Xen\s*4\.13", "Xen Hypervisor 4.13", "hypervisor", "Xen 4.13"),
    (r"Xen\s*4\.\d+", "Xen Hypervisor 4.x", "hypervisor", "Xen 4"),
    (r"Xen\s*Project", "Xen Project Hypervisor", "hypervisor", "Xen Project"),

    # XCP-ng Center (Windows management)
    (r"XCP-ng\s*Center", "XCP-ng Center", "management", "XCP-ng Center"),
]

# CITRIX PATTERNS (Comprehensive)

CITRIX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Citrix XenServer MACs (same as Xen)
    # REMOVED: 00:16:3E - IEEE assigns to Unknown, not CITRIX
    # Citrix NetScaler/ADC
    # REMOVED: 5C:E2:8C - IEEE assigns to Unknown, not CITRIX
    # Citrix SD-WAN
}

CITRIX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Citrix Hypervisor / XenServer
    # Citrix Hypervisor (new branding)
    (r"Citrix\s*Hypervisor\s*8\.2", "Citrix Hypervisor 8.2", "hypervisor", "Citrix Hypervisor 8.2"),
    (r"Citrix\s*Hypervisor\s*8\.1", "Citrix Hypervisor 8.1", "hypervisor", "Citrix Hypervisor 8.1"),
    (r"Citrix\s*Hypervisor\s*8\.0", "Citrix Hypervisor 8.0", "hypervisor", "Citrix Hypervisor 8.0"),
    (r"Citrix\s*Hypervisor\s*8", "Citrix Hypervisor 8.x", "hypervisor", "Citrix Hypervisor 8"),
    (r"Citrix\s*Hypervisor", "Citrix Hypervisor", "hypervisor", "Citrix Hypervisor"),

    # XenServer (legacy branding)
    (r"XenServer\s*8\.2", "Citrix XenServer 8.2", "hypervisor", "XenServer 8.2"),
    (r"XenServer\s*8\.1", "Citrix XenServer 8.1", "hypervisor", "XenServer 8.1"),
    (r"XenServer\s*8\.0", "Citrix XenServer 8.0", "hypervisor", "XenServer 8.0"),
    (r"XenServer\s*7\.6", "Citrix XenServer 7.6", "hypervisor", "XenServer 7.6"),
    (r"XenServer\s*7\.5", "Citrix XenServer 7.5", "hypervisor", "XenServer 7.5"),
    (r"XenServer\s*7\.4", "Citrix XenServer 7.4", "hypervisor", "XenServer 7.4"),
    (r"XenServer\s*7\.3", "Citrix XenServer 7.3", "hypervisor", "XenServer 7.3"),
    (r"XenServer\s*7\.2", "Citrix XenServer 7.2", "hypervisor", "XenServer 7.2"),
    (r"XenServer\s*7\.1", "Citrix XenServer 7.1 LTSR", "hypervisor", "XenServer 7.1 LTSR"),
    (r"XenServer\s*7\.0", "Citrix XenServer 7.0", "hypervisor", "XenServer 7.0"),
    (r"XenServer\s*7", "Citrix XenServer 7.x", "hypervisor", "XenServer 7"),
    (r"XenServer\s*6\.5", "Citrix XenServer 6.5", "hypervisor", "XenServer 6.5"),
    (r"XenServer\s*6\.2", "Citrix XenServer 6.2", "hypervisor", "XenServer 6.2"),
    (r"XenServer\s*6\.1", "Citrix XenServer 6.1", "hypervisor", "XenServer 6.1"),
    (r"XenServer\s*6\.0", "Citrix XenServer 6.0", "hypervisor", "XenServer 6.0"),
    (r"XenServer\s*6", "Citrix XenServer 6.x", "hypervisor", "XenServer 6"),
    (r"XenServer\s*5\.6", "Citrix XenServer 5.6", "hypervisor", "XenServer 5.6"),
    (r"XenServer", "Citrix XenServer", "hypervisor", "XenServer"),
    (r"Citrix\s*XenServer", "Citrix XenServer", "hypervisor", "XenServer"),

    # XenCenter (management)
    (r"XenCenter\s*8", "Citrix XenCenter 8.x", "management", "XenCenter 8"),
    (r"XenCenter\s*7", "Citrix XenCenter 7.x", "management", "XenCenter 7"),
    (r"XenCenter", "Citrix XenCenter", "management", "XenCenter"),

    # Citrix Virtual Apps and Desktops (CVAD)
    # Current Release (CR)
    (r"Citrix\s*Virtual\s*Apps\s*and\s*Desktops\s*2\d{3}", "Citrix Virtual Apps and Desktops", "vdi", "CVAD"),
    (r"Citrix\s*Virtual\s*Apps\s*and\s*Desktops\s*7\s*2\d{3}", "Citrix Virtual Apps and Desktops 7", "vdi", "CVAD 7"),
    (r"Citrix\s*Virtual\s*Apps\s*and\s*Desktops", "Citrix Virtual Apps and Desktops", "vdi", "CVAD"),
    (r"CVAD\s*2\d{3}", "Citrix Virtual Apps and Desktops", "vdi", "CVAD"),
    (r"CVAD\s*7", "Citrix Virtual Apps and Desktops 7", "vdi", "CVAD 7"),
    (r"CVAD", "Citrix Virtual Apps and Desktops", "vdi", "CVAD"),

    # LTSR versions
    (r"XenApp\s*and\s*XenDesktop\s*7\.15\s*LTSR", "Citrix XenApp/XenDesktop 7.15 LTSR", "vdi", "XD 7.15 LTSR"),
    (r"CVAD\s*1912\s*LTSR", "Citrix CVAD 1912 LTSR", "vdi", "CVAD 1912 LTSR"),
    (r"CVAD\s*2203\s*LTSR", "Citrix CVAD 2203 LTSR", "vdi", "CVAD 2203 LTSR"),

    # Legacy XenApp/XenDesktop
    (r"XenDesktop\s*7\.15", "Citrix XenDesktop 7.15", "vdi", "XenDesktop 7.15"),
    (r"XenDesktop\s*7\.14", "Citrix XenDesktop 7.14", "vdi", "XenDesktop 7.14"),
    (r"XenDesktop\s*7\.13", "Citrix XenDesktop 7.13", "vdi", "XenDesktop 7.13"),
    (r"XenDesktop\s*7\.12", "Citrix XenDesktop 7.12", "vdi", "XenDesktop 7.12"),
    (r"XenDesktop\s*7\.11", "Citrix XenDesktop 7.11", "vdi", "XenDesktop 7.11"),
    (r"XenDesktop\s*7\.10", "Citrix XenDesktop 7.10", "vdi", "XenDesktop 7.10"),
    (r"XenDesktop\s*7\.\d", "Citrix XenDesktop 7.x", "vdi", "XenDesktop 7"),
    (r"XenDesktop\s*7", "Citrix XenDesktop 7", "vdi", "XenDesktop 7"),
    (r"XenDesktop\s*5\.6", "Citrix XenDesktop 5.6", "vdi", "XenDesktop 5.6"),
    (r"XenDesktop\s*5\.5", "Citrix XenDesktop 5.5", "vdi", "XenDesktop 5.5"),
    (r"XenDesktop", "Citrix XenDesktop", "vdi", "XenDesktop"),
    (r"XenApp\s*7\.15", "Citrix XenApp 7.15", "vdi", "XenApp 7.15"),
    (r"XenApp\s*7\.\d", "Citrix XenApp 7.x", "vdi", "XenApp 7"),
    (r"XenApp\s*6\.5", "Citrix XenApp 6.5", "vdi", "XenApp 6.5"),
    (r"XenApp", "Citrix XenApp", "vdi", "XenApp"),

    # CVAD Components
    (r"Delivery\s*Controller", "Citrix Delivery Controller", "vdi", "DDC"),
    (r"DDC\s*\d", "Citrix Delivery Controller", "vdi", "DDC"),
    (r"Citrix\s*Director", "Citrix Director", "management", "Director"),
    (r"Citrix\s*Studio", "Citrix Studio", "management", "Studio"),
    (r"StoreFront\s*\d+\.\d+", "Citrix StoreFront", "gateway", "StoreFront"),
    (r"StoreFront", "Citrix StoreFront", "gateway", "StoreFront"),
    (r"Citrix\s*Provisioning\s*Services", "Citrix Provisioning Services", "provisioning", "PVS"),
    (r"Citrix\s*PVS\s*\d+", "Citrix Provisioning Services", "provisioning", "PVS"),
    (r"PVS\s*\d+\.\d+", "Citrix Provisioning Services", "provisioning", "PVS"),
    (r"Machine\s*Creation\s*Services", "Citrix MCS", "provisioning", "MCS"),
    (r"Citrix\s*MCS", "Citrix MCS", "provisioning", "MCS"),
    (r"Citrix\s*Workspace\s*App", "Citrix Workspace App", "vdi_client", "Workspace App"),
    (r"Citrix\s*Receiver", "Citrix Receiver", "vdi_client", "Receiver"),
    (r"ICA\s*Client", "Citrix ICA Client", "vdi_client", "ICA Client"),

    # Citrix ADC / NetScaler
    # Citrix ADC (new branding)
    (r"Citrix\s*ADC\s*14\.\d+", "Citrix ADC 14.x", "load_balancer", "ADC 14"),
    (r"Citrix\s*ADC\s*13\.1", "Citrix ADC 13.1", "load_balancer", "ADC 13.1"),
    (r"Citrix\s*ADC\s*13\.0", "Citrix ADC 13.0", "load_balancer", "ADC 13.0"),
    (r"Citrix\s*ADC\s*13", "Citrix ADC 13.x", "load_balancer", "ADC 13"),
    (r"Citrix\s*ADC\s*12\.1", "Citrix ADC 12.1", "load_balancer", "ADC 12.1"),
    (r"Citrix\s*ADC\s*12", "Citrix ADC 12.x", "load_balancer", "ADC 12"),
    (r"Citrix\s*ADC", "Citrix ADC", "load_balancer", "Citrix ADC"),

    # NetScaler (legacy)
    (r"NetScaler\s*14\.\d+", "Citrix NetScaler 14.x", "load_balancer", "NetScaler 14"),
    (r"NetScaler\s*13\.1", "Citrix NetScaler 13.1", "load_balancer", "NetScaler 13.1"),
    (r"NetScaler\s*13\.0", "Citrix NetScaler 13.0", "load_balancer", "NetScaler 13.0"),
    (r"NetScaler\s*12\.1", "Citrix NetScaler 12.1", "load_balancer", "NetScaler 12.1"),
    (r"NetScaler\s*12\.0", "Citrix NetScaler 12.0", "load_balancer", "NetScaler 12.0"),
    (r"NetScaler\s*11\.1", "Citrix NetScaler 11.1", "load_balancer", "NetScaler 11.1"),
    (r"NetScaler\s*11\.0", "Citrix NetScaler 11.0", "load_balancer", "NetScaler 11.0"),
    (r"NetScaler\s*10\.5", "Citrix NetScaler 10.5", "load_balancer", "NetScaler 10.5"),
    (r"NetScaler\s*10\.1", "Citrix NetScaler 10.1", "load_balancer", "NetScaler 10.1"),
    (r"NetScaler", "Citrix NetScaler", "load_balancer", "NetScaler"),

    # ADC/NetScaler Product Types
    (r"ADC\s*VPX", "Citrix ADC VPX (Virtual)", "load_balancer", "ADC VPX"),
    (r"ADC\s*MPX", "Citrix ADC MPX (Hardware)", "load_balancer", "ADC MPX"),
    (r"ADC\s*SDX", "Citrix ADC SDX (Multi-tenant)", "load_balancer", "ADC SDX"),
    (r"ADC\s*CPX", "Citrix ADC CPX (Container)", "load_balancer", "ADC CPX"),
    (r"ADC\s*BLX", "Citrix ADC BLX (Bare Metal)", "load_balancer", "ADC BLX"),
    (r"NetScaler\s*VPX", "Citrix NetScaler VPX", "load_balancer", "NetScaler VPX"),
    (r"NetScaler\s*MPX", "Citrix NetScaler MPX", "load_balancer", "NetScaler MPX"),
    (r"NetScaler\s*SDX", "Citrix NetScaler SDX", "load_balancer", "NetScaler SDX"),

    # Citrix Gateway (formerly NetScaler Gateway)
    (r"Citrix\s*Gateway\s*14", "Citrix Gateway 14.x", "gateway", "Citrix Gateway 14"),
    (r"Citrix\s*Gateway\s*13", "Citrix Gateway 13.x", "gateway", "Citrix Gateway 13"),
    (r"Citrix\s*Gateway\s*12", "Citrix Gateway 12.x", "gateway", "Citrix Gateway 12"),
    (r"Citrix\s*Gateway", "Citrix Gateway", "gateway", "Citrix Gateway"),
    (r"NetScaler\s*Gateway", "Citrix NetScaler Gateway", "gateway", "NetScaler Gateway"),
    (r"Access\s*Gateway", "Citrix Access Gateway", "gateway", "Access Gateway"),

    # Citrix SD-WAN
    (r"Citrix\s*SD-WAN\s*11\.\d+", "Citrix SD-WAN 11.x", "sdwan", "SD-WAN 11"),
    (r"Citrix\s*SD-WAN\s*10\.\d+", "Citrix SD-WAN 10.x", "sdwan", "SD-WAN 10"),
    (r"Citrix\s*SD-WAN", "Citrix SD-WAN", "sdwan", "Citrix SD-WAN"),
    (r"NetScaler\s*SD-WAN", "Citrix SD-WAN", "sdwan", "NetScaler SD-WAN"),
    (r"CloudBridge", "Citrix CloudBridge", "wan_optimizer", "CloudBridge"),

    # Citrix Cloud
    (r"Citrix\s*Cloud", "Citrix Cloud", "cloud", "Citrix Cloud"),
    (r"Citrix\s*DaaS", "Citrix DaaS", "vdi", "Citrix DaaS"),
    (r"Citrix\s*Workspace", "Citrix Workspace", "vdi", "Citrix Workspace"),
    (r"Citrix\s*Analytics", "Citrix Analytics", "analytics", "Citrix Analytics"),
    (r"Citrix\s*Endpoint\s*Management", "Citrix Endpoint Management", "mdm", "CEM"),
    (r"XenMobile", "Citrix XenMobile", "mdm", "XenMobile"),

    # Other Citrix Products
    (r"Citrix\s*ShareFile", "Citrix ShareFile", "file_sharing", "ShareFile"),
    (r"Citrix\s*Content\s*Collaboration", "Citrix Content Collaboration", "file_sharing", "Content Collaboration"),
    (r"Citrix\s*App\s*Layering", "Citrix App Layering", "provisioning", "App Layering"),
    (r"Citrix\s*WEM", "Citrix WEM", "management", "WEM"),
    (r"Workspace\s*Environment\s*Management", "Citrix WEM", "management", "WEM"),
    (r"Citrix\s*Profile\s*Management", "Citrix Profile Management", "management", "UPM"),
    (r"Citrix\s*Federated\s*Authentication", "Citrix FAS", "identity", "FAS"),
    (r"Citrix\s*Licensing", "Citrix License Server", "licensing", "License Server"),

    # Generic Citrix
    (r"Citrix", "Citrix Product", "virtualization", "Citrix"),
]

# NUTANIX PATTERNS (Expanded)

NUTANIX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "50:6B:8D": ("hypervisor", "Virtualization", "Nutanix"),
}

NUTANIX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # AHV (Acropolis Hypervisor)
    (r"Nutanix\s*AHV\s*20\d{2}\.\d+", "Nutanix AHV", "hypervisor", "AHV"),
    (r"Nutanix\s*AHV", "Nutanix AHV", "hypervisor", "AHV"),
    (r"AHV\s*20\d{2}", "Nutanix AHV", "hypervisor", "AHV"),
    (r"Acropolis\s*Hypervisor", "Nutanix AHV", "hypervisor", "AHV"),

    # AOS (Acropolis Operating System)
    (r"Nutanix\s*AOS\s*6\.\d+", "Nutanix AOS 6.x", "hypervisor", "AOS 6"),
    (r"Nutanix\s*AOS\s*5\.\d+", "Nutanix AOS 5.x", "hypervisor", "AOS 5"),
    (r"Nutanix\s*AOS", "Nutanix AOS", "hypervisor", "AOS"),
    (r"AOS\s*6\.", "Nutanix AOS 6.x", "hypervisor", "AOS 6"),
    (r"AOS\s*5\.", "Nutanix AOS 5.x", "hypervisor", "AOS 5"),

    # Prism (Management)
    (r"Prism\s*Central\s*pc\.2024", "Nutanix Prism Central 2024", "management", "PC 2024"),
    (r"Prism\s*Central\s*pc\.2023", "Nutanix Prism Central 2023", "management", "PC 2023"),
    (r"Prism\s*Central\s*pc\.2022", "Nutanix Prism Central 2022", "management", "PC 2022"),
    (r"Prism\s*Central", "Nutanix Prism Central", "management", "Prism Central"),
    (r"Prism\s*Element", "Nutanix Prism Element", "management", "Prism Element"),
    (r"Nutanix\s*Prism", "Nutanix Prism", "management", "Prism"),

    # Nutanix Hardware
    (r"Nutanix\s*NX-\d+-G\d+", "Nutanix NX Series", "hci", "NX Series"),
    (r"Nutanix\s*NX-8\d+", "Nutanix NX-8000 Series", "hci", "NX-8000"),
    (r"Nutanix\s*NX-3\d+", "Nutanix NX-3000 Series", "hci", "NX-3000"),
    (r"Nutanix\s*NX-1\d+", "Nutanix NX-1000 Series", "hci", "NX-1000"),
    (r"Nutanix\s*NX-\d+", "Nutanix NX Series", "hci", "NX Series"),

    # Nutanix Cloud Platform
    (r"Nutanix\s*Cloud\s*Platform", "Nutanix Cloud Platform", "cloud", "NCP"),
    (r"Nutanix\s*Kubernetes\s*Engine", "Nutanix Kubernetes Engine", "kubernetes", "NKE"),
    (r"NKE\s*\d", "Nutanix Kubernetes Engine", "kubernetes", "NKE"),
    (r"Nutanix\s*Calm", "Nutanix Calm", "automation", "Calm"),
    (r"Nutanix\s*Flow", "Nutanix Flow", "sdn", "Flow"),
    (r"Nutanix\s*Era", "Nutanix Era", "database", "Era"),
    (r"Nutanix\s*Files", "Nutanix Files", "storage", "Files"),
    (r"Nutanix\s*Objects", "Nutanix Objects", "storage", "Objects"),
    (r"Nutanix\s*Volumes", "Nutanix Volumes", "storage", "Volumes"),
    (r"Nutanix\s*Mine", "Nutanix Mine", "backup", "Mine"),
    (r"Nutanix\s*Frame", "Nutanix Frame", "vdi", "Frame"),
    (r"Nutanix\s*Xi", "Nutanix Xi", "cloud", "Xi"),

    # Generic
    (r"NTNX", "Nutanix Platform", "hci", "Nutanix"),
    (r"Nutanix", "Nutanix", "hci", "Nutanix"),
]

# OVIRT / RED HAT VIRTUALIZATION PATTERNS

OVIRT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # oVirt
    (r"oVirt\s*4\.5", "oVirt 4.5", "hypervisor", "oVirt 4.5"),
    (r"oVirt\s*4\.4", "oVirt 4.4", "hypervisor", "oVirt 4.4"),
    (r"oVirt\s*4\.3", "oVirt 4.3", "hypervisor", "oVirt 4.3"),
    (r"oVirt\s*4\.\d", "oVirt 4.x", "hypervisor", "oVirt 4"),
    (r"oVirt\s*Node", "oVirt Node", "hypervisor", "oVirt Node"),
    (r"oVirt\s*Engine", "oVirt Engine", "management", "oVirt Engine"),
    (r"oVirt", "oVirt", "hypervisor", "oVirt"),

    # Red Hat Virtualization
    (r"Red\s*Hat\s*Virtualization\s*4\.4", "Red Hat Virtualization 4.4", "hypervisor", "RHV 4.4"),
    (r"Red\s*Hat\s*Virtualization\s*4\.3", "Red Hat Virtualization 4.3", "hypervisor", "RHV 4.3"),
    (r"Red\s*Hat\s*Virtualization\s*4\.2", "Red Hat Virtualization 4.2", "hypervisor", "RHV 4.2"),
    (r"Red\s*Hat\s*Virtualization\s*4", "Red Hat Virtualization 4.x", "hypervisor", "RHV 4"),
    (r"Red\s*Hat\s*Virtualization", "Red Hat Virtualization", "hypervisor", "RHV"),
    (r"RHV\s*4\.\d", "Red Hat Virtualization 4.x", "hypervisor", "RHV 4"),
    (r"RHV\s*Manager", "Red Hat Virtualization Manager", "management", "RHV Manager"),
    (r"RHV-M", "Red Hat Virtualization Manager", "management", "RHV Manager"),
    (r"RHEV\s*3\.\d", "Red Hat Enterprise Virtualization 3.x", "hypervisor", "RHEV 3"),
    (r"RHEV\s*Manager", "RHEV Manager", "management", "RHEV Manager"),
    (r"RHEV-M", "RHEV Manager", "management", "RHEV Manager"),
    (r"RHEV", "Red Hat Enterprise Virtualization", "hypervisor", "RHEV"),

    # Red Hat OpenShift Virtualization
    (r"OpenShift\s*Virtualization", "Red Hat OpenShift Virtualization", "hypervisor", "OpenShift Virt"),
    (r"kubevirt", "KubeVirt", "hypervisor", "KubeVirt"),
    (r"KubeVirt", "KubeVirt", "hypervisor", "KubeVirt"),
]

# OPENSTACK PATTERNS

OPENSTACK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # OpenStack releases (alphabetical)
    (r"OpenStack\s*2024\.2", "OpenStack 2024.2 (Dalmatian)", "cloud", "Dalmatian"),
    (r"OpenStack\s*2024\.1", "OpenStack 2024.1 (Caracal)", "cloud", "Caracal"),
    (r"OpenStack\s*2023\.2", "OpenStack 2023.2 (Bobcat)", "cloud", "Bobcat"),
    (r"OpenStack\s*2023\.1", "OpenStack 2023.1 (Antelope)", "cloud", "Antelope"),
    (r"OpenStack\s*Zed", "OpenStack Zed", "cloud", "Zed"),
    (r"OpenStack\s*Yoga", "OpenStack Yoga", "cloud", "Yoga"),
    (r"OpenStack\s*Xena", "OpenStack Xena", "cloud", "Xena"),
    (r"OpenStack\s*Wallaby", "OpenStack Wallaby", "cloud", "Wallaby"),
    (r"OpenStack\s*Victoria", "OpenStack Victoria", "cloud", "Victoria"),
    (r"OpenStack\s*Ussuri", "OpenStack Ussuri", "cloud", "Ussuri"),
    (r"OpenStack\s*Train", "OpenStack Train", "cloud", "Train"),
    (r"OpenStack\s*Stein", "OpenStack Stein", "cloud", "Stein"),
    (r"OpenStack\s*Rocky", "OpenStack Rocky", "cloud", "Rocky"),
    (r"OpenStack\s*Queens", "OpenStack Queens", "cloud", "Queens"),
    (r"OpenStack\s*Pike", "OpenStack Pike", "cloud", "Pike"),
    (r"OpenStack\s*Ocata", "OpenStack Ocata", "cloud", "Ocata"),
    (r"OpenStack\s*Newton", "OpenStack Newton", "cloud", "Newton"),
    (r"OpenStack\s*Mitaka", "OpenStack Mitaka", "cloud", "Mitaka"),
    (r"OpenStack\s*Liberty", "OpenStack Liberty", "cloud", "Liberty"),
    (r"OpenStack\s*Kilo", "OpenStack Kilo", "cloud", "Kilo"),

    # OpenStack Components
    (r"Nova\s*\d+\.\d+", "OpenStack Nova (Compute)", "cloud", "Nova"),
    (r"nova-api", "OpenStack Nova API", "cloud", "Nova"),
    (r"nova-compute", "OpenStack Nova Compute", "hypervisor", "Nova"),
    (r"Neutron\s*\d+\.\d+", "OpenStack Neutron (Network)", "sdn", "Neutron"),
    (r"neutron-server", "OpenStack Neutron Server", "sdn", "Neutron"),
    (r"Cinder\s*\d+\.\d+", "OpenStack Cinder (Block Storage)", "storage", "Cinder"),
    (r"cinder-api", "OpenStack Cinder API", "storage", "Cinder"),
    (r"Swift\s*\d+\.\d+", "OpenStack Swift (Object Storage)", "storage", "Swift"),
    (r"swift-proxy", "OpenStack Swift Proxy", "storage", "Swift"),
    (r"Glance\s*\d+\.\d+", "OpenStack Glance (Image)", "cloud", "Glance"),
    (r"glance-api", "OpenStack Glance API", "cloud", "Glance"),
    (r"Keystone\s*\d+\.\d+", "OpenStack Keystone (Identity)", "identity", "Keystone"),
    (r"keystone-api", "OpenStack Keystone API", "identity", "Keystone"),
    (r"Horizon", "OpenStack Horizon (Dashboard)", "management", "Horizon"),
    (r"Heat\s*\d+\.\d+", "OpenStack Heat (Orchestration)", "automation", "Heat"),
    (r"heat-api", "OpenStack Heat API", "automation", "Heat"),
    (r"Ceilometer", "OpenStack Ceilometer (Telemetry)", "monitoring", "Ceilometer"),
    (r"Ironic", "OpenStack Ironic (Bare Metal)", "provisioning", "Ironic"),
    (r"Magnum", "OpenStack Magnum (Containers)", "container", "Magnum"),
    (r"Manila", "OpenStack Manila (Shared Filesystems)", "storage", "Manila"),
    (r"Octavia", "OpenStack Octavia (Load Balancer)", "load_balancer", "Octavia"),
    (r"Barbican", "OpenStack Barbican (Key Manager)", "security", "Barbican"),
    (r"Designate", "OpenStack Designate (DNS)", "dns", "Designate"),
    (r"Trove", "OpenStack Trove (Database)", "database", "Trove"),
    (r"Sahara", "OpenStack Sahara (Data Processing)", "data", "Sahara"),
    (r"Zaqar", "OpenStack Zaqar (Messaging)", "messaging", "Zaqar"),
    (r"Murano", "OpenStack Murano (App Catalog)", "cloud", "Murano"),
    (r"Senlin", "OpenStack Senlin (Clustering)", "cloud", "Senlin"),
    (r"Placement", "OpenStack Placement", "cloud", "Placement"),
    (r"Cyborg", "OpenStack Cyborg (Accelerators)", "cloud", "Cyborg"),
    (r"Blazar", "OpenStack Blazar (Reservation)", "cloud", "Blazar"),

    # OpenStack Distributions
    (r"Red\s*Hat\s*OpenStack\s*Platform\s*18", "Red Hat OpenStack Platform 18", "cloud", "RHOSP 18"),
    (r"Red\s*Hat\s*OpenStack\s*Platform\s*17", "Red Hat OpenStack Platform 17", "cloud", "RHOSP 17"),
    (r"Red\s*Hat\s*OpenStack\s*Platform\s*16", "Red Hat OpenStack Platform 16", "cloud", "RHOSP 16"),
    (r"Red\s*Hat\s*OpenStack\s*Platform", "Red Hat OpenStack Platform", "cloud", "RHOSP"),
    (r"RHOSP\s*\d+", "Red Hat OpenStack Platform", "cloud", "RHOSP"),
    (r"Canonical\s*OpenStack", "Canonical OpenStack (Charmed)", "cloud", "Charmed OpenStack"),
    (r"Charmed\s*OpenStack", "Canonical Charmed OpenStack", "cloud", "Charmed OpenStack"),
    (r"MAAS\s*\d+", "Canonical MAAS", "provisioning", "MAAS"),
    (r"MAAS", "Canonical MAAS", "provisioning", "MAAS"),
    (r"Juju\s*\d+", "Canonical Juju", "automation", "Juju"),
    (r"Juju", "Canonical Juju", "automation", "Juju"),
    (r"Mirantis\s*OpenStack", "Mirantis OpenStack", "cloud", "Mirantis"),
    (r"SUSE\s*OpenStack\s*Cloud", "SUSE OpenStack Cloud", "cloud", "SUSE OpenStack"),
    (r"HPE\s*Helion\s*OpenStack", "HPE Helion OpenStack", "cloud", "Helion"),
    (r"Oracle\s*OpenStack", "Oracle OpenStack", "cloud", "Oracle OpenStack"),
    (r"WindRiver\s*Titanium", "Wind River Titanium Cloud", "cloud", "Titanium Cloud"),

    # Generic OpenStack
    (r"OpenStack", "OpenStack", "cloud", "OpenStack"),
]

# MICROSOFT HYPER-V PATTERNS

HYPERV_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Hyper-V Server (standalone)
    (r"Hyper-V\s*Server\s*2022", "Microsoft Hyper-V Server 2022", "hypervisor", "Hyper-V 2022"),
    (r"Hyper-V\s*Server\s*2019", "Microsoft Hyper-V Server 2019", "hypervisor", "Hyper-V 2019"),
    (r"Hyper-V\s*Server\s*2016", "Microsoft Hyper-V Server 2016", "hypervisor", "Hyper-V 2016"),
    (r"Hyper-V\s*Server\s*2012\s*R2", "Microsoft Hyper-V Server 2012 R2", "hypervisor", "Hyper-V 2012 R2"),
    (r"Hyper-V\s*Server\s*2012", "Microsoft Hyper-V Server 2012", "hypervisor", "Hyper-V 2012"),
    (r"Hyper-V\s*Server\s*2008\s*R2", "Microsoft Hyper-V Server 2008 R2", "hypervisor", "Hyper-V 2008 R2"),
    (r"Hyper-V\s*Server", "Microsoft Hyper-V Server", "hypervisor", "Hyper-V Server"),

    # Windows Server with Hyper-V
    (r"Windows\s*Server\s*2022.*Hyper-V", "Windows Server 2022 Hyper-V", "hypervisor", "WS2022 Hyper-V"),
    (r"Windows\s*Server\s*2019.*Hyper-V", "Windows Server 2019 Hyper-V", "hypervisor", "WS2019 Hyper-V"),
    (r"Windows\s*Server\s*2016.*Hyper-V", "Windows Server 2016 Hyper-V", "hypervisor", "WS2016 Hyper-V"),
    (r"Windows\s*Server\s*2012\s*R2.*Hyper-V", "Windows Server 2012 R2 Hyper-V", "hypervisor", "WS2012R2 Hyper-V"),

    # Hyper-V Manager / SCVMM
    (r"System\s*Center\s*Virtual\s*Machine\s*Manager\s*2022", "SCVMM 2022", "management", "SCVMM 2022"),
    (r"System\s*Center\s*Virtual\s*Machine\s*Manager\s*2019", "SCVMM 2019", "management", "SCVMM 2019"),
    (r"System\s*Center\s*Virtual\s*Machine\s*Manager\s*2016", "SCVMM 2016", "management", "SCVMM 2016"),
    (r"System\s*Center\s*Virtual\s*Machine\s*Manager", "Microsoft SCVMM", "management", "SCVMM"),
    (r"SCVMM\s*2022", "Microsoft SCVMM 2022", "management", "SCVMM 2022"),
    (r"SCVMM\s*2019", "Microsoft SCVMM 2019", "management", "SCVMM 2019"),
    (r"SCVMM", "Microsoft SCVMM", "management", "SCVMM"),
    (r"VMM\s*Server", "Microsoft VMM Server", "management", "VMM"),

    # Azure Stack HCI
    (r"Azure\s*Stack\s*HCI\s*23H2", "Azure Stack HCI 23H2", "hci", "Azure Stack HCI 23H2"),
    (r"Azure\s*Stack\s*HCI\s*22H2", "Azure Stack HCI 22H2", "hci", "Azure Stack HCI 22H2"),
    (r"Azure\s*Stack\s*HCI\s*21H2", "Azure Stack HCI 21H2", "hci", "Azure Stack HCI 21H2"),
    (r"Azure\s*Stack\s*HCI\s*20H2", "Azure Stack HCI 20H2", "hci", "Azure Stack HCI 20H2"),
    (r"Azure\s*Stack\s*HCI", "Microsoft Azure Stack HCI", "hci", "Azure Stack HCI"),
    (r"Storage\s*Spaces\s*Direct", "Microsoft S2D", "storage", "S2D"),
    (r"S2D", "Microsoft S2D", "storage", "S2D"),

    # Windows Admin Center
    (r"Windows\s*Admin\s*Center\s*\d+", "Microsoft Windows Admin Center", "management", "WAC"),
    (r"Windows\s*Admin\s*Center", "Microsoft Windows Admin Center", "management", "WAC"),
    (r"WAC\s*\d+", "Microsoft Windows Admin Center", "management", "WAC"),

    # Generic Hyper-V
    (r"Hyper-V", "Microsoft Hyper-V", "hypervisor", "Hyper-V"),
    (r"vmms\.exe", "Microsoft Hyper-V", "hypervisor", "Hyper-V"),
]

# MICROSOFT AZURE CLOUD PATTERNS

AZURE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Azure Kubernetes Service (AKS)
    (r"Azure\s*Kubernetes\s*Service", "Azure Kubernetes Service", "container_orchestrator", "AKS"),
    (r"AKS\s*\d+\.\d+", "Azure Kubernetes Service", "container_orchestrator", "AKS"),
    (r"aks-agentpool", "AKS Node", "container_host", "AKS"),
    (r"aks-nodepool", "AKS Node", "container_host", "AKS"),

    # Azure Container Instances / Apps
    (r"Azure\s*Container\s*Instances", "Azure Container Instances", "container_host", "ACI"),
    (r"Azure\s*Container\s*Apps", "Azure Container Apps", "container_host", "ACA"),

    # Azure Arc
    (r"Azure\s*Arc\s*enabled\s*Kubernetes", "Azure Arc Kubernetes", "container_orchestrator", "Azure Arc K8s"),
    (r"Azure\s*Arc", "Microsoft Azure Arc", "management", "Azure Arc"),

    # Azure VM / IaaS
    (r"Azure\s*VM", "Microsoft Azure VM", "virtual_machine", "Azure VM"),
    (r"walinuxagent", "Azure Linux Agent", "virtual_machine", "Azure VM"),
    (r"WALinuxAgent", "Azure Linux Agent", "virtual_machine", "Azure VM"),
    (r"WindowsAzureGuestAgent", "Azure Windows Agent", "virtual_machine", "Azure VM"),
    (r"azure-provisioning", "Azure VM Provisioning", "virtual_machine", "Azure VM"),

    # Azure App Service
    (r"Azure\s*App\s*Service", "Azure App Service", "cloud", "Azure App Service"),
    (r"Azure\s*Functions", "Azure Functions", "cloud", "Azure Functions"),

    # Azure DevOps / Pipelines
    (r"Azure\s*DevOps\s*Agent", "Azure DevOps Agent", "ci_cd", "Azure DevOps"),
    (r"vsts-agent", "Azure DevOps Agent", "ci_cd", "Azure DevOps"),

    # Generic Azure
    (r"Microsoft\s*Azure", "Microsoft Azure", "cloud", "Azure"),
    (r"Azure\s*Cloud", "Microsoft Azure", "cloud", "Azure"),
]

# CONTAINER ORCHESTRATION PATTERNS (Kubernetes, Docker Swarm, Nomad, etc.)

CONTAINER_ORCH_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Kubernetes
    (r"kubernetes\s*v?1\.3[0-9]", "Kubernetes 1.3x", "container_orchestrator", "Kubernetes"),
    (r"kubernetes\s*v?1\.2[0-9]", "Kubernetes 1.2x", "container_orchestrator", "Kubernetes"),
    (r"kubernetes\s*v?\d+\.\d+", "Kubernetes", "container_orchestrator", "Kubernetes"),
    (r"kubelet\s*v?\d+\.\d+", "Kubernetes Kubelet", "container_host", "Kubernetes"),
    (r"kubelet", "Kubernetes Kubelet", "container_host", "Kubernetes"),
    (r"kube-proxy", "Kubernetes Proxy", "container_orchestrator", "Kubernetes"),
    (r"kube-apiserver", "Kubernetes API Server", "container_orchestrator", "Kubernetes"),
    (r"kube-controller", "Kubernetes Controller", "container_orchestrator", "Kubernetes"),
    (r"kube-scheduler", "Kubernetes Scheduler", "container_orchestrator", "Kubernetes"),
    (r"etcd\s*v?\d+\.\d+", "etcd", "container_orchestrator", "etcd"),

    # k3s / k0s (lightweight Kubernetes)
    (r"k3s\s*v?\d+\.\d+", "k3s (Lightweight K8s)", "container_orchestrator", "k3s"),
    (r"k3s", "k3s (Lightweight K8s)", "container_orchestrator", "k3s"),
    (r"k0s\s*v?\d+\.\d+", "k0s (Zero-Friction K8s)", "container_orchestrator", "k0s"),
    (r"k0s", "k0s (Zero-Friction K8s)", "container_orchestrator", "k0s"),

    # MicroK8s
    (r"microk8s\s*v?\d+\.\d+", "MicroK8s", "container_orchestrator", "MicroK8s"),
    (r"microk8s", "MicroK8s", "container_orchestrator", "MicroK8s"),

    # OpenShift
    (r"OpenShift\s*4\.\d+", "Red Hat OpenShift 4.x", "container_orchestrator", "OpenShift 4"),
    (r"OpenShift\s*3\.\d+", "Red Hat OpenShift 3.x", "container_orchestrator", "OpenShift 3"),
    (r"OpenShift\s*Container\s*Platform", "Red Hat OpenShift", "container_orchestrator", "OpenShift"),
    (r"OKD\s*\d+", "OKD (OpenShift Origin)", "container_orchestrator", "OKD"),

    # Rancher
    (r"Rancher\s*v?\d+\.\d+", "Rancher", "container_orchestrator", "Rancher"),
    (r"Rancher\s*Desktop", "Rancher Desktop", "container_host", "Rancher Desktop"),
    (r"RKE2?\s*v?\d+", "Rancher Kubernetes Engine", "container_orchestrator", "RKE"),

    # Docker Swarm / Docker Engine
    (r"Docker\s*Swarm", "Docker Swarm", "container_orchestrator", "Docker Swarm"),
    (r"dockerd\s*\d+\.\d+", "Docker Engine", "container_host", "Docker"),
    (r"Docker\s*Engine\s*\d+\.\d+", "Docker Engine", "container_host", "Docker"),
    (r"Docker\s*Desktop", "Docker Desktop", "container_host", "Docker Desktop"),
    (r"docker-compose", "Docker Compose", "container_host", "Docker Compose"),

    # Podman
    (r"Podman\s*\d+\.\d+", "Podman", "container_host", "Podman"),
    (r"podman", "Podman", "container_host", "Podman"),

    # containerd / CRI-O
    (r"containerd\s*v?\d+\.\d+", "containerd", "container_host", "containerd"),
    (r"containerd", "containerd", "container_host", "containerd"),
    (r"CRI-O\s*v?\d+\.\d+", "CRI-O", "container_host", "CRI-O"),
    (r"cri-o", "CRI-O", "container_host", "CRI-O"),

    # AWS ECS / EKS
    (r"Amazon\s*EKS", "Amazon EKS", "container_orchestrator", "EKS"),
    (r"Amazon\s*ECS", "Amazon ECS", "container_orchestrator", "ECS"),
    (r"ecs-agent", "Amazon ECS Agent", "container_host", "ECS"),
    (r"Fargate", "AWS Fargate", "container_host", "Fargate"),
    (r"Firecracker\s*v?\d+", "AWS Firecracker", "virtual_machine", "Firecracker"),
    (r"Firecracker", "AWS Firecracker", "virtual_machine", "Firecracker"),

    # Google GKE
    (r"Google\s*Kubernetes\s*Engine", "Google GKE", "container_orchestrator", "GKE"),
    (r"GKE\s*\d+\.\d+", "Google GKE", "container_orchestrator", "GKE"),
    (r"gke-node", "GKE Node", "container_host", "GKE"),

    # HashiCorp Nomad
    (r"Nomad\s*v?\d+\.\d+", "HashiCorp Nomad", "container_orchestrator", "Nomad"),
    (r"Nomad\s*Agent", "HashiCorp Nomad Agent", "container_orchestrator", "Nomad"),
    (r"nomad", "HashiCorp Nomad", "container_orchestrator", "Nomad"),

    # Portainer
    (r"Portainer\s*(CE|BE)?\s*\d+\.\d+", "Portainer", "management", "Portainer"),
    (r"Portainer", "Portainer", "management", "Portainer"),
]

# KVM / QEMU PATTERNS

KVM_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # QEMU/KVM versions
    (r"QEMU\s*9\.\d+", "QEMU 9.x", "hypervisor", "QEMU 9"),
    (r"QEMU\s*8\.\d+", "QEMU 8.x", "hypervisor", "QEMU 8"),
    (r"QEMU\s*7\.\d+", "QEMU 7.x", "hypervisor", "QEMU 7"),
    (r"QEMU\s*6\.\d+", "QEMU 6.x", "hypervisor", "QEMU 6"),
    (r"QEMU\s*5\.\d+", "QEMU 5.x", "hypervisor", "QEMU 5"),
    (r"QEMU\s*4\.\d+", "QEMU 4.x", "hypervisor", "QEMU 4"),
    (r"QEMU\s*\d+\.\d+\.\d+", "QEMU", "hypervisor", "QEMU"),
    (r"qemu-kvm", "QEMU/KVM", "hypervisor", "QEMU/KVM"),
    (r"QEMU", "QEMU", "hypervisor", "QEMU"),

    # libvirt
    (r"libvirt\s*10\.\d+", "libvirt 10.x", "hypervisor", "libvirt 10"),
    (r"libvirt\s*9\.\d+", "libvirt 9.x", "hypervisor", "libvirt 9"),
    (r"libvirt\s*8\.\d+", "libvirt 8.x", "hypervisor", "libvirt 8"),
    (r"libvirt\s*7\.\d+", "libvirt 7.x", "hypervisor", "libvirt 7"),
    (r"libvirt\s*\d+\.\d+\.\d+", "libvirt", "hypervisor", "libvirt"),
    (r"libvirtd", "libvirt daemon", "hypervisor", "libvirt"),
    (r"libvirt", "libvirt", "hypervisor", "libvirt"),

    # Virt-Manager
    (r"virt-manager\s*\d+\.\d+", "Virt-Manager", "management", "Virt-Manager"),
    (r"virt-manager", "Virt-Manager", "management", "Virt-Manager"),
    (r"Virtual\s*Machine\s*Manager", "Virt-Manager", "management", "Virt-Manager"),

    # Cockpit
    (r"cockpit-machines", "Cockpit Machines", "management", "Cockpit"),
    (r"Cockpit\s*\d+", "Cockpit", "management", "Cockpit"),
    (r"Cockpit", "Cockpit", "management", "Cockpit"),

    # Generic KVM
    (r"KVM\s*hypervisor", "KVM Hypervisor", "hypervisor", "KVM"),
    (r"KVM/QEMU", "KVM/QEMU", "hypervisor", "KVM/QEMU"),
]

# ORACLE VM / VIRTUALBOX PATTERNS

ORACLE_VM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # VirtualBox MACs
    "08:00:27": ("virtual_machine", "Virtualization", "VirtualBox VM"),
    "0A:00:27": ("virtual_machine", "Virtualization", "VirtualBox VM"),
    # Oracle VM MACs
    "00:21:F6": ("hypervisor", "Virtualization", "Oracle VM"),
}

ORACLE_VM_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # VirtualBox
    (r"VirtualBox\s*7\.\d+", "Oracle VirtualBox 7.x", "hypervisor", "VirtualBox 7"),
    (r"VirtualBox\s*6\.\d+", "Oracle VirtualBox 6.x", "hypervisor", "VirtualBox 6"),
    (r"VirtualBox\s*5\.\d+", "Oracle VirtualBox 5.x", "hypervisor", "VirtualBox 5"),
    (r"VirtualBox\s*\d+\.\d+\.\d+", "Oracle VirtualBox", "hypervisor", "VirtualBox"),
    (r"VirtualBox", "Oracle VirtualBox", "hypervisor", "VirtualBox"),
    (r"VBox", "Oracle VirtualBox", "hypervisor", "VirtualBox"),
    (r"vboxdrv", "Oracle VirtualBox", "hypervisor", "VirtualBox"),

    # Oracle VM Server
    (r"Oracle\s*VM\s*Server\s*3\.4", "Oracle VM Server 3.4", "hypervisor", "OVM 3.4"),
    (r"Oracle\s*VM\s*Server\s*3\.3", "Oracle VM Server 3.3", "hypervisor", "OVM 3.3"),
    (r"Oracle\s*VM\s*Server\s*3\.2", "Oracle VM Server 3.2", "hypervisor", "OVM 3.2"),
    (r"Oracle\s*VM\s*Server\s*3", "Oracle VM Server 3.x", "hypervisor", "OVM 3"),
    (r"Oracle\s*VM\s*Server", "Oracle VM Server", "hypervisor", "OVM Server"),

    # Oracle VM Manager
    (r"Oracle\s*VM\s*Manager\s*3\.4", "Oracle VM Manager 3.4", "management", "OVM Manager 3.4"),
    (r"Oracle\s*VM\s*Manager\s*3\.3", "Oracle VM Manager 3.3", "management", "OVM Manager 3.3"),
    (r"Oracle\s*VM\s*Manager", "Oracle VM Manager", "management", "OVM Manager"),

    # Oracle Linux Virtualization Manager (OLVM)
    (r"Oracle\s*Linux\s*Virtualization\s*Manager", "Oracle Linux Virtualization Manager", "management", "OLVM"),
    (r"OLVM\s*\d+", "Oracle Linux Virtualization Manager", "management", "OLVM"),
    (r"OLVM", "Oracle Linux Virtualization Manager", "management", "OLVM"),

    # Oracle Private Cloud Appliance
    (r"Oracle\s*Private\s*Cloud\s*Appliance", "Oracle Private Cloud Appliance", "hci", "PCA"),
    (r"Oracle\s*PCA", "Oracle Private Cloud Appliance", "hci", "PCA"),
]


# NETAPP STORAGE PATTERNS

NETAPP_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:A0:98": ("storage", "Storage", "NetApp"),
    "00:0D:A2": ("storage", "Storage", "NetApp"),
}

NETAPP_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # AFF (All Flash FAS)
    (r"AFF\s*A\d{3}", "NetApp AFF A-Series", "storage", "ONTAP"),
    (r"AFF\s*C\d{3}", "NetApp AFF C-Series", "storage", "ONTAP"),
    # FAS Series
    (r"FAS\s*\d{4}", "NetApp FAS Series", "storage", "ONTAP"),
    # ONTAP versions
    (r"ONTAP\s*9\.1[4-9]", "NetApp ONTAP 9.1x", "storage", "ONTAP 9"),
    (r"ONTAP\s*9\.\d+", "NetApp ONTAP 9.x", "storage", "ONTAP 9"),
    (r"Data\s*ONTAP", "NetApp Data ONTAP", "storage", "Data ONTAP"),
    # StorageGRID
    (r"StorageGRID", "NetApp StorageGRID", "object_storage", "StorageGRID"),
    # E-Series
    (r"E-Series\s*E\d{4}", "NetApp E-Series", "storage", "SANtricity"),
    (r"SANtricity", "NetApp SANtricity", "storage", "SANtricity"),
    # Cloud Volumes
    (r"Cloud\s*Volumes\s*ONTAP", "NetApp Cloud Volumes ONTAP", "cloud_storage", "CVO"),
    # Generic
    (r"NetApp", "NetApp Storage", "storage", "ONTAP"),
]

# DELL EMC STORAGE PATTERNS

EMC_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:97": ("storage", "Storage", "Dell EMC"),
    "00:01:44": ("storage", "Storage", "Dell EMC"),
    "00:60:48": ("storage", "Storage", "Dell EMC"),
}

EMC_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # PowerStore
    (r"PowerStore\s*\d{4}", "Dell PowerStore", "storage", "PowerStoreOS"),
    (r"PowerStore", "Dell PowerStore", "storage", "PowerStoreOS"),
    # PowerScale (Isilon)
    (r"PowerScale", "Dell PowerScale", "nas", "OneFS"),
    (r"Isilon", "Dell EMC Isilon", "nas", "OneFS"),
    (r"OneFS\s*\d+", "Dell PowerScale OneFS", "nas", "OneFS"),
    # PowerMax/VMAX
    (r"PowerMax", "Dell PowerMax", "storage", "PowerMaxOS"),
    (r"VMAX\s*\d+", "Dell EMC VMAX", "storage", "HYPERMAX"),
    # Unity
    (r"Unity\s*XT\s*\d{3}", "Dell Unity XT", "storage", "UnityOS"),
    (r"Unity\s*\d{3}", "Dell EMC Unity", "storage", "UnityOS"),
    (r"UnityVSA", "Dell Unity VSA", "virtual_storage", "UnityOS"),
    # VNX
    (r"VNX\s*\d{4}", "Dell EMC VNX", "storage", "VNX OE"),
    # Data Domain
    (r"Data\s*Domain\s*DD\d+", "Dell Data Domain", "backup", "DDOS"),
    (r"Data\s*Domain", "Dell Data Domain", "backup", "DDOS"),
    (r"PowerProtect\s*DD", "Dell PowerProtect DD", "backup", "DDOS"),
    # Avamar
    (r"Avamar", "Dell EMC Avamar", "backup", "Avamar"),
    # RecoverPoint
    (r"RecoverPoint", "Dell EMC RecoverPoint", "replication", "RecoverPoint"),
    # Generic
    (r"EMC\s*Storage", "Dell EMC Storage", "storage", None),
]

# PURE STORAGE PATTERNS

PURE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "24:A9:37": ("storage", "Storage", "Pure Storage"),
}

PURE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # FlashArray
    (r"FlashArray//X\d{2}", "Pure FlashArray//X", "storage", "Purity"),
    (r"FlashArray//XL", "Pure FlashArray//XL", "storage", "Purity"),
    (r"FlashArray//C", "Pure FlashArray//C", "storage", "Purity"),
    (r"FlashArray//E", "Pure FlashArray//E", "storage", "Purity"),
    (r"FlashArray", "Pure FlashArray", "storage", "Purity"),
    # FlashBlade
    (r"FlashBlade//S", "Pure FlashBlade//S", "nas", "Purity//FB"),
    (r"FlashBlade//E", "Pure FlashBlade//E", "nas", "Purity//FB"),
    (r"FlashBlade", "Pure FlashBlade", "nas", "Purity//FB"),
    # Purity versions
    (r"Purity\s*6\.\d+", "Pure Purity 6.x", "storage", "Purity 6"),
    (r"Purity//FA", "Pure Purity//FA", "storage", "Purity//FA"),
    (r"Purity//FB", "Pure Purity//FB", "nas", "Purity//FB"),
    # Pure1/Cloud
    (r"Pure1", "Pure Pure1", "management", "Pure1"),
    (r"Cloud\s*Block\s*Store", "Pure Cloud Block Store", "cloud_storage", "CBS"),
    # Generic
    (r"Pure\s*Storage", "Pure Storage", "storage", "Purity"),
]

# ASUSTOR NAS PATTERNS

ASUSTOR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

ASUSTOR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Lockerstor Series
    (r"Lockerstor\s*\d+", "ASUSTOR Lockerstor", "nas", "ADM"),
    (r"AS\s*67\d{2}", "ASUSTOR Lockerstor", "nas", "ADM"),
    # Drivestor Series
    (r"Drivestor\s*\d+", "ASUSTOR Drivestor", "nas", "ADM"),
    (r"AS\s*11\d{2}", "ASUSTOR Drivestor", "nas", "ADM"),
    # Nimbustor Series
    (r"Nimbustor\s*\d+", "ASUSTOR Nimbustor", "nas", "ADM"),
    (r"AS\s*54\d{2}", "ASUSTOR Nimbustor", "nas", "ADM"),
    # Flashstor Series
    (r"Flashstor\s*\d+", "ASUSTOR Flashstor", "nas", "ADM"),
    (r"AS\s*FS\d+", "ASUSTOR Flashstor", "nas", "ADM"),
    # ADM OS
    (r"ADM\s*4\.\d+", "ASUSTOR ADM 4.x", "nas", "ADM 4"),
    (r"ADM\s*\d+\.\d+", "ASUSTOR ADM", "nas", "ADM"),
    # Generic
    (r"ASUSTOR", "ASUSTOR NAS", "nas", "ADM"),
]

# TERRAMASTER NAS PATTERNS

TERRAMASTER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

TERRAMASTER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # F Series (Home/SOHO)
    (r"F[248]-\d{3}", "TerraMaster F-Series", "nas", "TOS"),
    # T Series (Tower)
    (r"T[469]-\d{3}", "TerraMaster T-Series", "nas", "TOS"),
    # U Series (Rackmount)
    (r"U[48]-\d{3}", "TerraMaster U-Series", "nas", "TOS"),
    (r"U\d{2}-\d{3}", "TerraMaster U-Series", "nas", "TOS"),
    # D Series (DAS)
    (r"D[248]-\d{3}", "TerraMaster D-Series DAS", "das", "TOS"),
    # TOS versions
    (r"TOS\s*5\.\d+", "TerraMaster TOS 5.x", "nas", "TOS 5"),
    (r"TOS\s*\d+\.\d+", "TerraMaster TOS", "nas", "TOS"),
    # Generic
    (r"TerraMaster", "TerraMaster NAS", "nas", "TOS"),
]


# APPLE DEVICE PATTERNS

APPLE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Apple has hundreds of OUIs - these are common ones
    "00:03:93": ("computer", "Computer", "Apple Device"),
    "00:05:02": ("computer", "Computer", "Apple Device"),
    "00:0A:27": ("computer", "Computer", "Apple Device"),
    "00:0A:95": ("computer", "Computer", "Apple Device"),
    "00:0D:93": ("computer", "Computer", "Apple Device"),
    "00:11:24": ("computer", "Computer", "Apple Device"),
    "00:14:51": ("computer", "Computer", "Apple Device"),
    "00:16:CB": ("computer", "Computer", "Apple Device"),
    "00:17:F2": ("computer", "Computer", "Apple Device"),
    "00:19:E3": ("computer", "Computer", "Apple Device"),
    "00:1B:63": ("computer", "Computer", "Apple Device"),
    "00:1C:B3": ("computer", "Computer", "Apple Device"),
    "00:1D:4F": ("computer", "Computer", "Apple Device"),
    "00:1E:52": ("computer", "Computer", "Apple Device"),
    "00:1E:C2": ("computer", "Computer", "Apple Device"),
    "00:1F:5B": ("computer", "Computer", "Apple Device"),
    "00:1F:F3": ("computer", "Computer", "Apple Device"),
    "00:21:E9": ("computer", "Computer", "Apple Device"),
    "00:22:41": ("computer", "Computer", "Apple Device"),
    "00:23:12": ("computer", "Computer", "Apple Device"),
    "00:23:32": ("computer", "Computer", "Apple Device"),
    "00:23:6C": ("computer", "Computer", "Apple Device"),
    "00:23:DF": ("computer", "Computer", "Apple Device"),
    "00:24:36": ("computer", "Computer", "Apple Device"),
    "00:25:00": ("computer", "Computer", "Apple Device"),
    "00:25:4B": ("computer", "Computer", "Apple Device"),
    "00:25:BC": ("computer", "Computer", "Apple Device"),
    "00:26:08": ("computer", "Computer", "Apple Device"),
    "00:26:4A": ("computer", "Computer", "Apple Device"),
    "00:26:B0": ("computer", "Computer", "Apple Device"),
    "00:26:BB": ("computer", "Computer", "Apple Device"),
    "28:CF:DA": ("phone", "Mobile", "iPhone"),
    "34:08:BC": ("phone", "Mobile", "iPhone"),
    "38:0F:4A": ("phone", "Mobile", "iPhone"),
    "3C:06:30": ("phone", "Mobile", "iPhone"),
    "40:98:AD": ("phone", "Mobile", "iPhone"),
    "50:7A:55": ("phone", "Mobile", "iPhone"),
    "70:48:0F": ("phone", "Mobile", "iPhone"),
    "78:31:C1": ("phone", "Mobile", "iPhone"),
    "78:CA:39": ("phone", "Mobile", "iPhone"),
    "80:E6:50": ("phone", "Mobile", "iPhone"),
    "84:FC:FE": ("phone", "Mobile", "iPhone"),
    "88:66:5A": ("phone", "Mobile", "iPhone"),
    "8C:FA:BA": ("phone", "Mobile", "iPhone"),
    "90:84:0D": ("phone", "Mobile", "iPhone"),
    "98:01:A7": ("phone", "Mobile", "iPhone"),
    "9C:20:7B": ("phone", "Mobile", "iPhone"),
    "9C:F4:8E": ("phone", "Mobile", "iPhone"),
    "A4:D1:D2": ("phone", "Mobile", "iPhone"),
    "AC:3C:0B": ("phone", "Mobile", "iPhone"),
    "B0:34:95": ("phone", "Mobile", "iPhone"),
    "B8:63:4D": ("phone", "Mobile", "iPhone"),
    "BC:52:B7": ("phone", "Mobile", "iPhone"),
    "C8:B5:B7": ("phone", "Mobile", "iPhone"),
    "D0:E1:40": ("phone", "Mobile", "iPhone"),
    "D8:CF:9C": ("phone", "Mobile", "iPhone"),
    "E0:B5:2D": ("phone", "Mobile", "iPhone"),
    "E4:25:E7": ("phone", "Mobile", "iPhone"),
    "F0:B4:79": ("phone", "Mobile", "iPhone"),
    "F4:0F:24": ("phone", "Mobile", "iPhone"),
    "F8:27:93": ("phone", "Mobile", "iPhone"),
    "FC:E9:98": ("phone", "Mobile", "iPhone"),
    # Modern Apple OUIs (IEEE verified)
    "04:0C:CE": ("computer", "Computer", "Apple Device"),
    "04:15:52": ("computer", "Computer", "Apple Device"),
    "04:26:65": ("computer", "Computer", "Apple Device"),
    "04:48:9A": ("computer", "Computer", "Apple Device"),
    "04:52:F3": ("computer", "Computer", "Apple Device"),
    "04:DB:56": ("computer", "Computer", "Apple Device"),
    "04:E5:36": ("computer", "Computer", "Apple Device"),
    "04:F7:E4": ("computer", "Computer", "Apple Device"),
    "08:6D:41": ("computer", "Computer", "Apple Device"),
    "0C:4D:E9": ("computer", "Computer", "Apple Device"),
    "0C:51:01": ("computer", "Computer", "Apple Device"),
    "0C:74:C2": ("computer", "Computer", "Apple Device"),
    "0C:BC:9F": ("computer", "Computer", "Apple Device"),
    "10:1C:0C": ("computer", "Computer", "Apple Device"),
    "10:40:F3": ("computer", "Computer", "Apple Device"),
    "10:9A:DD": ("computer", "Computer", "Apple Device"),
    "14:10:9F": ("computer", "Computer", "Apple Device"),
    "14:20:5E": ("computer", "Computer", "Apple Device"),
    "14:5A:05": ("computer", "Computer", "Apple Device"),
    "14:7D:DA": ("computer", "Computer", "Apple Device"),
    "14:8F:C6": ("computer", "Computer", "Apple Device"),
    "14:99:E2": ("computer", "Computer", "Apple Device"),
    "18:20:32": ("computer", "Computer", "Apple Device"),
    "18:34:51": ("computer", "Computer", "Apple Device"),
    "18:65:90": ("computer", "Computer", "Apple Device"),
    "18:AF:61": ("computer", "Computer", "Apple Device"),
    "18:E7:F4": ("computer", "Computer", "Apple Device"),
    "1C:36:BB": ("computer", "Computer", "Apple Device"),
    "1C:91:48": ("computer", "Computer", "Apple Device"),
    "1C:E6:2B": ("computer", "Computer", "Apple Device"),
    "20:3C:AE": ("computer", "Computer", "Apple Device"),
    "20:78:F0": ("computer", "Computer", "Apple Device"),
    "20:9B:CD": ("computer", "Computer", "Apple Device"),
    "20:A2:E4": ("computer", "Computer", "Apple Device"),
    "20:AB:37": ("computer", "Computer", "Apple Device"),
    "20:C9:D0": ("computer", "Computer", "Apple Device"),
    "24:24:0E": ("computer", "Computer", "Apple Device"),
    "24:A0:74": ("computer", "Computer", "Apple Device"),
    "24:A2:E1": ("computer", "Computer", "Apple Device"),
    "24:AB:81": ("computer", "Computer", "Apple Device"),
    "24:F0:94": ("computer", "Computer", "Apple Device"),
    "28:6A:BA": ("computer", "Computer", "Apple Device"),
    "28:A0:2B": ("computer", "Computer", "Apple Device"),
    "28:E0:2C": ("computer", "Computer", "Apple Device"),
    "28:E1:4C": ("computer", "Computer", "Apple Device"),
    "28:ED:6A": ("computer", "Computer", "Apple Device"),
    "2C:1F:23": ("computer", "Computer", "Apple Device"),
    "2C:33:61": ("computer", "Computer", "Apple Device"),
    "2C:BE:08": ("computer", "Computer", "Apple Device"),
    "30:10:E4": ("computer", "Computer", "Apple Device"),
    "30:35:AD": ("computer", "Computer", "Apple Device"),
    "30:63:6B": ("computer", "Computer", "Apple Device"),
    "30:90:AB": ("computer", "Computer", "Apple Device"),
    "34:36:3B": ("computer", "Computer", "Apple Device"),
    "34:C0:59": ("computer", "Computer", "Apple Device"),
    "34:E2:FD": ("computer", "Computer", "Apple Device"),
    "38:48:4C": ("computer", "Computer", "Apple Device"),
    "38:53:9C": ("computer", "Computer", "Apple Device"),
    "38:66:F0": ("computer", "Computer", "Apple Device"),
    "38:89:2C": ("computer", "Computer", "Apple Device"),
    "38:B5:4D": ("computer", "Computer", "Apple Device"),
    "38:C9:86": ("computer", "Computer", "Apple Device"),
    "3C:07:54": ("computer", "Computer", "Apple Device"),
    "3C:15:C2": ("computer", "Computer", "Apple Device"),
    "3C:22:FB": ("computer", "Computer", "Apple Device"),
    "3C:2E:F9": ("computer", "Computer", "Apple Device"),
    "40:30:04": ("computer", "Computer", "Apple Device"),
    "40:33:1A": ("computer", "Computer", "Apple Device"),
    "40:4D:7F": ("computer", "Computer", "Apple Device"),
    "40:A6:D9": ("computer", "Computer", "Apple Device"),
    "40:B3:95": ("computer", "Computer", "Apple Device"),
    "40:BC:60": ("computer", "Computer", "Apple Device"),
    "40:CB:C0": ("computer", "Computer", "Apple Device"),
    "44:00:10": ("computer", "Computer", "Apple Device"),
    "44:2A:60": ("computer", "Computer", "Apple Device"),
    "44:D8:84": ("computer", "Computer", "Apple Device"),
    "48:43:7C": ("computer", "Computer", "Apple Device"),
    "48:60:BC": ("computer", "Computer", "Apple Device"),
    "48:74:6E": ("computer", "Computer", "Apple Device"),
    "48:A9:1C": ("computer", "Computer", "Apple Device"),
    "48:BF:6B": ("computer", "Computer", "Apple Device"),
    "48:E9:F1": ("computer", "Computer", "Apple Device"),
    "4C:32:75": ("computer", "Computer", "Apple Device"),
    "4C:57:CA": ("computer", "Computer", "Apple Device"),
    "4C:8D:79": ("computer", "Computer", "Apple Device"),
    "50:82:D5": ("computer", "Computer", "Apple Device"),
    "50:BC:96": ("computer", "Computer", "Apple Device"),
    "50:ED:3C": ("computer", "Computer", "Apple Device"),
    "54:26:96": ("computer", "Computer", "Apple Device"),
    "54:4E:90": ("computer", "Computer", "Apple Device"),
    "54:72:4F": ("computer", "Computer", "Apple Device"),
    "54:99:63": ("computer", "Computer", "Apple Device"),
    "54:AE:27": ("computer", "Computer", "Apple Device"),
    "54:EA:A8": ("computer", "Computer", "Apple Device"),
    "58:1F:AA": ("computer", "Computer", "Apple Device"),
    "58:40:4E": ("computer", "Computer", "Apple Device"),
    "58:55:CA": ("computer", "Computer", "Apple Device"),
    "58:B0:35": ("computer", "Computer", "Apple Device"),
    "5C:59:48": ("computer", "Computer", "Apple Device"),
    "5C:96:9D": ("computer", "Computer", "Apple Device"),
    "5C:F7:E6": ("computer", "Computer", "Apple Device"),
    "60:03:08": ("computer", "Computer", "Apple Device"),
    "60:33:4B": ("computer", "Computer", "Apple Device"),
    "60:69:44": ("computer", "Computer", "Apple Device"),
    "60:8C:4A": ("computer", "Computer", "Apple Device"),
    "60:A3:7D": ("computer", "Computer", "Apple Device"),
    "60:C5:47": ("computer", "Computer", "Apple Device"),
    "60:D9:C7": ("computer", "Computer", "Apple Device"),
    "60:F4:45": ("computer", "Computer", "Apple Device"),
    "60:FA:CD": ("computer", "Computer", "Apple Device"),
    "60:FB:42": ("computer", "Computer", "Apple Device"),
    "64:20:0C": ("computer", "Computer", "Apple Device"),
    "64:70:33": ("computer", "Computer", "Apple Device"),
    "64:76:BA": ("computer", "Computer", "Apple Device"),
    "64:9A:BE": ("computer", "Computer", "Apple Device"),
    "64:B0:A6": ("computer", "Computer", "Apple Device"),
    "64:E6:82": ("computer", "Computer", "Apple Device"),
    "68:09:27": ("computer", "Computer", "Apple Device"),
    "68:5B:35": ("computer", "Computer", "Apple Device"),
    "68:64:4B": ("computer", "Computer", "Apple Device"),
    "68:96:7B": ("computer", "Computer", "Apple Device"),
    "68:9C:70": ("computer", "Computer", "Apple Device"),
    "68:A8:6D": ("computer", "Computer", "Apple Device"),
    "68:AB:1E": ("computer", "Computer", "Apple Device"),
    "68:AE:20": ("computer", "Computer", "Apple Device"),
    "68:D9:3C": ("computer", "Computer", "Apple Device"),
    "68:DB:CA": ("computer", "Computer", "Apple Device"),
    "68:FE:F7": ("computer", "Computer", "Apple Device"),
    "6C:19:C0": ("computer", "Computer", "Apple Device"),
    "6C:3E:6D": ("computer", "Computer", "Apple Device"),
    "6C:40:08": ("computer", "Computer", "Apple Device"),
    "6C:4D:73": ("computer", "Computer", "Apple Device"),
    "6C:70:9F": ("computer", "Computer", "Apple Device"),
    "6C:72:E7": ("computer", "Computer", "Apple Device"),
    "6C:96:CF": ("computer", "Computer", "Apple Device"),
    "6C:AB:31": ("computer", "Computer", "Apple Device"),
    "70:11:24": ("computer", "Computer", "Apple Device"),
    "70:3E:AC": ("computer", "Computer", "Apple Device"),
    "70:56:81": ("computer", "Computer", "Apple Device"),
    "70:73:CB": ("computer", "Computer", "Apple Device"),
    "70:81:EB": ("computer", "Computer", "Apple Device"),
    "70:A2:B3": ("computer", "Computer", "Apple Device"),
    "70:CD:60": ("computer", "Computer", "Apple Device"),
    "70:DE:E2": ("computer", "Computer", "Apple Device"),
    "70:E7:2C": ("computer", "Computer", "Apple Device"),
    "74:1B:B2": ("computer", "Computer", "Apple Device"),
    "74:42:8B": ("computer", "Computer", "Apple Device"),
    "74:8D:08": ("computer", "Computer", "Apple Device"),
    "74:E1:B6": ("computer", "Computer", "Apple Device"),
    "74:E2:F5": ("computer", "Computer", "Apple Device"),
    "78:3A:84": ("computer", "Computer", "Apple Device"),
    "78:67:D7": ("computer", "Computer", "Apple Device"),
    "78:6C:1C": ("computer", "Computer", "Apple Device"),
    "78:7B:8A": ("computer", "Computer", "Apple Device"),
    "78:88:6D": ("computer", "Computer", "Apple Device"),
    "78:A3:E4": ("computer", "Computer", "Apple Device"),
    "78:D7:5F": ("computer", "Computer", "Apple Device"),
    "78:FD:94": ("computer", "Computer", "Apple Device"),
    "7C:11:BE": ("computer", "Computer", "Apple Device"),
    "7C:50:49": ("computer", "Computer", "Apple Device"),
    "7C:6D:62": ("computer", "Computer", "Apple Device"),
    "7C:9A:1D": ("computer", "Computer", "Apple Device"),
    "7C:C3:A1": ("computer", "Computer", "Apple Device"),
    "7C:D1:C3": ("computer", "Computer", "Apple Device"),
    "7C:FA:DF": ("computer", "Computer", "Apple Device"),
    "80:00:6E": ("computer", "Computer", "Apple Device"),
    "80:49:71": ("computer", "Computer", "Apple Device"),
    "80:82:23": ("computer", "Computer", "Apple Device"),
    "80:92:9F": ("computer", "Computer", "Apple Device"),
    "80:B0:3D": ("computer", "Computer", "Apple Device"),
    "80:BE:05": ("computer", "Computer", "Apple Device"),
    "80:EA:96": ("computer", "Computer", "Apple Device"),
    "80:ED:2C": ("computer", "Computer", "Apple Device"),
    "84:38:35": ("computer", "Computer", "Apple Device"),
    "84:78:8B": ("computer", "Computer", "Apple Device"),
    "84:85:06": ("computer", "Computer", "Apple Device"),
    "84:89:AD": ("computer", "Computer", "Apple Device"),
    "84:B1:53": ("computer", "Computer", "Apple Device"),
    # REMOVED: 84:F3:EB - IEEE assigns to Espressif Inc., not Apple
    "88:19:08": ("computer", "Computer", "Apple Device"),
    "88:1F:A1": ("computer", "Computer", "Apple Device"),
    "88:53:95": ("computer", "Computer", "Apple Device"),
    "88:6B:6E": ("computer", "Computer", "Apple Device"),
    "88:C6:63": ("computer", "Computer", "Apple Device"),
    "88:CB:87": ("computer", "Computer", "Apple Device"),
    "88:E8:7F": ("computer", "Computer", "Apple Device"),
    "8C:00:6D": ("computer", "Computer", "Apple Device"),
    "8C:29:37": ("computer", "Computer", "Apple Device"),
    "8C:2D:AA": ("computer", "Computer", "Apple Device"),
    "8C:58:77": ("computer", "Computer", "Apple Device"),
    "8C:7B:9D": ("computer", "Computer", "Apple Device"),
    "8C:85:90": ("computer", "Computer", "Apple Device"),
    "8C:8E:F2": ("computer", "Computer", "Apple Device"),
    "8C:FE:57": ("computer", "Computer", "Apple Device"),
    "90:27:E4": ("computer", "Computer", "Apple Device"),
    "90:3C:92": ("computer", "Computer", "Apple Device"),
    "90:60:F1": ("computer", "Computer", "Apple Device"),
    "90:72:40": ("computer", "Computer", "Apple Device"),
    "90:8D:6C": ("computer", "Computer", "Apple Device"),
    "90:B0:ED": ("computer", "Computer", "Apple Device"),
    "90:B2:1F": ("computer", "Computer", "Apple Device"),
    "90:C1:C6": ("computer", "Computer", "Apple Device"),
    "90:DD:5D": ("computer", "Computer", "Apple Device"),
    "90:FD:61": ("computer", "Computer", "Apple Device"),
    # REMOVED: 94:B5:55 - IEEE assigns to Espressif Inc., not Apple
    "94:E9:6A": ("computer", "Computer", "Apple Device"),
    "94:F6:A3": ("computer", "Computer", "Apple Device"),
    "98:03:D8": ("computer", "Computer", "Apple Device"),
    "98:10:E8": ("computer", "Computer", "Apple Device"),
    "98:46:0A": ("computer", "Computer", "Apple Device"),
    "98:5A:EB": ("computer", "Computer", "Apple Device"),
    "98:B8:E3": ("computer", "Computer", "Apple Device"),
    "98:D6:BB": ("computer", "Computer", "Apple Device"),
    "98:E0:D9": ("computer", "Computer", "Apple Device"),
    "98:F0:AB": ("computer", "Computer", "Apple Device"),
    "98:FE:94": ("computer", "Computer", "Apple Device"),
    "9C:04:EB": ("computer", "Computer", "Apple Device"),
    "9C:35:EB": ("computer", "Computer", "Apple Device"),
    "9C:84:BF": ("computer", "Computer", "Apple Device"),
    "9C:8B:A0": ("computer", "Computer", "Apple Device"),
    "9C:E3:3F": ("computer", "Computer", "Apple Device"),
    "9C:FC:01": ("computer", "Computer", "Apple Device"),
    "A0:11:65": ("computer", "Computer", "Apple Device"),
    "A0:4E:A7": ("computer", "Computer", "Apple Device"),
    "A0:56:F3": ("computer", "Computer", "Apple Device"),
    "A0:78:17": ("computer", "Computer", "Apple Device"),
    "A0:99:9B": ("computer", "Computer", "Apple Device"),
    "A0:D7:95": ("computer", "Computer", "Apple Device"),
    "A0:ED:CD": ("computer", "Computer", "Apple Device"),
    "A4:5E:60": ("computer", "Computer", "Apple Device"),
    "A4:67:06": ("computer", "Computer", "Apple Device"),
    "A4:83:E7": ("computer", "Computer", "Apple Device"),
    "A4:B1:97": ("computer", "Computer", "Apple Device"),
    "A4:D9:31": ("computer", "Computer", "Apple Device"),
    "A4:F1:E8": ("computer", "Computer", "Apple Device"),
    "A8:20:66": ("computer", "Computer", "Apple Device"),
    "A8:51:AB": ("computer", "Computer", "Apple Device"),
    "A8:5C:2C": ("computer", "Computer", "Apple Device"),
    "A8:66:7F": ("computer", "Computer", "Apple Device"),
    "A8:86:DD": ("computer", "Computer", "Apple Device"),
    "A8:88:08": ("computer", "Computer", "Apple Device"),
    "A8:BB:CF": ("computer", "Computer", "Apple Device"),
    "A8:BE:27": ("computer", "Computer", "Apple Device"),
    "A8:FA:D8": ("computer", "Computer", "Apple Device"),
    "AC:29:3A": ("computer", "Computer", "Apple Device"),
    "AC:7F:3E": ("computer", "Computer", "Apple Device"),
    "AC:87:A3": ("computer", "Computer", "Apple Device"),
    "AC:CF:5C": ("computer", "Computer", "Apple Device"),
    "AC:E4:B5": ("computer", "Computer", "Apple Device"),
    "AC:FD:EC": ("computer", "Computer", "Apple Device"),
    "B0:19:C6": ("computer", "Computer", "Apple Device"),
    "B0:48:1A": ("computer", "Computer", "Apple Device"),
    "B0:65:BD": ("computer", "Computer", "Apple Device"),
    "B0:70:2D": ("computer", "Computer", "Apple Device"),
    "B0:9F:BA": ("computer", "Computer", "Apple Device"),
    "B4:18:D1": ("computer", "Computer", "Apple Device"),
    "B4:4B:D2": ("computer", "Computer", "Apple Device"),
    "B4:8B:19": ("computer", "Computer", "Apple Device"),
    "B4:F0:AB": ("computer", "Computer", "Apple Device"),
    "B8:09:8A": ("computer", "Computer", "Apple Device"),
    "B8:17:C2": ("computer", "Computer", "Apple Device"),
    "B8:41:A4": ("computer", "Computer", "Apple Device"),
    "B8:44:D9": ("computer", "Computer", "Apple Device"),
    "B8:53:AC": ("computer", "Computer", "Apple Device"),
    "B8:5D:0A": ("computer", "Computer", "Apple Device"),
    "B8:78:2E": ("computer", "Computer", "Apple Device"),
    "B8:7B:C5": ("computer", "Computer", "Apple Device"),
    "B8:8D:12": ("computer", "Computer", "Apple Device"),
    "B8:C1:11": ("computer", "Computer", "Apple Device"),
    "B8:C7:5D": ("computer", "Computer", "Apple Device"),
    "B8:E8:56": ("computer", "Computer", "Apple Device"),
    "B8:F6:B1": ("computer", "Computer", "Apple Device"),
    "BC:4C:C4": ("computer", "Computer", "Apple Device"),
    "BC:67:78": ("computer", "Computer", "Apple Device"),
    "BC:6C:21": ("computer", "Computer", "Apple Device"),
    "BC:92:6B": ("computer", "Computer", "Apple Device"),
    "BC:A9:20": ("computer", "Computer", "Apple Device"),
    "BC:D0:74": ("computer", "Computer", "Apple Device"),
    "BC:EC:5D": ("computer", "Computer", "Apple Device"),
    "C0:1A:DA": ("computer", "Computer", "Apple Device"),
    "C0:63:94": ("computer", "Computer", "Apple Device"),
    "C0:84:7A": ("computer", "Computer", "Apple Device"),
    "C0:9F:42": ("computer", "Computer", "Apple Device"),
    "C0:A5:3E": ("computer", "Computer", "Apple Device"),
    "C0:B6:58": ("computer", "Computer", "Apple Device"),
    "C0:CC:F8": ("computer", "Computer", "Apple Device"),
    "C0:CE:CD": ("computer", "Computer", "Apple Device"),
    "C0:D0:12": ("computer", "Computer", "Apple Device"),
    "C0:E8:62": ("computer", "Computer", "Apple Device"),
    "C4:2C:03": ("computer", "Computer", "Apple Device"),
    "C4:B3:01": ("computer", "Computer", "Apple Device"),
    "C8:1E:E7": ("computer", "Computer", "Apple Device"),
    "C8:2A:14": ("computer", "Computer", "Apple Device"),
    "C8:33:4B": ("computer", "Computer", "Apple Device"),
    "C8:3C:85": ("computer", "Computer", "Apple Device"),
    "C8:69:CD": ("computer", "Computer", "Apple Device"),
    "C8:85:50": ("computer", "Computer", "Apple Device"),
    "C8:D0:83": ("computer", "Computer", "Apple Device"),
    "C8:E0:EB": ("computer", "Computer", "Apple Device"),
    "CC:08:8D": ("computer", "Computer", "Apple Device"),
    "CC:20:E8": ("computer", "Computer", "Apple Device"),
    "CC:25:EF": ("computer", "Computer", "Apple Device"),
    "CC:44:63": ("computer", "Computer", "Apple Device"),
    "CC:78:5F": ("computer", "Computer", "Apple Device"),
    "D0:03:4B": ("computer", "Computer", "Apple Device"),
    "D0:25:98": ("computer", "Computer", "Apple Device"),
    "D0:33:11": ("computer", "Computer", "Apple Device"),
    "D0:4F:7E": ("computer", "Computer", "Apple Device"),
    "D0:81:7A": ("computer", "Computer", "Apple Device"),
    "D0:A6:37": ("computer", "Computer", "Apple Device"),
    "D0:C5:F3": ("computer", "Computer", "Apple Device"),
    "D0:D2:B0": ("computer", "Computer", "Apple Device"),
    "D4:9A:20": ("computer", "Computer", "Apple Device"),
    "D4:F4:6F": ("computer", "Computer", "Apple Device"),
    "D8:00:4D": ("computer", "Computer", "Apple Device"),
    "D8:1D:72": ("computer", "Computer", "Apple Device"),
    "D8:30:62": ("computer", "Computer", "Apple Device"),
    "D8:8F:76": ("computer", "Computer", "Apple Device"),
    "D8:9E:3F": ("computer", "Computer", "Apple Device"),
    "D8:A2:5E": ("computer", "Computer", "Apple Device"),
    "D8:BB:2C": ("computer", "Computer", "Apple Device"),
    "D8:D1:CB": ("computer", "Computer", "Apple Device"),
    "DC:0C:5C": ("computer", "Computer", "Apple Device"),
    "DC:2B:2A": ("computer", "Computer", "Apple Device"),
    "DC:37:14": ("computer", "Computer", "Apple Device"),
    "DC:41:5F": ("computer", "Computer", "Apple Device"),
    "DC:56:E7": ("computer", "Computer", "Apple Device"),
    "DC:86:D8": ("computer", "Computer", "Apple Device"),
    "DC:9B:9C": ("computer", "Computer", "Apple Device"),
    "DC:A4:CA": ("computer", "Computer", "Apple Device"),
    "DC:A9:04": ("computer", "Computer", "Apple Device"),
    "E0:33:8E": ("computer", "Computer", "Apple Device"),
    "E0:5F:45": ("computer", "Computer", "Apple Device"),
    "E0:66:78": ("computer", "Computer", "Apple Device"),
    "E0:AC:CB": ("computer", "Computer", "Apple Device"),
    "E0:B9:BA": ("computer", "Computer", "Apple Device"),
    "E0:C7:67": ("computer", "Computer", "Apple Device"),
    "E0:C9:7A": ("computer", "Computer", "Apple Device"),
    "E0:F5:C6": ("computer", "Computer", "Apple Device"),
    "E4:8B:7F": ("computer", "Computer", "Apple Device"),
    "E4:9A:DC": ("computer", "Computer", "Apple Device"),
    "E4:CE:8F": ("computer", "Computer", "Apple Device"),
    "E4:E4:AB": ("computer", "Computer", "Apple Device"),
    "E8:04:0B": ("computer", "Computer", "Apple Device"),
    "E8:06:88": ("computer", "Computer", "Apple Device"),
    "E8:36:17": ("computer", "Computer", "Apple Device"),
    "E8:80:2E": ("computer", "Computer", "Apple Device"),
    "E8:8D:28": ("computer", "Computer", "Apple Device"),
    "E8:B2:AC": ("computer", "Computer", "Apple Device"),
    "EC:35:86": ("computer", "Computer", "Apple Device"),
    "EC:85:2F": ("computer", "Computer", "Apple Device"),
    "EC:AD:B8": ("computer", "Computer", "Apple Device"),
    "F0:18:98": ("computer", "Computer", "Apple Device"),
    "F0:24:75": ("computer", "Computer", "Apple Device"),
    # REMOVED: F0:72:EA - IEEE assigns to Google Inc., not Apple
    "F0:B0:E7": ("computer", "Computer", "Apple Device"),
    "F0:C1:F1": ("computer", "Computer", "Apple Device"),
    "F0:CB:A1": ("computer", "Computer", "Apple Device"),
    "F0:D1:A9": ("computer", "Computer", "Apple Device"),
    "F0:DB:E2": ("computer", "Computer", "Apple Device"),
    "F0:DC:E2": ("computer", "Computer", "Apple Device"),
    "F4:1B:A1": ("computer", "Computer", "Apple Device"),
    "F4:31:C3": ("computer", "Computer", "Apple Device"),
    "F4:37:B7": ("computer", "Computer", "Apple Device"),
    "F4:5C:89": ("computer", "Computer", "Apple Device"),
    "F4:F1:5A": ("computer", "Computer", "Apple Device"),
    "F8:1E:DF": ("computer", "Computer", "Apple Device"),
    "F8:38:80": ("computer", "Computer", "Apple Device"),
    "F8:4D:89": ("computer", "Computer", "Apple Device"),
    "F8:62:14": ("computer", "Computer", "Apple Device"),
    "FC:25:3F": ("computer", "Computer", "Apple Device"),
    "FC:D8:48": ("computer", "Computer", "Apple Device"),
    "FC:FC:48": ("computer", "Computer", "Apple Device"),
}

APPLE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # MacBook Pro models (M-series)
    (r"MacBook\s*Pro\s*16.*M4\s*Max", "MacBook Pro 16\" M4 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M4\s*Pro", "MacBook Pro 16\" M4 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M4", "MacBook Pro 16\" M4", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M3\s*Max", "MacBook Pro 16\" M3 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M3\s*Pro", "MacBook Pro 16\" M3 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M3", "MacBook Pro 16\" M3", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M2\s*Max", "MacBook Pro 16\" M2 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M2\s*Pro", "MacBook Pro 16\" M2 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M1\s*Max", "MacBook Pro 16\" M1 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16.*M1\s*Pro", "MacBook Pro 16\" M1 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*16", "MacBook Pro 16\"", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M4\s*Max", "MacBook Pro 14\" M4 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M4\s*Pro", "MacBook Pro 14\" M4 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M4", "MacBook Pro 14\" M4", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M3\s*Max", "MacBook Pro 14\" M3 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M3\s*Pro", "MacBook Pro 14\" M3 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M3", "MacBook Pro 14\" M3", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M2\s*Max", "MacBook Pro 14\" M2 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M2\s*Pro", "MacBook Pro 14\" M2 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M1\s*Max", "MacBook Pro 14\" M1 Max", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14.*M1\s*Pro", "MacBook Pro 14\" M1 Pro", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*14", "MacBook Pro 14\"", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*13.*M2", "MacBook Pro 13\" M2", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*13.*M1", "MacBook Pro 13\" M1", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*13", "MacBook Pro 13\"", "laptop", "macOS"),
    (r"MacBook\s*Pro\s*15", "MacBook Pro 15\"", "laptop", "macOS"),
    (r"MacBook\s*Pro", "MacBook Pro", "laptop", "macOS"),

    # MacBook Air models (M-series)
    (r"MacBook\s*Air\s*15.*M4", "MacBook Air 15\" M4", "laptop", "macOS"),
    (r"MacBook\s*Air\s*15.*M3", "MacBook Air 15\" M3", "laptop", "macOS"),
    (r"MacBook\s*Air\s*15.*M2", "MacBook Air 15\" M2", "laptop", "macOS"),
    (r"MacBook\s*Air\s*15", "MacBook Air 15\"", "laptop", "macOS"),
    (r"MacBook\s*Air\s*13.*M4", "MacBook Air 13\" M4", "laptop", "macOS"),
    (r"MacBook\s*Air\s*13.*M3", "MacBook Air 13\" M3", "laptop", "macOS"),
    (r"MacBook\s*Air\s*13.*M2", "MacBook Air 13\" M2", "laptop", "macOS"),
    (r"MacBook\s*Air\s*13.*M1", "MacBook Air 13\" M1", "laptop", "macOS"),
    (r"MacBook\s*Air\s*M4", "MacBook Air M4", "laptop", "macOS"),
    (r"MacBook\s*Air\s*M3", "MacBook Air M3", "laptop", "macOS"),
    (r"MacBook\s*Air\s*M2", "MacBook Air M2", "laptop", "macOS"),
    (r"MacBook\s*Air\s*M1", "MacBook Air M1", "laptop", "macOS"),
    (r"MacBook\s*Air", "MacBook Air", "laptop", "macOS"),
    (r"MacBook\s*12", "MacBook 12\"", "laptop", "macOS"),
    (r"MacBook", "MacBook", "laptop", "macOS"),

    # Mac Studio
    (r"Mac\s*Studio.*M4\s*Ultra", "Mac Studio M4 Ultra", "desktop", "macOS"),
    (r"Mac\s*Studio.*M4\s*Max", "Mac Studio M4 Max", "desktop", "macOS"),
    (r"Mac\s*Studio.*M2\s*Ultra", "Mac Studio M2 Ultra", "desktop", "macOS"),
    (r"Mac\s*Studio.*M2\s*Max", "Mac Studio M2 Max", "desktop", "macOS"),
    (r"Mac\s*Studio.*M1\s*Ultra", "Mac Studio M1 Ultra", "desktop", "macOS"),
    (r"Mac\s*Studio.*M1\s*Max", "Mac Studio M1 Max", "desktop", "macOS"),
    (r"Mac\s*Studio", "Mac Studio", "desktop", "macOS"),

    # Mac Pro
    (r"Mac\s*Pro.*M2\s*Ultra", "Mac Pro M2 Ultra", "desktop", "macOS"),
    (r"Mac\s*Pro\s*\(?2019", "Mac Pro (2019)", "desktop", "macOS"),
    (r"Mac\s*Pro\s*\(?2013", "Mac Pro (2013)", "desktop", "macOS"),
    (r"Mac\s*Pro", "Mac Pro", "desktop", "macOS"),

    # Mac mini
    (r"Mac\s*mini.*M4\s*Pro", "Mac mini M4 Pro", "desktop", "macOS"),
    (r"Mac\s*mini.*M4", "Mac mini M4", "desktop", "macOS"),
    (r"Mac\s*mini.*M2\s*Pro", "Mac mini M2 Pro", "desktop", "macOS"),
    (r"Mac\s*mini.*M2", "Mac mini M2", "desktop", "macOS"),
    (r"Mac\s*mini.*M1", "Mac mini M1", "desktop", "macOS"),
    (r"Mac\s*mini", "Mac mini", "desktop", "macOS"),

    # iMac
    (r"iMac.*M4", "iMac M4", "desktop", "macOS"),
    (r"iMac.*M3", "iMac M3", "desktop", "macOS"),
    (r"iMac.*M1", "iMac M1", "desktop", "macOS"),
    (r"iMac\s*Pro", "iMac Pro", "desktop", "macOS"),
    (r"iMac\s*27", "iMac 27\"", "desktop", "macOS"),
    (r"iMac\s*24", "iMac 24\"", "desktop", "macOS"),
    (r"iMac\s*21\.5", "iMac 21.5\"", "desktop", "macOS"),
    (r"iMac", "iMac", "desktop", "macOS"),

    # iPhone 16 series (2024)
    (r"iPhone\s*16\s*Pro\s*Max", "iPhone 16 Pro Max", "phone", "iOS"),
    (r"iPhone\s*16\s*Pro", "iPhone 16 Pro", "phone", "iOS"),
    (r"iPhone\s*16\s*Plus", "iPhone 16 Plus", "phone", "iOS"),
    (r"iPhone\s*16", "iPhone 16", "phone", "iOS"),

    # iPhone 15 series (2023)
    (r"iPhone\s*15\s*Pro\s*Max", "iPhone 15 Pro Max", "phone", "iOS"),
    (r"iPhone\s*15\s*Pro", "iPhone 15 Pro", "phone", "iOS"),
    (r"iPhone\s*15\s*Plus", "iPhone 15 Plus", "phone", "iOS"),
    (r"iPhone\s*15", "iPhone 15", "phone", "iOS"),

    # iPhone 14 series (2022)
    (r"iPhone\s*14\s*Pro\s*Max", "iPhone 14 Pro Max", "phone", "iOS"),
    (r"iPhone\s*14\s*Pro", "iPhone 14 Pro", "phone", "iOS"),
    (r"iPhone\s*14\s*Plus", "iPhone 14 Plus", "phone", "iOS"),
    (r"iPhone\s*14", "iPhone 14", "phone", "iOS"),

    # iPhone 13 series (2021)
    (r"iPhone\s*13\s*Pro\s*Max", "iPhone 13 Pro Max", "phone", "iOS"),
    (r"iPhone\s*13\s*Pro", "iPhone 13 Pro", "phone", "iOS"),
    (r"iPhone\s*13\s*mini", "iPhone 13 mini", "phone", "iOS"),
    (r"iPhone\s*13", "iPhone 13", "phone", "iOS"),

    # iPhone 12 series (2020)
    (r"iPhone\s*12\s*Pro\s*Max", "iPhone 12 Pro Max", "phone", "iOS"),
    (r"iPhone\s*12\s*Pro", "iPhone 12 Pro", "phone", "iOS"),
    (r"iPhone\s*12\s*mini", "iPhone 12 mini", "phone", "iOS"),
    (r"iPhone\s*12", "iPhone 12", "phone", "iOS"),

    # iPhone 11 series (2019)
    (r"iPhone\s*11\s*Pro\s*Max", "iPhone 11 Pro Max", "phone", "iOS"),
    (r"iPhone\s*11\s*Pro", "iPhone 11 Pro", "phone", "iOS"),
    (r"iPhone\s*11", "iPhone 11", "phone", "iOS"),

    # iPhone X series (2017-2018)
    (r"iPhone\s*XS\s*Max", "iPhone XS Max", "phone", "iOS"),
    (r"iPhone\s*XS", "iPhone XS", "phone", "iOS"),
    (r"iPhone\s*XR", "iPhone XR", "phone", "iOS"),
    (r"iPhone\s*X(?![SR])", "iPhone X", "phone", "iOS"),

    # iPhone 8/7/6 series
    (r"iPhone\s*8\s*Plus", "iPhone 8 Plus", "phone", "iOS"),
    (r"iPhone\s*8", "iPhone 8", "phone", "iOS"),
    (r"iPhone\s*7\s*Plus", "iPhone 7 Plus", "phone", "iOS"),
    (r"iPhone\s*7", "iPhone 7", "phone", "iOS"),
    (r"iPhone\s*6[Ss]\s*Plus", "iPhone 6s Plus", "phone", "iOS"),
    (r"iPhone\s*6[Ss]", "iPhone 6s", "phone", "iOS"),
    (r"iPhone\s*6\s*Plus", "iPhone 6 Plus", "phone", "iOS"),
    (r"iPhone\s*6", "iPhone 6", "phone", "iOS"),

    # iPhone SE series
    (r"iPhone\s*SE\s*\(?3rd", "iPhone SE (3rd gen)", "phone", "iOS"),
    (r"iPhone\s*SE\s*\(?2nd", "iPhone SE (2nd gen)", "phone", "iOS"),
    (r"iPhone\s*SE\s*\(?1st", "iPhone SE (1st gen)", "phone", "iOS"),
    (r"iPhone\s*SE", "iPhone SE", "phone", "iOS"),

    # Legacy iPhones
    (r"iPhone\s*5[Ss]", "iPhone 5s", "phone", "iOS"),
    (r"iPhone\s*5[Cc]", "iPhone 5c", "phone", "iOS"),
    (r"iPhone\s*5", "iPhone 5", "phone", "iOS"),
    (r"iPhone\s*4[Ss]", "iPhone 4S", "phone", "iOS"),
    (r"iPhone\s*4", "iPhone 4", "phone", "iOS"),
    (r"iPhone\s*3G[Ss]", "iPhone 3GS", "phone", "iOS"),
    (r"iPhone\s*3G", "iPhone 3G", "phone", "iOS"),

    # Generic iPhone catch-all
    (r"iPhone", "iPhone", "phone", "iOS"),

    # iPad Pro models
    (r"iPad\s*Pro\s*13", "iPad Pro 13\"", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*12\.9\s*\(?6th", "iPad Pro 12.9\" (6th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*12\.9\s*\(?5th", "iPad Pro 12.9\" (5th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*12\.9\s*\(?4th", "iPad Pro 12.9\" (4th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*12\.9\s*\(?3rd", "iPad Pro 12.9\" (3rd gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*12\.9", "iPad Pro 12.9\"", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*11\s*\(?4th", "iPad Pro 11\" (4th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*11\s*\(?3rd", "iPad Pro 11\" (3rd gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*11\s*\(?2nd", "iPad Pro 11\" (2nd gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*11\s*\(?1st", "iPad Pro 11\" (1st gen)", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*11", "iPad Pro 11\"", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*10\.5", "iPad Pro 10.5\"", "tablet", "iPadOS"),
    (r"iPad\s*Pro\s*9\.7", "iPad Pro 9.7\"", "tablet", "iPadOS"),
    (r"iPad\s*Pro", "iPad Pro", "tablet", "iPadOS"),

    # iPad Air models
    (r"iPad\s*Air\s*\(?6th", "iPad Air (6th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Air\s*\(?5th", "iPad Air (5th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Air\s*\(?4th", "iPad Air (4th gen)", "tablet", "iPadOS"),
    (r"iPad\s*Air\s*\(?3rd", "iPad Air (3rd gen)", "tablet", "iPadOS"),
    (r"iPad\s*Air\s*2", "iPad Air 2", "tablet", "iPadOS"),
    (r"iPad\s*Air", "iPad Air", "tablet", "iPadOS"),

    # iPad mini models
    (r"iPad\s*mini\s*\(?7th", "iPad mini (7th gen)", "tablet", "iPadOS"),
    (r"iPad\s*mini\s*\(?6th", "iPad mini (6th gen)", "tablet", "iPadOS"),
    (r"iPad\s*mini\s*\(?5th", "iPad mini (5th gen)", "tablet", "iPadOS"),
    (r"iPad\s*mini\s*4", "iPad mini 4", "tablet", "iPadOS"),
    (r"iPad\s*mini\s*3", "iPad mini 3", "tablet", "iPadOS"),
    (r"iPad\s*mini\s*2", "iPad mini 2", "tablet", "iPadOS"),
    (r"iPad\s*mini", "iPad mini", "tablet", "iPadOS"),

    # Standard iPad models
    (r"iPad\s*\(?10th", "iPad (10th gen)", "tablet", "iPadOS"),
    (r"iPad\s*\(?9th", "iPad (9th gen)", "tablet", "iPadOS"),
    (r"iPad\s*\(?8th", "iPad (8th gen)", "tablet", "iPadOS"),
    (r"iPad\s*\(?7th", "iPad (7th gen)", "tablet", "iPadOS"),
    (r"iPad\s*\(?6th", "iPad (6th gen)", "tablet", "iPadOS"),
    (r"iPad", "iPad", "tablet", "iPadOS"),

    # Apple TV models
    (r"Apple\s*TV\s*4K\s*\(?3rd", "Apple TV 4K (3rd gen)", "media_player", "tvOS"),
    (r"Apple\s*TV\s*4K\s*\(?2nd", "Apple TV 4K (2nd gen)", "media_player", "tvOS"),
    (r"Apple\s*TV\s*4K\s*\(?1st", "Apple TV 4K (1st gen)", "media_player", "tvOS"),
    (r"Apple\s*TV\s*4K", "Apple TV 4K", "media_player", "tvOS"),
    (r"Apple\s*TV\s*HD", "Apple TV HD", "media_player", "tvOS"),
    (r"Apple\s*TV\s*\(?4th", "Apple TV (4th gen)", "media_player", "tvOS"),
    (r"Apple\s*TV\s*\(?3rd", "Apple TV (3rd gen)", "media_player", "tvOS"),
    (r"Apple\s*TV", "Apple TV", "media_player", "tvOS"),

    # HomePod models
    (r"HomePod\s*\(?2nd", "HomePod (2nd gen)", "smart_speaker", "audioOS"),
    (r"HomePod\s*mini", "HomePod mini", "smart_speaker", "audioOS"),
    (r"HomePod", "HomePod", "smart_speaker", "audioOS"),

    # Apple Watch models
    (r"Apple\s*Watch\s*Ultra\s*2", "Apple Watch Ultra 2", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Ultra", "Apple Watch Ultra", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*10", "Apple Watch Series 10", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*9", "Apple Watch Series 9", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*8", "Apple Watch Series 8", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*7", "Apple Watch Series 7", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*6", "Apple Watch Series 6", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*SE\s*\(?2nd", "Apple Watch SE (2nd gen)", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*SE", "Apple Watch SE", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*5", "Apple Watch Series 5", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*4", "Apple Watch Series 4", "wearable", "watchOS"),
    (r"Apple\s*Watch\s*Series\s*3", "Apple Watch Series 3", "wearable", "watchOS"),
    (r"Apple\s*Watch", "Apple Watch", "wearable", "watchOS"),

    # AirPods models
    (r"AirPods\s*Pro\s*2", "AirPods Pro (2nd gen)", "wireless_earbuds", "AirPods Firmware"),
    (r"AirPods\s*Pro", "AirPods Pro", "wireless_earbuds", "AirPods Firmware"),
    (r"AirPods\s*Max", "AirPods Max", "wireless_headphones", "AirPods Firmware"),
    (r"AirPods\s*\(?4th", "AirPods (4th gen)", "wireless_earbuds", "AirPods Firmware"),
    (r"AirPods\s*\(?3rd", "AirPods (3rd gen)", "wireless_earbuds", "AirPods Firmware"),
    (r"AirPods\s*\(?2nd", "AirPods (2nd gen)", "wireless_earbuds", "AirPods Firmware"),
    (r"AirPods", "AirPods", "wireless_earbuds", "AirPods Firmware"),

    # AirPort / Time Capsule
    (r"AirPort\s*Extreme", "AirPort Extreme", "router", "AirPort OS"),
    (r"AirPort\s*Express", "AirPort Express", "router", "AirPort OS"),
    (r"AirPort\s*Time\s*Capsule", "Time Capsule", "nas", "AirPort OS"),
    (r"Time\s*Capsule", "Time Capsule", "nas", "AirPort OS"),

    # Apple Vision Pro
    (r"Apple\s*Vision\s*Pro", "Apple Vision Pro", "ar_headset", "visionOS"),
    (r"Vision\s*Pro", "Apple Vision Pro", "ar_headset", "visionOS"),

    # macOS versions in banners
    (r"macOS\s*Sonoma", "Mac (macOS Sonoma)", "computer", "macOS 14"),
    (r"macOS\s*Ventura", "Mac (macOS Ventura)", "computer", "macOS 13"),
    (r"macOS\s*Monterey", "Mac (macOS Monterey)", "computer", "macOS 12"),
    (r"macOS\s*Big\s*Sur", "Mac (macOS Big Sur)", "computer", "macOS 11"),
    (r"macOS\s*Catalina", "Mac (macOS Catalina)", "computer", "macOS 10.15"),
    (r"Mac\s*OS\s*X", "Mac", "computer", "macOS"),
    (r"Darwin", "Apple Device", "computer", "macOS"),
]


# SAMSUNG / LG SMART DEVICE PATTERNS

SAMSUNG_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Samsung has many OUIs - common ones for TVs and IoT
    "00:07:AB": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:12:47": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:12:FB": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:15:B9": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:16:32": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:17:C9": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:18:AF": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1A:8A": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1B:98": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1C:43": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1D:25": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1D:F6": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1E:7D": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:1F:CC": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:21:4C": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:21:D1": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:23:39": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:23:99": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:23:D6": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:24:54": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:24:90": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:24:E9": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:25:66": ("tv", "Entertainment", "Samsung Smart TV"),
    "00:26:37": ("tv", "Entertainment", "Samsung Smart TV"),
    "08:D4:2B": ("phone", "Mobile", "Samsung Galaxy"),
    "14:49:E0": ("phone", "Mobile", "Samsung Galaxy"),
    "18:3F:47": ("phone", "Mobile", "Samsung Galaxy"),
    "20:6E:9C": ("phone", "Mobile", "Samsung Galaxy"),
    "24:18:1D": ("phone", "Mobile", "Samsung Galaxy"),
    "28:98:7B": ("phone", "Mobile", "Samsung Galaxy"),
    "2C:AE:2B": ("phone", "Mobile", "Samsung Galaxy"),
    "30:96:FB": ("phone", "Mobile", "Samsung Galaxy"),
    "34:14:5F": ("phone", "Mobile", "Samsung Galaxy"),
    "3C:5A:37": ("phone", "Mobile", "Samsung Galaxy"),
    "40:0E:85": ("phone", "Mobile", "Samsung Galaxy"),
    "44:F4:59": ("phone", "Mobile", "Samsung Galaxy"),
    "48:13:7E": ("phone", "Mobile", "Samsung Galaxy"),
    "54:88:0E": ("phone", "Mobile", "Samsung Galaxy"),
    "5C:2E:59": ("phone", "Mobile", "Samsung Galaxy"),
    "60:D0:A9": ("phone", "Mobile", "Samsung Galaxy"),
    "64:B8:53": ("phone", "Mobile", "Samsung Galaxy"),
    "68:27:37": ("phone", "Mobile", "Samsung Galaxy"),
    "6C:2F:2C": ("phone", "Mobile", "Samsung Galaxy"),
    "70:F9:27": ("phone", "Mobile", "Samsung Galaxy"),
    "78:52:1A": ("phone", "Mobile", "Samsung Galaxy"),
    "78:D6:F0": ("phone", "Mobile", "Samsung Galaxy"),
    "7C:0A:3F": ("phone", "Mobile", "Samsung Galaxy"),
    "80:65:6D": ("phone", "Mobile", "Samsung Galaxy"),
    "84:11:9E": ("phone", "Mobile", "Samsung Galaxy"),
    "88:32:9B": ("phone", "Mobile", "Samsung Galaxy"),
    "8C:77:12": ("phone", "Mobile", "Samsung Galaxy"),
    "90:18:7C": ("phone", "Mobile", "Samsung Galaxy"),
    "94:35:0A": ("phone", "Mobile", "Samsung Galaxy"),
    "98:52:B1": ("phone", "Mobile", "Samsung Galaxy"),
    "A0:0B:BA": ("phone", "Mobile", "Samsung Galaxy"),
    "A4:84:31": ("phone", "Mobile", "Samsung Galaxy"),
    "A8:7C:01": ("phone", "Mobile", "Samsung Galaxy"),
    "AC:5F:3E": ("phone", "Mobile", "Samsung Galaxy"),
    "B4:3A:28": ("phone", "Mobile", "Samsung Galaxy"),
    "BC:44:86": ("phone", "Mobile", "Samsung Galaxy"),
    # SmartThings Hub
    # Samsung appliances
    "64:1C:AE": ("appliance", "Smart Home", "Samsung Appliance"),
}

SAMSUNG_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Smart TVs - SmartViewSDK is Samsung's screen casting for TVs
    (r"SmartViewSDK", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"SmartView", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"Samsung\s*SMART\s*TV", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"Samsung\s*TV", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"Tizen\s*\d+\.\d+", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"Tizen", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"\[TV\]", "Samsung Smart TV", "smart_tv", "Tizen"),
    (r"UE\d{2}[A-Z]{2}\d+", "Samsung Smart TV", "smart_tv", "Tizen"),  # EU Model numbers
    (r"UN\d{2}[A-Z]{2}\d+", "Samsung Smart TV", "smart_tv", "Tizen"),  # US Model numbers
    (r"QN\d{2}[A-Z]{2}\d+", "Samsung QLED TV", "smart_tv", "Tizen"),   # QLED US
    (r"QE\d{2}[A-Z]{2}\d+", "Samsung QLED TV", "smart_tv", "Tizen"),   # QLED EU
    (r"GQ\d{2}[A-Z]{2}\d+", "Samsung QLED TV", "smart_tv", "Tizen"),   # QLED DE
    (r"UA\d{2}[A-Z]{2}\d+", "Samsung Smart TV", "smart_tv", "Tizen"),  # Asia Model
    (r"UHD\s*TV", "Samsung UHD TV", "smart_tv", "Tizen"),
    (r"QLED", "Samsung QLED TV", "smart_tv", "Tizen"),
    (r"Neo\s*QLED", "Samsung Neo QLED TV", "smart_tv", "Tizen"),
    (r"The\s*Frame", "Samsung The Frame TV", "smart_tv", "Tizen"),
    (r"The\s*Serif", "Samsung The Serif TV", "smart_tv", "Tizen"),
    (r"The\s*Sero", "Samsung The Sero TV", "smart_tv", "Tizen"),

    # Samsung Monitors (some have smart features)
    (r"Samsung\s*Monitor", "Samsung Monitor", "display", None),
    (r"Smart\s*Monitor", "Samsung Smart Monitor", "smart_display", "Tizen"),
    (r"Odyssey", "Samsung Odyssey Monitor", "display", None),
    (r"ViewFinity", "Samsung ViewFinity Monitor", "display", None),

    # Galaxy phones
    (r"Galaxy\s*S2[34]", "Samsung Galaxy S24/S23", "smartphone", "Android"),
    (r"Galaxy\s*S2[12]", "Samsung Galaxy S22/S21", "smartphone", "Android"),
    (r"Galaxy\s*S\d{1,2}", "Samsung Galaxy S Series", "smartphone", "Android"),
    (r"Galaxy\s*Z\s*Fold", "Samsung Galaxy Z Fold", "smartphone", "Android"),
    (r"Galaxy\s*Z\s*Flip", "Samsung Galaxy Z Flip", "smartphone", "Android"),
    (r"Galaxy\s*A\d{2}", "Samsung Galaxy A Series", "smartphone", "Android"),
    (r"Galaxy\s*M\d{2}", "Samsung Galaxy M Series", "smartphone", "Android"),
    (r"Galaxy\s*Note", "Samsung Galaxy Note", "smartphone", "Android"),
    (r"Galaxy\s*Tab\s*S\d", "Samsung Galaxy Tab S", "tablet", "Android"),
    (r"Galaxy\s*Tab\s*A\d", "Samsung Galaxy Tab A", "tablet", "Android"),
    (r"Galaxy\s*Tab", "Samsung Galaxy Tab", "tablet", "Android"),
    (r"SM-[GANT]\d{3}", "Samsung Galaxy", "smartphone", "Android"),  # Phone model numbers
    (r"SM-P\d{3}", "Samsung Galaxy Tab", "tablet", "Android"),
    (r"SM-X\d{3}", "Samsung Galaxy Tab", "tablet", "Android"),

    # Galaxy Watch / Wearables
    (r"Galaxy\s*Watch\s*\d*", "Samsung Galaxy Watch", "smartwatch", "Tizen"),
    (r"Galaxy\s*Fit", "Samsung Galaxy Fit", "fitness_tracker", None),
    (r"Galaxy\s*Buds", "Samsung Galaxy Buds", "earbuds", None),
    (r"SM-R\d{3}", "Samsung Galaxy Watch", "smartwatch", "Tizen"),

    # SmartThings
    (r"SmartThings\s*Hub", "Samsung SmartThings Hub", "iot_hub", "SmartThings"),
    (r"SmartThings\s*Station", "Samsung SmartThings Station", "iot_hub", "SmartThings"),
    (r"SmartThings", "Samsung SmartThings", "iot_hub", "SmartThings"),

    # Appliances
    (r"Samsung\s*Refrigerator", "Samsung Smart Refrigerator", "smart_appliance", "SmartThings"),
    (r"Samsung\s*Washer", "Samsung Smart Washer", "smart_appliance", "SmartThings"),
    (r"Samsung\s*Dryer", "Samsung Smart Dryer", "smart_appliance", "SmartThings"),
    (r"Family\s*Hub", "Samsung Family Hub", "smart_appliance", "SmartThings"),
    (r"Bespoke", "Samsung Bespoke Appliance", "smart_appliance", "SmartThings"),

    # Soundbars
    (r"Samsung\s*Soundbar", "Samsung Soundbar", "soundbar", None),
    (r"HW-[A-Z]\d{3}", "Samsung Soundbar", "soundbar", None),

    # NOTE: No generic Samsung fallback - let OUI handle it
    # Previously defaulted to "phone" which caused misidentification
]

LG_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:1C:62": ("tv", "Entertainment", "LG Smart TV"),
    "00:1E:75": ("tv", "Entertainment", "LG Smart TV"),
    "00:1F:6B": ("tv", "Entertainment", "LG Smart TV"),
    "00:22:A9": ("tv", "Entertainment", "LG Smart TV"),
    "00:24:83": ("tv", "Entertainment", "LG Smart TV"),
    "00:25:E5": ("tv", "Entertainment", "LG Smart TV"),
    "00:26:E2": ("tv", "Entertainment", "LG Smart TV"),
    "00:34:DA": ("tv", "Entertainment", "LG Smart TV"),
    "00:AA:70": ("tv", "Entertainment", "LG Smart TV"),
    "00:E0:91": ("tv", "Entertainment", "LG Smart TV"),
    "10:68:3F": ("tv", "Entertainment", "LG Smart TV"),
    "14:C9:13": ("tv", "Entertainment", "LG Smart TV"),
    "20:21:A5": ("tv", "Entertainment", "LG Smart TV"),
    "2C:54:CF": ("tv", "Entertainment", "LG Smart TV"),
    "34:4D:F7": ("tv", "Entertainment", "LG Smart TV"),
    "38:8C:50": ("tv", "Entertainment", "LG Smart TV"),
    "3C:BD:D8": ("tv", "Entertainment", "LG Smart TV"),
    "40:B0:FA": ("tv", "Entertainment", "LG Smart TV"),
    "48:59:29": ("tv", "Entertainment", "LG Smart TV"),
    "50:55:27": ("tv", "Entertainment", "LG Smart TV"),
    "58:A2:B5": ("tv", "Entertainment", "LG Smart TV"),
    "5C:70:A3": ("tv", "Entertainment", "LG Smart TV"),
    "64:99:5D": ("tv", "Entertainment", "LG Smart TV"),
    # REMOVED: 6C:B7:49 - IEEE assigns to Huawei Technologies, not LG
    "78:5D:C8": ("tv", "Entertainment", "LG Smart TV"),
    "7C:1C:4E": ("tv", "Entertainment", "LG Smart TV"),
    # REMOVED: 80:CE:62 - IEEE assigns to Hewlett Packard, not LG
    "88:C9:D0": ("tv", "Entertainment", "LG Smart TV"),
    "94:C9:B2": ("tv", "Entertainment", "LG Smart TV"),
    "98:93:CC": ("tv", "Entertainment", "LG Smart TV"),
    "A8:16:B2": ("tv", "Entertainment", "LG Smart TV"),
    "AC:0D:1B": ("tv", "Entertainment", "LG Smart TV"),
    "B4:E6:2A": ("tv", "Entertainment", "LG Smart TV"),
    "BC:F5:AC": ("tv", "Entertainment", "LG Smart TV"),
    "C4:36:6C": ("tv", "Entertainment", "LG Smart TV"),
    # REMOVED: C8:02:8F - IEEE assigns to Unknown, not LG
    "CC:2D:8C": ("tv", "Entertainment", "LG Smart TV"),
    "D0:13:FD": ("tv", "Entertainment", "LG Smart TV"),
    "DC:0B:34": ("tv", "Entertainment", "LG Smart TV"),
    "E8:5B:5B": ("tv", "Entertainment", "LG Smart TV"),
    "F0:1C:13": ("tv", "Entertainment", "LG Smart TV"),
    "F8:0C:F3": ("tv", "Entertainment", "LG Smart TV"),
}

LG_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Smart TVs
    (r"LG\s*Smart\s*TV", "LG Smart TV", "tv", "webOS"),
    (r"LG\s*webOS\s*TV", "LG webOS TV", "tv", "webOS"),
    (r"webOS\s*\d+\.\d+", "LG webOS TV", "tv", "webOS"),
    (r"OLED\d{2}[A-Z]\d", "LG OLED TV", "tv", "webOS"),
    (r"NANO\d{2}[A-Z]\d", "LG NanoCell TV", "tv", "webOS"),
    (r"QNED\d{2}[A-Z]\d", "LG QNED TV", "tv", "webOS"),
    (r"\d{2}UQ\d+", "LG UHD TV", "tv", "webOS"),
    (r"\d{2}UP\d+", "LG UHD TV", "tv", "webOS"),

    # Soundbars
    (r"LG\s*Sound\s*Bar", "LG Soundbar", "soundbar", "webOS"),
    (r"SN\d{2}", "LG Soundbar", "soundbar", "webOS"),
    (r"SP\d{2}", "LG Soundbar", "soundbar", "webOS"),
    (r"SC\d{2}", "LG Soundbar", "soundbar", "webOS"),

    # Appliances
    (r"LG\s*ThinQ", "LG ThinQ Appliance", "appliance", "ThinQ"),
    (r"ThinQ", "LG ThinQ Device", "appliance", "ThinQ"),

    # Generic
    (r"LG\s*Electronics", "LG Device", "tv", "webOS"),
]


# HONEYWELL / SCHNEIDER INDUSTRIAL PATTERNS

HONEYWELL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:40:84": ("plc", "Industrial", "Honeywell Controller"),
    "00:D0:2D": ("building_controller", "HVAC", "Honeywell BMS"),
    # REMOVED: 18:B4:30 - IEEE assigns to Nest Labs Inc. (Google), not Honeywell
    "48:A2:E6": ("thermostat", "HVAC", "Honeywell Thermostat"),
}

HONEYWELL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Thermostats
    (r"T6\s*Pro", "Honeywell T6 Pro", "thermostat", "Honeywell Home"),
    (r"T10\s*Pro", "Honeywell T10 Pro", "thermostat", "Honeywell Home"),
    (r"Lyric\s*T6", "Honeywell Lyric T6", "thermostat", "Honeywell Home"),
    (r"Lyric\s*T5", "Honeywell Lyric T5", "thermostat", "Honeywell Home"),
    (r"Prestige", "Honeywell Prestige", "thermostat", "Honeywell Home"),
    (r"VisionPRO", "Honeywell VisionPRO", "thermostat", "Honeywell Home"),
    (r"RTH\d+", "Honeywell Thermostat", "thermostat", "Honeywell Home"),
    (r"TH\d+", "Honeywell Thermostat", "thermostat", "Honeywell Home"),

    # Building Management
    (r"WEBs-AX", "Honeywell WEBs-AX", "building_controller", "Niagara"),
    (r"Niagara\s*\d", "Honeywell Niagara", "building_controller", "Niagara"),
    (r"Tridium", "Honeywell Tridium", "building_controller", "Niagara"),
    (r"JACE\s*\d+", "Honeywell JACE", "building_controller", "Niagara"),
    (r"Spyder", "Honeywell Spyder", "building_controller", "Spyder"),

    # Industrial Controllers
    (r"Experion\s*PKS", "Honeywell Experion PKS", "dcs", "Experion"),
    (r"Experion\s*LX", "Honeywell Experion LX", "plc", "Experion"),
    (r"ControlEdge\s*PLC", "Honeywell ControlEdge PLC", "plc", "ControlEdge"),
    (r"ControlEdge\s*RTU", "Honeywell ControlEdge RTU", "rtu", "ControlEdge"),
    (r"MasterLogic", "Honeywell MasterLogic", "plc", "MasterLogic"),
    (r"HC900", "Honeywell HC900", "plc", "HC900"),

    # Safety Systems
    (r"Safety\s*Manager", "Honeywell Safety Manager", "safety_controller", "SIS"),
    (r"FSC", "Honeywell FSC", "safety_controller", "SIS"),

    # Generic
    (r"Honeywell", "Honeywell Device", "plc", None),
]

SCHNEIDER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:54": ("plc", "Industrial", "Schneider PLC"),
    "00:80:F4": ("plc", "Industrial", "Schneider Electric"),
    "00:80:F4": ("plc", "Industrial", "Schneider PLC"),
    # REMOVED: 70:4D:7B - IEEE assigns to Unknown, not SCHNEIDER
}

SCHNEIDER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Modicon PLCs
    (r"Modicon\s*M340", "Schneider Modicon M340", "plc", "Unity Pro"),
    (r"Modicon\s*M580", "Schneider Modicon M580", "plc", "Unity Pro"),
    (r"Modicon\s*M251", "Schneider Modicon M251", "plc", "SoMachine"),
    (r"Modicon\s*M262", "Schneider Modicon M262", "plc", "EcoStruxure"),
    (r"Modicon\s*M171", "Schneider Modicon M171", "plc", "SoMachine"),
    (r"Modicon\s*Quantum", "Schneider Modicon Quantum", "plc", "Unity Pro"),
    (r"Modicon\s*Premium", "Schneider Modicon Premium", "plc", "Unity Pro"),
    (r"Modicon\s*Momentum", "Schneider Modicon Momentum", "plc", "Unity Pro"),

    # TM Series
    (r"TM221", "Schneider TM221", "plc", "SoMachine Basic"),
    (r"TM241", "Schneider TM241", "plc", "SoMachine"),
    (r"TM251", "Schneider TM251", "plc", "SoMachine"),
    (r"TM262", "Schneider TM262", "plc", "EcoStruxure"),

    # HMI
    (r"Magelis", "Schneider Magelis HMI", "hmi", "Vijeo Designer"),
    (r"HMIG[TPS]\d+", "Schneider Magelis HMI", "hmi", "Vijeo Designer"),
    (r"Harmony\s*iPC", "Schneider Harmony iPC", "hmi", "Windows"),

    # Drives
    (r"Altivar\s*Process", "Schneider Altivar Process", "vfd", "Altivar"),
    (r"Altivar\s*Machine", "Schneider Altivar Machine", "vfd", "Altivar"),
    (r"Altivar\s*\d+", "Schneider Altivar", "vfd", "Altivar"),
    (r"ATV\d+", "Schneider Altivar", "vfd", "Altivar"),

    # Power Monitoring
    (r"PowerLogic\s*PM", "Schneider PowerLogic PM", "power_meter", "ION"),
    (r"ION\d+", "Schneider ION Power Meter", "power_meter", "ION"),
    (r"PowerTag", "Schneider PowerTag", "power_meter", "EcoStruxure"),

    # EcoStruxure
    (r"EcoStruxure", "Schneider EcoStruxure", "management", "EcoStruxure"),
    (r"StruxureWare", "Schneider StruxureWare", "management", "StruxureWare"),

    # UPS
    (r"APC\s*Smart-UPS", "APC Smart-UPS", "ups", "APC"),
    (r"APC\s*Symmetra", "APC Symmetra", "ups", "APC"),
    (r"APC\s*Back-UPS", "APC Back-UPS", "ups", "APC"),

    # Generic
    (r"Schneider\s*Electric", "Schneider Device", "plc", None),
]

SIEMENS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0E:8C": ("plc", "Industrial", "Siemens PLC"),
    "00:1B:1B": ("plc", "Industrial", "Siemens PLC"),
    "00:1C:06": ("plc", "Industrial", "Siemens PLC"),
    "28:63:36": ("plc", "Industrial", "Siemens PLC"),
    # REMOVED: 44:6A:2E - IEEE assigns to Huawei Technologies, not Siemens
    # REMOVED: 6C:3B:6B - IEEE assigns to Unknown, not SIEMENS
    "8C:F3:19": ("plc", "Industrial", "Siemens PLC"),
    "AC:64:17": ("plc", "Industrial", "Siemens PLC"),
    # REMOVED: B0:B2:DC - IEEE assigns to Unknown, not SIEMENS
}

SIEMENS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # S7 PLCs
    (r"S7-1500", "Siemens S7-1500", "plc", "TIA Portal"),
    (r"S7-1200", "Siemens S7-1200", "plc", "TIA Portal"),
    (r"S7-300", "Siemens S7-300", "plc", "STEP 7"),
    (r"S7-400", "Siemens S7-400", "plc", "STEP 7"),
    (r"S7-\d+", "Siemens S7", "plc", "STEP 7"),
    (r"SIMATIC\s*S7", "Siemens SIMATIC S7", "plc", "TIA Portal"),

    # ET200 Distributed I/O
    (r"ET\s*200SP", "Siemens ET 200SP", "io_module", "TIA Portal"),
    (r"ET\s*200MP", "Siemens ET 200MP", "io_module", "TIA Portal"),
    (r"ET\s*200S", "Siemens ET 200S", "io_module", "STEP 7"),
    (r"ET\s*200M", "Siemens ET 200M", "io_module", "STEP 7"),

    # HMI Panels
    (r"TP\d{3}", "Siemens HMI Panel", "hmi", "WinCC"),
    (r"KP\d{3}", "Siemens HMI Panel", "hmi", "WinCC"),
    (r"KTP\d{3}", "Siemens HMI Panel", "hmi", "WinCC"),
    (r"SIMATIC\s*HMI", "Siemens SIMATIC HMI", "hmi", "WinCC"),
    (r"Comfort\s*Panel", "Siemens Comfort Panel", "hmi", "WinCC"),
    (r"Basic\s*Panel", "Siemens Basic Panel", "hmi", "WinCC"),

    # Industrial PCs
    (r"SIMATIC\s*IPC", "Siemens SIMATIC IPC", "industrial_pc", "Windows"),
    (r"SIMATIC\s*Field\s*PG", "Siemens Field PG", "industrial_pc", "Windows"),
    (r"IPC\d{3}", "Siemens IPC", "industrial_pc", "Windows"),

    # Drives
    (r"SINAMICS\s*G\d+", "Siemens SINAMICS G", "vfd", "SINAMICS"),
    (r"SINAMICS\s*S\d+", "Siemens SINAMICS S", "vfd", "SINAMICS"),
    (r"SINAMICS\s*V\d+", "Siemens SINAMICS V", "vfd", "SINAMICS"),
    (r"MICROMASTER", "Siemens Micromaster", "vfd", "MICROMASTER"),

    # Network devices
    (r"SCALANCE\s*X", "Siemens SCALANCE X Switch", "switch", "SCALANCE"),
    (r"SCALANCE\s*W", "Siemens SCALANCE W AP", "access_point", "SCALANCE"),
    (r"SCALANCE\s*M", "Siemens SCALANCE M Router", "router", "SCALANCE"),
    (r"SCALANCE\s*S", "Siemens SCALANCE S Firewall", "firewall", "SCALANCE"),

    # SINEMA
    (r"SINEMA\s*Remote\s*Connect", "Siemens SINEMA RC", "vpn", "SINEMA"),
    (r"SINEMA\s*Server", "Siemens SINEMA Server", "management", "SINEMA"),

    # Generic
    (r"SIMATIC", "Siemens SIMATIC", "plc", "TIA Portal"),
    (r"Siemens", "Siemens Device", "plc", None),
]

ALLEN_BRADLEY_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:BC": ("plc", "Industrial", "Allen-Bradley PLC"),
    "00:1D:9C": ("plc", "Industrial", "Allen-Bradley PLC"),
    "5C:88:16": ("plc", "Industrial", "Allen-Bradley PLC"),
    # REMOVED: 00:0D:3A - IEEE assigns to Microsoft Corp., not Allen-Bradley/Rockwell
}

ALLEN_BRADLEY_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ControlLogix
    (r"ControlLogix\s*5580", "Allen-Bradley ControlLogix 5580", "plc", "Studio 5000"),
    (r"ControlLogix\s*5570", "Allen-Bradley ControlLogix 5570", "plc", "Studio 5000"),
    (r"ControlLogix\s*5560", "Allen-Bradley ControlLogix 5560", "plc", "RSLogix 5000"),
    (r"ControlLogix\s*5550", "Allen-Bradley ControlLogix 5550", "plc", "RSLogix 5000"),
    (r"ControlLogix", "Allen-Bradley ControlLogix", "plc", "Studio 5000"),
    (r"1756-L\d+", "Allen-Bradley ControlLogix", "plc", "Studio 5000"),

    # CompactLogix
    (r"CompactLogix\s*5380", "Allen-Bradley CompactLogix 5380", "plc", "Studio 5000"),
    (r"CompactLogix\s*5370", "Allen-Bradley CompactLogix 5370", "plc", "Studio 5000"),
    (r"CompactLogix", "Allen-Bradley CompactLogix", "plc", "Studio 5000"),
    (r"1769-L\d+", "Allen-Bradley CompactLogix", "plc", "Studio 5000"),

    # Micro800
    (r"Micro850", "Allen-Bradley Micro850", "plc", "CCW"),
    (r"Micro830", "Allen-Bradley Micro830", "plc", "CCW"),
    (r"Micro820", "Allen-Bradley Micro820", "plc", "CCW"),
    (r"Micro810", "Allen-Bradley Micro810", "plc", "CCW"),

    # PLC-5 / SLC 500
    (r"PLC-5", "Allen-Bradley PLC-5", "plc", "RSLogix 5"),
    (r"SLC\s*500", "Allen-Bradley SLC 500", "plc", "RSLogix 500"),

    # HMI
    (r"PanelView\s*Plus\s*7", "Allen-Bradley PanelView Plus 7", "hmi", "FactoryTalk"),
    (r"PanelView\s*Plus\s*6", "Allen-Bradley PanelView Plus 6", "hmi", "FactoryTalk"),
    (r"PanelView\s*5000", "Allen-Bradley PanelView 5000", "hmi", "FactoryTalk"),
    (r"PanelView\s*800", "Allen-Bradley PanelView 800", "hmi", "CCW"),
    (r"PanelView", "Allen-Bradley PanelView", "hmi", "FactoryTalk"),

    # Drives
    (r"PowerFlex\s*755", "Allen-Bradley PowerFlex 755", "vfd", "Studio 5000"),
    (r"PowerFlex\s*527", "Allen-Bradley PowerFlex 527", "vfd", "Studio 5000"),
    (r"PowerFlex\s*525", "Allen-Bradley PowerFlex 525", "vfd", "CCW"),
    (r"PowerFlex\s*4", "Allen-Bradley PowerFlex 4", "vfd", "DriveExecutive"),
    (r"PowerFlex", "Allen-Bradley PowerFlex", "vfd", "Studio 5000"),

    # Network
    (r"Stratix\s*5700", "Allen-Bradley Stratix 5700", "switch", "IOS"),
    (r"Stratix\s*5400", "Allen-Bradley Stratix 5400", "switch", "IOS"),
    (r"Stratix\s*5410", "Allen-Bradley Stratix 5410", "switch", "IOS"),
    (r"Stratix", "Allen-Bradley Stratix", "switch", "IOS"),

    # Generic
    (r"Allen-Bradley", "Allen-Bradley Device", "plc", None),
    (r"Rockwell\s*Automation", "Rockwell Automation", "plc", None),
]

# ABB INDUSTRIAL PATTERNS

ABB_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:80:F4 - IEEE assigns to Unknown, not ABB
}

ABB_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # AC500 PLC
    (r"AC500", "ABB AC500 PLC", "plc", "Automation Builder"),
    (r"PM5\d{2}", "ABB AC500 PM5xx", "plc", "Automation Builder"),
    # Drives
    (r"ACS880", "ABB ACS880 Drive", "vfd", "Drive Composer"),
    (r"ACS580", "ABB ACS580 Drive", "vfd", "Drive Composer"),
    (r"ACS480", "ABB ACS480 Drive", "vfd", "Drive Composer"),
    (r"ACS380", "ABB ACS380 Drive", "vfd", "Drive Composer"),
    (r"ACS\d{3}", "ABB ACS Drive", "vfd", "Drive Composer"),
    # Robots
    (r"IRC5", "ABB IRC5 Robot Controller", "robot", "RobotStudio"),
    (r"OmniCore", "ABB OmniCore Robot Controller", "robot", "RobotStudio"),
    # SCADA
    (r"Ability\s*Symphony", "ABB Symphony Plus", "dcs", "Symphony"),
    (r"800xA", "ABB 800xA DCS", "dcs", "800xA"),
    # Generic
    (r"ABB", "ABB Device", "plc", None),
]

# OMRON INDUSTRIAL PATTERNS

OMRON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

OMRON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # NX/NJ Series (Modern)
    (r"NX1P2", "Omron NX1P2", "plc", "Sysmac Studio"),
    (r"NX102", "Omron NX102", "plc", "Sysmac Studio"),
    (r"NJ\d{3}", "Omron NJ Series", "plc", "Sysmac Studio"),
    # CJ/CS Series (Classic)
    (r"CJ2M", "Omron CJ2M", "plc", "CX-Programmer"),
    (r"CJ1M", "Omron CJ1M", "plc", "CX-Programmer"),
    (r"CS1G", "Omron CS1G", "plc", "CX-Programmer"),
    # CP Series (Compact)
    (r"CP1L", "Omron CP1L", "plc", "CX-Programmer"),
    (r"CP1E", "Omron CP1E", "plc", "CX-Programmer"),
    # HMI
    (r"NA5", "Omron NA5 HMI", "hmi", "Sysmac Studio"),
    (r"NB\d+", "Omron NB HMI", "hmi", "NB-Designer"),
    # VFD
    (r"3G3MX2", "Omron MX2 Inverter", "vfd", "CX-Drive"),
    # Safety
    (r"NX-S", "Omron NX Safety", "safety_plc", "Sysmac Studio"),
    # Generic
    (r"Omron", "Omron Device", "plc", None),
]

# MITSUBISHI ELECTRIC INDUSTRIAL PATTERNS

MITSUBISHI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:06:8C - IEEE assigns to Unknown, not MITSUBISHI
}

MITSUBISHI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # iQ-R Series
    (r"R\d{2}CPU", "Mitsubishi iQ-R PLC", "plc", "GX Works3"),
    (r"iQ-R", "Mitsubishi iQ-R", "plc", "GX Works3"),
    # iQ-F Series
    (r"FX5U", "Mitsubishi FX5U", "plc", "GX Works3"),
    (r"FX5UC", "Mitsubishi FX5UC", "plc", "GX Works3"),
    (r"iQ-F", "Mitsubishi iQ-F", "plc", "GX Works3"),
    # Q Series
    (r"Q\d{2}CPU", "Mitsubishi Q Series", "plc", "GX Works2"),
    # FX Series (Legacy)
    (r"FX3U", "Mitsubishi FX3U", "plc", "GX Works2"),
    (r"FX3G", "Mitsubishi FX3G", "plc", "GX Works2"),
    # GOT HMI
    (r"GOT2000", "Mitsubishi GOT2000 HMI", "hmi", "GT Designer3"),
    (r"GOT1000", "Mitsubishi GOT1000 HMI", "hmi", "GT Designer2"),
    (r"GT27", "Mitsubishi GT27 HMI", "hmi", "GT Designer3"),
    # VFD
    (r"FR-A800", "Mitsubishi FR-A800 Inverter", "vfd", "FR Configurator2"),
    (r"FR-E800", "Mitsubishi FR-E800 Inverter", "vfd", "FR Configurator2"),
    # Robot
    (r"MELFA", "Mitsubishi MELFA Robot", "robot", "RT ToolBox3"),
    # Generic
    (r"Mitsubishi\s*Electric", "Mitsubishi Electric", "plc", None),
    (r"MELSEC", "Mitsubishi MELSEC", "plc", "GX Works"),
]

# BECKHOFF INDUSTRIAL PATTERNS

BECKHOFF_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:01:05": ("plc", "Industrial", "Beckhoff"),
}

BECKHOFF_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # CX Series (Embedded PC)
    (r"CX\d{4}", "Beckhoff CX Series", "industrial_pc", "TwinCAT"),
    # C Series (Industrial PC)
    (r"C6\d{3}", "Beckhoff C6xxx IPC", "industrial_pc", "TwinCAT"),
    # CP Series (Panel PC)
    (r"CP\d{4}", "Beckhoff Panel PC", "hmi", "TwinCAT"),
    # EtherCAT Terminals
    (r"EL\d{4}", "Beckhoff EtherCAT Terminal", "io_module", "TwinCAT"),
    (r"EK\d{4}", "Beckhoff EtherCAT Coupler", "io_module", "TwinCAT"),
    # TwinCAT
    (r"TwinCAT\s*3", "Beckhoff TwinCAT 3", "plc", "TwinCAT 3"),
    (r"TwinCAT\s*2", "Beckhoff TwinCAT 2", "plc", "TwinCAT 2"),
    (r"TwinCAT", "Beckhoff TwinCAT", "plc", "TwinCAT"),
    # AX/AM Drives
    (r"AX\d{4}", "Beckhoff AX Servo Drive", "servo", "TwinCAT"),
    # Generic
    (r"Beckhoff", "Beckhoff Device", "plc", "TwinCAT"),
]

# PHOENIX CONTACT INDUSTRIAL PATTERNS

PHOENIX_CONTACT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:A0:45": ("plc", "Industrial", "Phoenix Contact"),
}

PHOENIX_CONTACT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # PLCnext
    (r"PLCnext", "Phoenix Contact PLCnext", "plc", "PLCnext Engineer"),
    (r"AXC\s*F\s*\d{4}", "Phoenix Contact AXC F", "plc", "PLCnext Engineer"),
    # Inline
    (r"ILC\s*\d{3}", "Phoenix Contact ILC", "plc", "PC Worx"),
    (r"IL\s*PLC", "Phoenix Contact Inline PLC", "plc", "PC Worx"),
    # mGuard Security
    (r"mGuard", "Phoenix Contact mGuard", "firewall", "Device Manager"),
    # Network
    (r"FL\s*SWITCH", "Phoenix Contact FL Switch", "switch", "Device Manager"),
    (r"FL\s*MGUARD", "Phoenix Contact FL mGuard", "firewall", "Device Manager"),
    # Power Supply
    (r"QUINT\s*POWER", "Phoenix Contact QUINT Power", "power_supply", None),
    (r"TRIO\s*POWER", "Phoenix Contact TRIO Power", "power_supply", None),
    # Generic
    (r"Phoenix\s*Contact", "Phoenix Contact Device", "plc", None),
]


# AV/PROFESSIONAL DISPLAY PATTERNS

AMX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

AMX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"NX-\d{4}", "AMX NX Controller", "av_controller", "NetLinx"),
    (r"NI-\d{4}", "AMX NI NetLinx", "av_controller", "NetLinx"),
    (r"DVX-\d{4}", "AMX DVX Switcher", "av_switcher", "NetLinx"),
    (r"DGX-\d+", "AMX DGX Switcher", "av_switcher", "NetLinx"),
    (r"Enova\s*DGX", "AMX Enova DGX", "av_switcher", "NetLinx"),
    (r"NetLinx", "AMX NetLinx", "av_controller", "NetLinx"),
    (r"Acendo\s*Vibe", "AMX Acendo Vibe", "soundbar", "Firmware"),
    (r"AMX", "AMX Device", "av_controller", None),
]

BIAMP_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

BIAMP_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Tesira\s*SERVER", "Biamp Tesira SERVER", "dsp", "Tesira"),
    (r"Tesira\s*FORTE", "Biamp Tesira FORTE", "dsp", "Tesira"),
    (r"TesiraFORTE", "Biamp TesiraFORTE", "dsp", "Tesira"),
    (r"Tesira", "Biamp Tesira", "dsp", "Tesira"),
    (r"Nexia", "Biamp Nexia", "dsp", "NWare"),
    (r"Audia", "Biamp Audia", "dsp", "NWare"),
    (r"Devio", "Biamp Devio", "conferencing", "Tesira"),
    (r"Parlé", "Biamp Parlé", "microphone", "Tesira"),
    (r"Biamp", "Biamp Device", "dsp", None),
]

BARCO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

BARCO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"ClickShare\s*CX", "Barco ClickShare CX", "wireless_presentation", "ClickShare"),
    (r"ClickShare\s*CS[E]?", "Barco ClickShare CSE", "wireless_presentation", "ClickShare"),
    (r"ClickShare", "Barco ClickShare", "wireless_presentation", "ClickShare"),
    (r"G\d{2}\s*Body", "Barco G Series Projector", "projector", "Projector Toolset"),
    (r"F\d{2}", "Barco F Series Projector", "projector", "Projector Toolset"),
    (r"UDX", "Barco UDX Projector", "projector", "Projector Toolset"),
    (r"HDX", "Barco HDX Projector", "projector", "Projector Toolset"),
    (r"Barco", "Barco Device", "projector", None),
]

CHRISTIE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

CHRISTIE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Griffyn\s*4K", "Christie Griffyn 4K", "projector", "Christie Twist"),
    (r"D4K", "Christie D4K Projector", "projector", "Christie Twist"),
    (r"DHD\d+", "Christie DHD Projector", "projector", "Christie Twist"),
    (r"DWU\d+", "Christie DWU Projector", "projector", "Christie Twist"),
    (r"M\s*4K", "Christie M 4K", "projector", "Christie Twist"),
    (r"Boxer\s*4K", "Christie Boxer 4K", "projector", "Christie Twist"),
    (r"Christie", "Christie Projector", "projector", None),
]

NEC_DISPLAY_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:4C": ("display", "AV", "NEC Display"),
}

NEC_DISPLAY_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"PA\d{3}", "NEC PA Series Display", "display", "NaViSet"),
    (r"MA\d{3}", "NEC MA Series Display", "display", "NaViSet"),
    (r"C\d{3}Q", "NEC C Series Display", "display", "NaViSet"),
    (r"E\d{3}Q", "NEC E Series Display", "display", "NaViSet"),
    (r"V\d{3}Q", "NEC V Series Display", "display", "NaViSet"),
    (r"MultiSync", "NEC MultiSync", "display", "NaViSet"),
    (r"NP-P\d+", "NEC NP Projector", "projector", "NaViSet"),
    (r"NEC\s*Display", "NEC Display", "display", None),
]

CRESTRON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:10:7E": ("av_controller", "AV", "Crestron"),
    "00:10:79": ("av_controller", "AV", "Crestron"),
}

CRESTRON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"CP4", "Crestron CP4 Processor", "av_controller", "Crestron"),
    (r"CP3", "Crestron CP3 Processor", "av_controller", "Crestron"),
    (r"DM-NVX", "Crestron DM-NVX", "av_encoder", "Crestron"),
    (r"DM-MD\d+", "Crestron DM Switcher", "av_switcher", "Crestron"),
    (r"TSW-\d+", "Crestron TSW Touch Panel", "touch_panel", "Crestron"),
    (r"TS-\d+", "Crestron TS Touch Screen", "touch_panel", "Crestron"),
    (r"Mercury", "Crestron Mercury", "conferencing", "Crestron"),
    (r"Flex", "Crestron Flex", "conferencing", "Crestron"),
    (r"Crestron", "Crestron Device", "av_controller", None),
]

EXTRON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:05:A6": ("av_controller", "AV", "Extron"),
}

EXTRON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"IPL\s*Pro", "Extron IPL Pro Controller", "av_controller", "Toolbelt"),
    (r"IN\d{4}", "Extron IN Switcher", "av_switcher", "Toolbelt"),
    (r"DTP\s*CrossPoint", "Extron DTP CrossPoint", "av_switcher", "Toolbelt"),
    (r"DXP\s*HD", "Extron DXP HD", "av_switcher", "Toolbelt"),
    (r"SMP\s*\d+", "Extron SMP Recorder", "av_recorder", "Toolbelt"),
    (r"NAV\s*Pro", "Extron NAV Pro", "av_encoder", "Toolbelt"),
    (r"Extron", "Extron Device", "av_controller", None),
]

QSYS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:60:74": ("dsp", "AV", "QSC Q-SYS"),
}

QSYS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Q-SYS\s*Core\s*\d+i", "QSC Q-SYS Core", "dsp", "Q-SYS Designer"),
    (r"Q-SYS\s*Core", "QSC Q-SYS Core", "dsp", "Q-SYS Designer"),
    (r"Q-SYS", "QSC Q-SYS", "dsp", "Q-SYS Designer"),
    (r"NV-\d+-H", "QSC NV Series Encoder", "av_encoder", "Q-SYS Designer"),
    (r"TSC-\d+", "QSC TSC Touch Screen", "touch_panel", "Q-SYS Designer"),
    (r"QSC", "QSC Device", "dsp", None),
]


# MAKER/EMBEDDED PLATFORM PATTERNS

NVIDIA_JETSON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:04:4B": ("sbc", "Embedded", "NVIDIA Jetson"),
    "48:B0:2D": ("sbc", "Embedded", "NVIDIA Jetson"),
}

NVIDIA_JETSON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Jetson\s*AGX\s*Orin", "NVIDIA Jetson AGX Orin", "sbc", "JetPack"),
    (r"Jetson\s*Orin\s*Nano", "NVIDIA Jetson Orin Nano", "sbc", "JetPack"),
    (r"Jetson\s*Orin\s*NX", "NVIDIA Jetson Orin NX", "sbc", "JetPack"),
    (r"Jetson\s*AGX\s*Xavier", "NVIDIA Jetson AGX Xavier", "sbc", "JetPack"),
    (r"Jetson\s*Xavier\s*NX", "NVIDIA Jetson Xavier NX", "sbc", "JetPack"),
    (r"Jetson\s*Nano", "NVIDIA Jetson Nano", "sbc", "JetPack"),
    (r"Jetson\s*TX2", "NVIDIA Jetson TX2", "sbc", "JetPack"),
    (r"Jetson\s*TX1", "NVIDIA Jetson TX1", "sbc", "JetPack"),
    (r"Jetson", "NVIDIA Jetson", "sbc", "JetPack"),
    (r"L4T", "NVIDIA Linux for Tegra", "sbc", "JetPack"),
    (r"Tegra", "NVIDIA Tegra", "sbc", "JetPack"),
]

ARDUINO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "A8:61:0A": ("mcu", "Embedded", "Arduino"),
    "C8:F0:9E": ("mcu", "Embedded", "Arduino"),
}

ARDUINO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Arduino\s*Portenta", "Arduino Portenta", "mcu", "Arduino IDE"),
    (r"Arduino\s*Opta", "Arduino Opta PLC", "plc", "Arduino IDE"),
    (r"Arduino\s*MKR", "Arduino MKR", "mcu", "Arduino IDE"),
    (r"Arduino\s*Nano\s*33", "Arduino Nano 33", "mcu", "Arduino IDE"),
    (r"Arduino\s*Uno\s*WiFi", "Arduino Uno WiFi", "mcu", "Arduino IDE"),
    (r"Arduino\s*Mega", "Arduino Mega", "mcu", "Arduino IDE"),
    (r"Arduino\s*Due", "Arduino Due", "mcu", "Arduino IDE"),
    (r"Arduino", "Arduino Device", "mcu", "Arduino IDE"),
]

BEAGLEBONE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "1C:BA:8C": ("sbc", "Embedded", "BeagleBone"),
    "90:59:AF": ("sbc", "Embedded", "BeagleBone"),
    "D0:5F:B8": ("sbc", "Embedded", "BeagleBone"),
    "C8:A0:30": ("sbc", "Embedded", "BeagleBone"),
}

BEAGLEBONE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"BeagleBone\s*AI-64", "BeagleBone AI-64", "sbc", "Debian"),
    (r"BeagleBone\s*AI", "BeagleBone AI", "sbc", "Debian"),
    (r"BeagleBone\s*Black\s*Wireless", "BeagleBone Black Wireless", "sbc", "Debian"),
    (r"BeagleBone\s*Black\s*Industrial", "BeagleBone Black Industrial", "sbc", "Debian"),
    (r"BeagleBone\s*Black", "BeagleBone Black", "sbc", "Debian"),
    (r"BeagleBone\s*Green", "BeagleBone Green", "sbc", "Debian"),
    (r"BeagleBone\s*Blue", "BeagleBone Blue", "sbc", "Debian"),
    (r"PocketBeagle", "PocketBeagle", "sbc", "Debian"),
    (r"BeagleBone", "BeagleBone", "sbc", "Debian"),
    (r"BeagleBoard", "BeagleBoard", "sbc", "Debian"),
]


# NOTE: ESPRESSIF_MAC_PREFIXES and ESPRESSIF_BANNER_PATTERNS are defined
# in the IoT/Embedded section below (around line ~6550).


# COMPUTER VENDOR PATTERNS

MSI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 80:CE:62 - IEEE assigns to Unknown, not MSI
}

MSI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"MSI\s*MEG", "MSI MEG Gaming", "computer", None),
    (r"MSI\s*MPG", "MSI MPG Gaming", "computer", None),
    (r"MSI\s*MAG", "MSI MAG Gaming", "computer", None),
    (r"MSI\s*PRO", "MSI PRO", "computer", None),
    (r"MSI\s*Prestige", "MSI Prestige", "laptop", None),
    (r"MSI\s*Creator", "MSI Creator", "laptop", None),
    (r"MSI\s*Stealth", "MSI Stealth", "laptop", None),
    (r"MSI\s*Raider", "MSI Raider", "laptop", None),
    (r"MSI\s*Katana", "MSI Katana", "laptop", None),
    (r"MSI\s*Titan", "MSI Titan", "laptop", None),
    (r"MSI", "MSI Device", "computer", None),
]

ACER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 50:9A:4C - IEEE assigns to Unknown, not ACER
}

ACER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Acer\s*Predator", "Acer Predator", "laptop", None),
    (r"Acer\s*Nitro", "Acer Nitro", "laptop", None),
    (r"Acer\s*Swift", "Acer Swift", "laptop", None),
    (r"Acer\s*Aspire", "Acer Aspire", "laptop", None),
    (r"Acer\s*TravelMate", "Acer TravelMate", "laptop", None),
    (r"Acer\s*Chromebook", "Acer Chromebook", "laptop", "ChromeOS"),
    (r"Acer\s*ConceptD", "Acer ConceptD", "workstation", None),
    (r"Acer", "Acer Device", "computer", None),
]

MICROSOFT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Azure VM MAC prefix — IEEE MA-L assigned to Microsoft Corporation
    "00:0D:3A": ("virtual_machine", "Cloud", "Azure VM"),
    "00:12:5A": ("computer", "Computer", "Microsoft"),
    "00:15:5D": ("virtual_machine", "Virtualization", "Hyper-V VM"),
    "00:17:FA": ("computer", "Computer", "Microsoft"),
    # REMOVED: 00:1D:D8 - IEEE assigns to Unknown, not MICROSOFT
    "00:50:F2": ("computer", "Computer", "Microsoft"),
    "28:18:78": ("tablet", "Computer", "Microsoft Surface"),
    "60:45:BD": ("tablet", "Computer", "Microsoft Surface"),
    "7C:1E:52": ("tablet", "Computer", "Microsoft Surface"),
    "98:5F:D3": ("tablet", "Computer", "Microsoft Surface"),
    # Additional Microsoft Surface OUIs
    "C0:33:5E": ("tablet", "Computer", "Microsoft Surface"),
    "50:1A:56": ("tablet", "Computer", "Microsoft Surface"),
    "B8:31:B5": ("tablet", "Computer", "Microsoft Surface"),
    "5C:BA:37": ("tablet", "Computer", "Microsoft Surface"),
    "3C:83:75": ("tablet", "Computer", "Microsoft Surface"),
    "EC:83:50": ("tablet", "Computer", "Microsoft Surface"),
}

MICROSOFT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Surface\s*Pro\s*\d+", "Microsoft Surface Pro", "tablet", "Windows"),
    (r"Surface\s*Pro\s*X", "Microsoft Surface Pro X", "tablet", "Windows"),
    (r"Surface\s*Laptop\s*Studio", "Microsoft Surface Laptop Studio", "laptop", "Windows"),
    (r"Surface\s*Laptop\s*\d+", "Microsoft Surface Laptop", "laptop", "Windows"),
    (r"Surface\s*Book\s*\d+", "Microsoft Surface Book", "laptop", "Windows"),
    (r"Surface\s*Go\s*\d+", "Microsoft Surface Go", "tablet", "Windows"),
    (r"Surface\s*Studio\s*\d+", "Microsoft Surface Studio", "workstation", "Windows"),
    (r"Surface\s*Hub", "Microsoft Surface Hub", "display", "Windows"),
    (r"Surface", "Microsoft Surface", "computer", "Windows"),
    (r"Xbox\s*Series\s*X", "Microsoft Xbox Series X", "game_console", None),
    (r"Xbox\s*Series\s*S", "Microsoft Xbox Series S", "game_console", None),
    (r"Xbox\s*One", "Microsoft Xbox One", "game_console", None),
    (r"Xbox", "Microsoft Xbox", "game_console", None),
]


# EV CHARGER PATTERNS

CHARGEPOINT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:1A:3E": ("ev_charger", "EV", "ChargePoint"),
    "2C:26:5F": ("ev_charger", "EV", "ChargePoint"),
}

CHARGEPOINT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"CT4\d{3}", "ChargePoint CT4000", "ev_charger", "ChargePoint"),
    (r"CPF\d{2}", "ChargePoint CPF", "ev_charger", "ChargePoint"),
    (r"Express\s*Plus", "ChargePoint Express Plus", "ev_charger", "ChargePoint"),
    (r"ChargePoint", "ChargePoint Charger", "ev_charger", "ChargePoint"),
]

TESLA_WALL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "98:ED:5C": ("ev_charger", "EV", "Tesla Wall Connector"),
    "4C:FC:AA": ("ev_charger", "EV", "Tesla"),
}

TESLA_WALL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Tesla\s*Wall\s*Connector\s*3", "Tesla Wall Connector Gen 3", "ev_charger", None),
    (r"Tesla\s*Wall\s*Connector", "Tesla Wall Connector", "ev_charger", None),
    (r"Tesla\s*Supercharger", "Tesla Supercharger", "ev_charger", None),
]

JUICEBOX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

JUICEBOX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"JuiceBox\s*Pro\s*40", "JuiceBox Pro 40", "ev_charger", "Enel X Way"),
    (r"JuiceBox\s*40", "JuiceBox 40", "ev_charger", "Enel X Way"),
    (r"JuiceBox", "JuiceBox Charger", "ev_charger", "Enel X Way"),
]

WALLBOX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

WALLBOX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Pulsar\s*Plus", "Wallbox Pulsar Plus", "ev_charger", "Wallbox"),
    (r"Pulsar\s*Pro", "Wallbox Pulsar Pro", "ev_charger", "Wallbox"),
    (r"Commander\s*2", "Wallbox Commander 2", "ev_charger", "Wallbox"),
    (r"Quasar\s*2", "Wallbox Quasar 2", "ev_charger", "Wallbox"),
    (r"Wallbox", "Wallbox Charger", "ev_charger", "Wallbox"),
]

CLIPPER_CREEK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

CLIPPER_CREEK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"HCS-\d+", "ClipperCreek HCS", "ev_charger", "ClipperCreek"),
    (r"LCS-\d+", "ClipperCreek LCS", "ev_charger", "ClipperCreek"),
    (r"ClipperCreek", "ClipperCreek Charger", "ev_charger", "ClipperCreek"),
]


# BARCODE SCANNER / POS PATTERNS

DATALOGIC_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

DATALOGIC_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Gryphon\s*4\d{3}", "Datalogic Gryphon 4000", "barcode_scanner", None),
    (r"Gryphon", "Datalogic Gryphon", "barcode_scanner", None),
    (r"PowerScan\s*9\d{3}", "Datalogic PowerScan 9000", "barcode_scanner", None),
    (r"PowerScan", "Datalogic PowerScan", "barcode_scanner", None),
    (r"QuickScan", "Datalogic QuickScan", "barcode_scanner", None),
    (r"Magellan\s*\d{4}", "Datalogic Magellan", "barcode_scanner", None),
    (r"Datalogic", "Datalogic Device", "barcode_scanner", None),
]

HONEYWELL_SCANNER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

HONEYWELL_SCANNER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Voyager\s*\d{4}", "Honeywell Voyager", "barcode_scanner", None),
    (r"Xenon\s*\d{4}", "Honeywell Xenon", "barcode_scanner", None),
    (r"Granit\s*\d{4}", "Honeywell Granit", "barcode_scanner", None),
    (r"Orbit\s*\d{4}", "Honeywell Orbit", "barcode_scanner", None),
    (r"Genesis\s*\d{4}", "Honeywell Genesis", "barcode_scanner", None),
    (r"Stratos\s*\d{4}", "Honeywell Stratos", "barcode_scanner", None),
    (r"Honeywell\s*Scanner", "Honeywell Scanner", "barcode_scanner", None),
]

ZEBRA_SCANNER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:A0:F8": ("barcode_scanner", "POS", "Zebra"),
}

ZEBRA_SCANNER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"DS\d{4}", "Zebra DS Series Scanner", "barcode_scanner", None),
    (r"LI\d{4}", "Zebra LI Series Scanner", "barcode_scanner", None),
    (r"LS\d{4}", "Zebra LS Series Scanner", "barcode_scanner", None),
    (r"MP\d{4}", "Zebra MP Series Scanner", "barcode_scanner", None),
    (r"MT\d{4}", "Zebra MT Series Mobile", "mobile_computer", None),
    (r"MC\d{4}", "Zebra MC Series Mobile", "mobile_computer", None),
    (r"TC\d{2}", "Zebra TC Series Mobile", "mobile_computer", None),
    (r"Zebra\s*Scanner", "Zebra Scanner", "barcode_scanner", None),
]

SYMBOL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:15:70": ("barcode_scanner", "POS", "Symbol"),
    # REMOVED: 00:A0:F8 - IEEE assigns to Unknown, not SYMBOL
}

SYMBOL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Symbol\s*DS\d{4}", "Symbol DS Scanner", "barcode_scanner", None),
    (r"Symbol\s*LS\d{4}", "Symbol LS Scanner", "barcode_scanner", None),
    (r"Symbol\s*MC\d{4}", "Symbol MC Mobile", "mobile_computer", None),
    (r"Symbol", "Symbol Device", "barcode_scanner", None),
]


# AMAZON / GOOGLE IOT PATTERNS

AMAZON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:BB:3A": ("smart_speaker", "IoT", "Amazon Echo"),
    "0C:47:C9": ("smart_speaker", "IoT", "Amazon Echo"),
    "18:74:2E": ("smart_speaker", "IoT", "Amazon Echo"),
    "24:4C:E3": ("smart_speaker", "IoT", "Amazon Echo"),
    "34:D2:70": ("smart_speaker", "IoT", "Amazon Echo"),
    "38:F7:3D": ("smart_speaker", "IoT", "Amazon Echo"),
    "40:A2:DB": ("smart_speaker", "IoT", "Amazon Echo"),
    "44:65:0D": ("smart_speaker", "IoT", "Amazon Echo"),
    "4C:EF:C0": ("smart_speaker", "IoT", "Amazon Echo"),
    "50:DC:E7": ("smart_speaker", "IoT", "Amazon Echo"),
    "58:E5:7A": ("smart_speaker", "IoT", "Amazon Echo"),
    "68:37:E9": ("smart_speaker", "IoT", "Amazon Echo"),
    "6C:56:97": ("smart_speaker", "IoT", "Amazon Echo"),
    "74:C2:46": ("smart_speaker", "IoT", "Amazon Echo"),
    "78:E1:03": ("smart_speaker", "IoT", "Amazon Echo"),
    "84:D6:D0": ("smart_speaker", "IoT", "Amazon Echo"),
    "A0:02:DC": ("smart_speaker", "IoT", "Amazon Echo"),
    "AC:63:BE": ("smart_speaker", "IoT", "Amazon Echo"),
    "B0:FC:0D": ("smart_speaker", "IoT", "Amazon Echo"),
    "F0:27:2D": ("smart_speaker", "IoT", "Amazon Echo"),
    "F0:81:73": ("smart_speaker", "IoT", "Amazon Echo"),
    "FC:65:DE": ("smart_speaker", "IoT", "Amazon Echo"),
    # Fire TV
    "00:FC:8B": ("media_player", "Entertainment", "Fire TV"),
    "08:84:9D": ("media_player", "Entertainment", "Fire TV"),
    "6C:0F:38": ("media_player", "Entertainment", "Fire TV"),
    # Ring
    "C4:90:28": ("doorbell", "IoT", "Ring Doorbell"),
    "DC:B6:C1": ("doorbell", "IoT", "Ring Doorbell"),
    "5C:47:5E": ("ip_camera", "Surveillance", "Ring Camera"),
    # Blink
    "B4:7C:9C": ("ip_camera", "Surveillance", "Blink Camera"),
    # eero (Amazon subsidiary - mesh WiFi routers)
    # Verified eero OUIs from IEEE registration
    "34:D2:70": ("mesh_router", "Network Equipment", "eero"),
}

AMAZON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Echo devices
    (r"Echo\s*Dot", "Amazon Echo Dot", "smart_speaker", "Fire OS"),
    (r"Echo\s*Show\s*15", "Amazon Echo Show 15", "smart_display", "Fire OS"),
    (r"Echo\s*Show\s*10", "Amazon Echo Show 10", "smart_display", "Fire OS"),
    (r"Echo\s*Show\s*8", "Amazon Echo Show 8", "smart_display", "Fire OS"),
    (r"Echo\s*Show\s*5", "Amazon Echo Show 5", "smart_display", "Fire OS"),
    (r"Echo\s*Show", "Amazon Echo Show", "smart_display", "Fire OS"),
    (r"Echo\s*Studio", "Amazon Echo Studio", "smart_speaker", "Fire OS"),
    (r"Echo\s*Plus", "Amazon Echo Plus", "smart_speaker", "Fire OS"),
    (r"Echo\s*Pop", "Amazon Echo Pop", "smart_speaker", "Fire OS"),
    (r"Echo\s*Hub", "Amazon Echo Hub", "smart_display", "Fire OS"),
    (r"Echo(?!\s*Show|\s*Dot|\s*Studio|\s*Plus|\s*Pop|\s*Hub)", "Amazon Echo", "smart_speaker", "Fire OS"),

    # Fire TV
    (r"Fire\s*TV\s*Stick\s*4K\s*Max", "Fire TV Stick 4K Max", "media_player", "Fire OS"),
    (r"Fire\s*TV\s*Stick\s*4K", "Fire TV Stick 4K", "media_player", "Fire OS"),
    (r"Fire\s*TV\s*Stick", "Fire TV Stick", "media_player", "Fire OS"),
    (r"Fire\s*TV\s*Cube", "Fire TV Cube", "media_player", "Fire OS"),
    (r"Fire\s*TV", "Fire TV", "media_player", "Fire OS"),

    # Ring
    (r"Ring\s*Video\s*Doorbell\s*Pro", "Ring Video Doorbell Pro", "doorbell", "Ring OS"),
    (r"Ring\s*Video\s*Doorbell", "Ring Video Doorbell", "doorbell", "Ring OS"),
    (r"Ring\s*Doorbell", "Ring Doorbell", "doorbell", "Ring OS"),
    (r"Ring\s*Spotlight\s*Cam", "Ring Spotlight Cam", "ip_camera", "Ring OS"),
    (r"Ring\s*Stick\s*Up\s*Cam", "Ring Stick Up Cam", "ip_camera", "Ring OS"),
    (r"Ring\s*Floodlight\s*Cam", "Ring Floodlight Cam", "ip_camera", "Ring OS"),
    (r"Ring\s*Indoor\s*Cam", "Ring Indoor Cam", "ip_camera", "Ring OS"),
    (r"Ring\s*Alarm", "Ring Alarm", "alarm_panel", "Ring OS"),

    # Blink
    (r"Blink\s*Outdoor", "Blink Outdoor Camera", "ip_camera", "Blink OS"),
    (r"Blink\s*Indoor", "Blink Indoor Camera", "ip_camera", "Blink OS"),
    (r"Blink\s*Mini", "Blink Mini Camera", "ip_camera", "Blink OS"),

    # eero (Amazon mesh WiFi system)
    # eero Max 7 Series (WiFi 7)
    (r"eero\s*Max\s*7", "eero Max 7", "mesh_router", "eeroOS"),

    # eero Pro Series
    (r"eero\s*Pro\s*6E", "eero Pro 6E", "mesh_router", "eeroOS"),
    (r"eero\s*Pro\s*6", "eero Pro 6", "mesh_router", "eeroOS"),
    (r"eero\s*Pro", "eero Pro", "mesh_router", "eeroOS"),

    # eero 6 Series (WiFi 6)
    (r"eero\s*6\+", "eero 6+", "mesh_router", "eeroOS"),
    (r"eero\s*6E", "eero 6E", "mesh_router", "eeroOS"),
    (r"eero\s*6", "eero 6", "mesh_router", "eeroOS"),

    # eero PoE Series
    (r"eero\s*PoE\s*6", "eero PoE 6", "mesh_router", "eeroOS"),
    (r"eero\s*PoE\s*Gateway", "eero PoE Gateway", "mesh_router", "eeroOS"),

    # eero Beacon (extenders)
    (r"eero\s*Beacon", "eero Beacon", "range_extender", "eeroOS"),

    # Generic eero
    (r"eero", "eero", "mesh_router", "eeroOS"),

    # Generic
    (r"Amazon", "Amazon Device", "smart_speaker", "Fire OS"),
]

GOOGLE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # All 101 Google, Inc. OUI prefixes (IEEE MA-L verified via maclookup.app)
    # Source: https://maclookup.app/vendors/google-inc
    # Default type: smart_home/IoT — hostname/mDNS/banner patterns refine this
    # Known device-specific OUIs (observed assignments)
    "00:1A:11": ("smart_speaker", "IoT", "Google Home"),
    "1C:F2:9A": ("smart_speaker", "IoT", "Google Home"),
    "20:DF:B9": ("smart_speaker", "IoT", "Google Nest"),
    "30:FD:38": ("smart_speaker", "IoT", "Google Home"),
    "44:07:0B": ("smart_speaker", "IoT", "Google"),  # Shared OUI: Nest WiFi, Chromecast, Home — let mDNS refine
    "48:D6:D5": ("smart_speaker", "IoT", "Google Home"),
    "54:60:09": ("router", "Network Equipment", "Google Wifi"),
    "94:EB:2C": ("smart_speaker", "IoT", "Google Home"),
    "A4:77:33": ("router", "Network Equipment", "Google Wifi"),
    "CC:F4:11": ("router", "Network Equipment", "Google Wifi"),
    "D8:6C:63": ("media_player", "Entertainment", "Chromecast"),
    "D8:EB:46": ("media_player", "Entertainment", "Chromecast"),
    "E4:F0:42": ("smart_speaker", "IoT", "Google Home"),
    "F4:F5:D8": ("router", "Network Equipment", "Google Wifi"),
    "F4:F5:E8": ("media_player", "Entertainment", "Chromecast"),
    "F8:0F:F9": ("smart_speaker", "IoT", "Google Nest/Home"),
    "BC:DF:58": ("smart_speaker", "IoT", "Google Nest/Home"),
    # Generic Google, Inc. OUIs — device type refined by other signals
    "00:F6:20": ("smart_home", "IoT", "Google Device"),
    "04:00:6E": ("smart_home", "IoT", "Google Device"),
    "04:C8:B0": ("smart_home", "IoT", "Google Device"),
    "08:8B:C8": ("smart_home", "IoT", "Google Device"),
    "08:9E:08": ("smart_home", "IoT", "Google Device"),
    "08:B4:B1": ("smart_home", "IoT", "Google Device"),
    "0C:C4:13": ("smart_home", "IoT", "Google Device"),
    "10:D9:A2": ("smart_home", "IoT", "Google Device"),
    "14:22:3B": ("smart_home", "IoT", "Google Device"),
    "14:C1:4E": ("smart_home", "IoT", "Google Device"),
    "1C:53:F9": ("smart_home", "IoT", "Google Device"),
    "20:1F:3B": ("smart_home", "IoT", "Google Device"),
    "20:33:89": ("smart_home", "IoT", "Google Device"),
    "20:F0:94": ("smart_home", "IoT", "Google Device"),
    "24:05:88": ("smart_home", "IoT", "Google Device"),
    "24:29:34": ("smart_home", "IoT", "Google Device"),
    "24:95:2F": ("smart_home", "IoT", "Google Device"),
    "24:E5:0F": ("smart_home", "IoT", "Google Device"),
    "28:BD:89": ("smart_home", "IoT", "Google Device"),
    "30:E0:44": ("smart_home", "IoT", "Google Device"),
    "34:39:16": ("smart_home", "IoT", "Google Device"),
    "34:C7:E9": ("smart_home", "IoT", "Google Device"),
    "38:86:F7": ("smart_home", "IoT", "Google Device"),
    "38:8B:59": ("smart_home", "IoT", "Google Device"),
    "3C:31:74": ("smart_home", "IoT", "Google Device"),
    "3C:5A:B4": ("smart_home", "IoT", "Google Device"),
    "3C:8D:20": ("smart_home", "IoT", "Google Device"),
    "40:A4:4A": ("smart_home", "IoT", "Google Device"),
    "44:10:30": ("smart_home", "IoT", "Google Device"),
    "44:BB:3B": ("smart_home", "IoT", "Google Device"),
    "54:67:49": ("smart_home", "IoT", "Google Device"),
    "58:24:29": ("smart_home", "IoT", "Google Device"),
    "5C:33:7B": ("smart_home", "IoT", "Google Device"),
    "60:70:6C": ("smart_home", "IoT", "Google Device"),
    "60:B7:6E": ("smart_home", "IoT", "Google Device"),
    "64:9D:38": ("smart_home", "IoT", "Google Device"),
    "70:3A:CB": ("smart_home", "IoT", "Google Device"),
    "74:74:46": ("smart_home", "IoT", "Google Device"),
    "7C:D9:5C": ("smart_home", "IoT", "Google Device"),
    "84:A8:24": ("smart_home", "IoT", "Google Device"),
    "88:3D:24": ("smart_home", "IoT", "Google Device"),
    "88:54:1F": ("smart_home", "IoT", "Google Device"),
    "90:0C:C8": ("smart_home", "IoT", "Google Device"),
    "90:CA:FA": ("smart_home", "IoT", "Google Device"),
    "94:45:60": ("smart_home", "IoT", "Google Device"),
    "94:95:A0": ("smart_home", "IoT", "Google Device"),
    "98:3A:1F": ("smart_home", "IoT", "Google Device"),
    "98:98:FB": ("smart_home", "IoT", "Google Device"),
    "98:D2:93": ("smart_home", "IoT", "Google Device"),
    "9C:4F:5F": ("smart_home", "IoT", "Google Device"),
    "AC:3E:B1": ("smart_home", "IoT", "Google Device"),
    "AC:67:84": ("smart_home", "IoT", "Google Device"),
    "AC:E6:BB": ("smart_home", "IoT", "Google Device"),
    "B0:2A:43": ("smart_home", "IoT", "Google Device"),
    "B0:6A:41": ("smart_home", "IoT", "Google Device"),
    "B0:D5:FB": ("smart_home", "IoT", "Google Device"),
    "B0:E4:D5": ("smart_home", "IoT", "Google Device"),
    "B4:13:24": ("smart_home", "IoT", "Google Device"),
    "B4:23:A2": ("smart_home", "IoT", "Google Device"),
    "B8:7B:D4": ("smart_home", "IoT", "Google Device"),
    "B8:DB:38": ("smart_home", "IoT", "Google Device"),
    "B8:F4:A4": ("smart_home", "IoT", "Google Device"),
    "C0:1C:6A": ("smart_home", "IoT", "Google Device"),
    "C8:2A:DD": ("smart_home", "IoT", "Google Device"),
    "CC:A7:C1": ("smart_home", "IoT", "Google Device"),
    "D4:3A:2C": ("smart_home", "IoT", "Google Device"),
    "D8:8C:79": ("smart_home", "IoT", "Google Device"),
    "DA:A1:19": ("smart_home", "IoT", "Google Device"),
    "E0:1A:DF": ("smart_home", "IoT", "Google Device"),
    "E4:5E:1B": ("smart_home", "IoT", "Google Device"),
    "E8:D5:2B": ("smart_home", "IoT", "Google Device"),
    "F0:5C:77": ("smart_home", "IoT", "Google Device"),
    "F0:72:EA": ("smart_home", "IoT", "Google Device"),
    "F0:EF:86": ("smart_home", "IoT", "Google Device"),
    "F4:03:04": ("smart_home", "IoT", "Google Device"),
    "F8:1A:2B": ("smart_home", "IoT", "Google Device"),
    "FC:41:16": ("smart_home", "IoT", "Google Device"),
    "FC:91:5D": ("smart_home", "IoT", "Google Device"),
    # Nest Labs Inc. OUIs (IEEE verified — Google subsidiary)
    # Source: https://maclookup.app/vendors/nest-labs-inc
    "18:B4:30": ("smart_home", "IoT", "Nest Device"),
    "64:16:66": ("thermostat", "HVAC", "Nest Thermostat"),
    # Google Chromecast OUI (separate IEEE registration as "Google Chromecast")
    # Source: https://aruljohn.com/mac/FA8FCA
    "FA:8F:CA": ("media_player", "Entertainment", "Chromecast"),
    "F8:8F:CA": ("media_player", "Entertainment", "Chromecast"),
}

GOOGLE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Google Home / Nest speakers
    (r"Google\s*Nest\s*Hub\s*Max", "Google Nest Hub Max", "smart_display", "Cast OS"),
    (r"Google\s*Nest\s*Hub", "Google Nest Hub", "smart_display", "Cast OS"),
    (r"Google\s*Nest\s*Audio", "Google Nest Audio", "smart_speaker", "Cast OS"),
    (r"Google\s*Nest\s*Mini", "Google Nest Mini", "smart_speaker", "Cast OS"),
    (r"Google\s*Home\s*Max", "Google Home Max", "smart_speaker", "Cast OS"),
    (r"Google\s*Home\s*Mini", "Google Home Mini", "smart_speaker", "Cast OS"),
    (r"Google\s*Home", "Google Home", "smart_speaker", "Cast OS"),

    # Chromecast
    (r"Chromecast\s*with\s*Google\s*TV\s*4K", "Chromecast with Google TV 4K", "media_player", "Google TV"),
    (r"Chromecast\s*with\s*Google\s*TV", "Chromecast with Google TV", "media_player", "Google TV"),
    (r"Chromecast\s*Ultra", "Chromecast Ultra", "media_player", "Cast OS"),
    (r"Chromecast", "Chromecast", "media_player", "Cast OS"),

    # Nest WiFi / Google WiFi
    (r"Nest\s*Wifi\s*Pro", "Google Nest Wifi Pro", "router", "Google WiFi"),
    (r"Nest\s*Wifi", "Google Nest Wifi", "router", "Google WiFi"),
    (r"Google\s*Wifi", "Google Wifi", "router", "Google WiFi"),

    # Nest cameras
    (r"Nest\s*Cam\s*Outdoor", "Google Nest Cam Outdoor", "ip_camera", "Nest OS"),
    (r"Nest\s*Cam\s*Indoor", "Google Nest Cam Indoor", "ip_camera", "Nest OS"),
    (r"Nest\s*Cam\s*with\s*Floodlight", "Google Nest Cam Floodlight", "ip_camera", "Nest OS"),
    (r"Nest\s*Cam", "Google Nest Cam", "ip_camera", "Nest OS"),

    # Nest Doorbell
    (r"Nest\s*Doorbell", "Google Nest Doorbell", "doorbell", "Nest OS"),

    # Nest Thermostat
    (r"Nest\s*Learning\s*Thermostat", "Nest Learning Thermostat", "thermostat", "Nest OS"),
    (r"Nest\s*Thermostat", "Nest Thermostat", "thermostat", "Nest OS"),

    # Nest Protect
    (r"Nest\s*Protect", "Nest Protect", "smoke_detector", "Nest OS"),

    # Pixel phones
    (r"Pixel\s*8\s*Pro", "Google Pixel 8 Pro", "phone", "Android"),
    (r"Pixel\s*8a", "Google Pixel 8a", "phone", "Android"),
    (r"Pixel\s*8", "Google Pixel 8", "phone", "Android"),
    (r"Pixel\s*7", "Google Pixel 7", "phone", "Android"),
    (r"Pixel\s*\d", "Google Pixel", "phone", "Android"),

    # Generic
    (r"Google", "Google Device", "smart_speaker", "Cast OS"),
]


# SONOS AUDIO PATTERNS

SONOS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0E:58": ("smart_speaker", "Audio", "Sonos Speaker"),
    "34:7E:5C": ("smart_speaker", "Audio", "Sonos Speaker"),
    "48:A6:B8": ("smart_speaker", "Audio", "Sonos Speaker"),
    # REMOVED: 5C:AA:FD - IEEE assigns to Unknown, not SONOS
    "78:28:CA": ("smart_speaker", "Audio", "Sonos Speaker"),
    "94:9F:3E": ("smart_speaker", "Audio", "Sonos Speaker"),
    "B8:E9:37": ("smart_speaker", "Audio", "Sonos Speaker"),
    "F0:F6:C1": ("smart_speaker", "Audio", "Sonos Speaker"),
    "54:2A:1B": ("smart_speaker", "Audio", "Sonos Speaker"),
    # Additional Sonos OUIs
    "38:42:0B": ("smart_speaker", "Audio", "Sonos Speaker"),
    "40:9E:90": ("smart_speaker", "Audio", "Sonos Speaker"),
    "5C:AA:FD": ("smart_speaker", "Audio", "Sonos Speaker"),
    "A8:7E:E0": ("smart_speaker", "Audio", "Sonos Speaker"),
    "C4:38:8B": ("smart_speaker", "Audio", "Sonos Speaker"),
}

SONOS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Sonos speakers
    (r"Sonos\s*Era\s*300", "Sonos Era 300", "smart_speaker", "Sonos S2"),
    (r"Sonos\s*Era\s*100", "Sonos Era 100", "smart_speaker", "Sonos S2"),
    (r"Sonos\s*Move\s*2", "Sonos Move 2", "portable_speaker", "Sonos S2"),
    (r"Sonos\s*Move", "Sonos Move", "portable_speaker", "Sonos S2"),
    (r"Sonos\s*Roam\s*SL", "Sonos Roam SL", "portable_speaker", "Sonos S2"),
    (r"Sonos\s*Roam", "Sonos Roam", "portable_speaker", "Sonos S2"),
    (r"Sonos\s*One\s*SL", "Sonos One SL", "smart_speaker", "Sonos S2"),
    (r"Sonos\s*One", "Sonos One", "smart_speaker", "Sonos S2"),
    (r"Sonos\s*Five", "Sonos Five", "smart_speaker", "Sonos S2"),
    (r"Sonos\s*Play:5", "Sonos Play:5", "smart_speaker", "Sonos S2"),
    (r"Sonos\s*Play:3", "Sonos Play:3", "smart_speaker", "Sonos S1"),
    (r"Sonos\s*Play:1", "Sonos Play:1", "smart_speaker", "Sonos S1"),
    (r"Sonos\s*Port", "Sonos Port", "audio_streamer", "Sonos S2"),
    (r"Sonos\s*Amp", "Sonos Amp", "amplifier", "Sonos S2"),
    (r"Sonos\s*Connect:Amp", "Sonos Connect:Amp", "amplifier", "Sonos S1"),
    (r"Sonos\s*Connect", "Sonos Connect", "audio_streamer", "Sonos S1"),

    # Soundbars
    (r"Sonos\s*Arc", "Sonos Arc", "soundbar", "Sonos S2"),
    (r"Sonos\s*Beam\s*Gen\s*2", "Sonos Beam Gen 2", "soundbar", "Sonos S2"),
    (r"Sonos\s*Beam", "Sonos Beam", "soundbar", "Sonos S2"),
    (r"Sonos\s*Ray", "Sonos Ray", "soundbar", "Sonos S2"),
    (r"Sonos\s*Playbar", "Sonos Playbar", "soundbar", "Sonos S1"),
    (r"Sonos\s*Playbase", "Sonos Playbase", "soundbar", "Sonos S1"),

    # Subwoofers
    (r"Sonos\s*Sub\s*Mini", "Sonos Sub Mini", "subwoofer", "Sonos S2"),
    (r"Sonos\s*Sub", "Sonos Sub", "subwoofer", "Sonos S2"),

    # Generic
    (r"Sonos", "Sonos Device", "smart_speaker", "Sonos S2"),
]


# ROKU / STREAMING DEVICE PATTERNS

ROKU_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0D:4B": ("media_player", "Entertainment", "Roku"),
    "08:05:81": ("media_player", "Entertainment", "Roku"),
    "10:59:32": ("media_player", "Entertainment", "Roku"),
    "20:EF:BD": ("media_player", "Entertainment", "Roku"),
    "84:EA:ED": ("media_player", "Entertainment", "Roku"),
    "AC:3A:7A": ("media_player", "Entertainment", "Roku"),
    "B0:A7:37": ("media_player", "Entertainment", "Roku"),
    "B8:3E:59": ("media_player", "Entertainment", "Roku"),
    "C8:3A:6B": ("media_player", "Entertainment", "Roku"),
    "D0:4D:2C": ("media_player", "Entertainment", "Roku"),
    "DC:3A:5E": ("media_player", "Entertainment", "Roku"),
}

ROKU_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Roku streaming sticks
    (r"Roku\s*Streaming\s*Stick\s*4K\+", "Roku Streaming Stick 4K+", "media_player", "Roku OS"),
    (r"Roku\s*Streaming\s*Stick\s*4K", "Roku Streaming Stick 4K", "media_player", "Roku OS"),
    (r"Roku\s*Streaming\s*Stick\+", "Roku Streaming Stick+", "media_player", "Roku OS"),
    (r"Roku\s*Streaming\s*Stick", "Roku Streaming Stick", "media_player", "Roku OS"),

    # Roku Express
    (r"Roku\s*Express\s*4K\+", "Roku Express 4K+", "media_player", "Roku OS"),
    (r"Roku\s*Express\s*4K", "Roku Express 4K", "media_player", "Roku OS"),
    (r"Roku\s*Express", "Roku Express", "media_player", "Roku OS"),

    # Roku Ultra
    (r"Roku\s*Ultra", "Roku Ultra", "media_player", "Roku OS"),

    # Roku TVs
    (r"Roku\s*TV", "Roku TV", "tv", "Roku OS"),
    (r"TCL\s*Roku\s*TV", "TCL Roku TV", "tv", "Roku OS"),
    (r"Hisense\s*Roku\s*TV", "Hisense Roku TV", "tv", "Roku OS"),
    (r"Sharp\s*Roku\s*TV", "Sharp Roku TV", "tv", "Roku OS"),

    # Roku Soundbar
    (r"Roku\s*Streambar\s*Pro", "Roku Streambar Pro", "soundbar", "Roku OS"),
    (r"Roku\s*Streambar", "Roku Streambar", "soundbar", "Roku OS"),
    (r"Roku\s*Smart\s*Soundbar", "Roku Smart Soundbar", "soundbar", "Roku OS"),

    # Generic
    (r"Roku", "Roku Device", "media_player", "Roku OS"),
]


# PHILIPS HUE / SIGNIFY PATTERNS

PHILIPS_HUE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:17:88": ("iot_hub", "Smart Home", "Philips Hue Bridge"),
    "EC:B5:FA": ("iot_hub", "Smart Home", "Philips Hue Bridge"),
}

PHILIPS_HUE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Hue Bridge
    (r"Hue\s*Bridge\s*v2", "Philips Hue Bridge v2", "iot_hub", "Hue"),
    (r"Hue\s*Bridge", "Philips Hue Bridge", "iot_hub", "Hue"),
    (r"BSB002", "Philips Hue Bridge v2", "iot_hub", "Hue"),
    (r"BSB001", "Philips Hue Bridge v1", "iot_hub", "Hue"),

    # Hue bulbs/lights
    (r"Hue\s*White\s*and\s*Color", "Philips Hue White and Color", "smart_light", "Hue"),
    (r"Hue\s*White\s*Ambiance", "Philips Hue White Ambiance", "smart_light", "Hue"),
    (r"Hue\s*White", "Philips Hue White", "smart_light", "Hue"),
    (r"Hue\s*Lightstrip", "Philips Hue Lightstrip", "smart_light", "Hue"),
    (r"Hue\s*Play", "Philips Hue Play", "smart_light", "Hue"),
    (r"Hue\s*Go", "Philips Hue Go", "smart_light", "Hue"),
    (r"Hue\s*Bloom", "Philips Hue Bloom", "smart_light", "Hue"),

    # Accessories
    (r"Hue\s*Dimmer", "Philips Hue Dimmer Switch", "smart_switch", "Hue"),
    (r"Hue\s*Motion", "Philips Hue Motion Sensor", "motion_sensor", "Hue"),
    (r"Hue\s*Tap", "Philips Hue Tap", "smart_switch", "Hue"),

    # Generic
    (r"Philips\s*Hue", "Philips Hue Device", "smart_light", "Hue"),
    (r"Signify", "Signify Device", "smart_light", "Hue"),
]


# WYZE / SMART HOME PATTERNS

WYZE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "2C:AA:8E": ("ip_camera", "Surveillance", "Wyze Cam"),
    "D0:3F:27": ("ip_camera", "Surveillance", "Wyze Cam"),
    "7C:78:B2": ("ip_camera", "Surveillance", "Wyze Cam"),
    "A4:DA:22": ("ip_camera", "Surveillance", "Wyze Cam"),
}

WYZE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Cameras
    (r"Wyze\s*Cam\s*v3\s*Pro", "Wyze Cam v3 Pro", "ip_camera", "Wyze"),
    (r"Wyze\s*Cam\s*v3", "Wyze Cam v3", "ip_camera", "Wyze"),
    (r"Wyze\s*Cam\s*v2", "Wyze Cam v2", "ip_camera", "Wyze"),
    (r"Wyze\s*Cam\s*Pan\s*v3", "Wyze Cam Pan v3", "ptz_camera", "Wyze"),
    (r"Wyze\s*Cam\s*Pan\s*v2", "Wyze Cam Pan v2", "ptz_camera", "Wyze"),
    (r"Wyze\s*Cam\s*Pan", "Wyze Cam Pan", "ptz_camera", "Wyze"),
    (r"Wyze\s*Cam\s*Outdoor", "Wyze Cam Outdoor", "ip_camera", "Wyze"),
    (r"Wyze\s*Cam\s*Floodlight", "Wyze Cam Floodlight", "ip_camera", "Wyze"),
    (r"Wyze\s*Video\s*Doorbell", "Wyze Video Doorbell", "doorbell", "Wyze"),

    # Smart home
    (r"Wyze\s*Lock", "Wyze Lock", "smart_lock", "Wyze"),
    (r"Wyze\s*Plug", "Wyze Plug", "smart_plug", "Wyze"),
    (r"Wyze\s*Bulb", "Wyze Bulb", "smart_light", "Wyze"),
    (r"Wyze\s*Thermostat", "Wyze Thermostat", "thermostat", "Wyze"),
    (r"Wyze\s*Sensor", "Wyze Sensor", "sensor", "Wyze"),
    (r"Wyze\s*Vacuum", "Wyze Robot Vacuum", "vacuum", "Wyze"),
    (r"Wyze\s*Watch", "Wyze Watch", "wearable", "Wyze"),

    # Generic
    (r"Wyze", "Wyze Device", "ip_camera", "Wyze"),
]


# CANON / EPSON / BROTHER PRINTER PATTERNS

CANON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:85": ("printer", "Printer", "Canon Printer"),
    "00:1E:8F": ("printer", "Printer", "Canon Printer"),
    "00:BB:C1": ("printer", "Printer", "Canon Printer"),
    "18:0C:AC": ("printer", "Printer", "Canon Printer"),
    "1C:B0:72": ("printer", "Printer", "Canon Printer"),
    "88:87:17": ("printer", "Printer", "Canon Printer"),
    # REMOVED: C4:AD:34 - IEEE assigns to Unknown, not CANON
    "EC:DF:36": ("printer", "Printer", "Canon Printer"),
    "F4:81:39": ("printer", "Printer", "Canon Printer"),
}

CANON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # imageCLASS (Laser)
    (r"imageCLASS\s*MF\d+", "Canon imageCLASS MFP", "mfp", "Canon"),
    (r"imageCLASS\s*LBP\d+", "Canon imageCLASS Laser", "laser_printer", "Canon"),
    (r"i-SENSYS\s*MF\d+", "Canon i-SENSYS MFP", "mfp", "Canon"),
    (r"i-SENSYS\s*LBP\d+", "Canon i-SENSYS Laser", "laser_printer", "Canon"),

    # PIXMA (Inkjet)
    (r"PIXMA\s*TS\d+", "Canon PIXMA TS Series", "inkjet_printer", "Canon"),
    (r"PIXMA\s*TR\d+", "Canon PIXMA TR Series", "inkjet_printer", "Canon"),
    (r"PIXMA\s*G\d+", "Canon PIXMA G MegaTank", "inkjet_printer", "Canon"),
    (r"PIXMA\s*MG\d+", "Canon PIXMA MG Series", "inkjet_printer", "Canon"),
    (r"PIXMA\s*MX\d+", "Canon PIXMA MX Series", "mfp", "Canon"),
    (r"PIXMA\s*PRO-\d+", "Canon PIXMA PRO", "photo_printer", "Canon"),

    # imageRUNNER (Enterprise)
    (r"imageRUNNER\s*ADVANCE\s*DX", "Canon imageRUNNER ADVANCE DX", "mfp", "Canon"),
    (r"imageRUNNER\s*ADVANCE", "Canon imageRUNNER ADVANCE", "mfp", "Canon"),
    (r"imageRUNNER", "Canon imageRUNNER", "mfp", "Canon"),
    (r"iR-ADV", "Canon imageRUNNER ADVANCE", "mfp", "Canon"),
    (r"iR\s*\d+", "Canon imageRUNNER", "mfp", "Canon"),

    # imagePROGRAF (Large format)
    (r"imagePROGRAF\s*PRO-\d+", "Canon imagePROGRAF PRO", "large_format_printer", "Canon"),
    (r"imagePROGRAF\s*TX-\d+", "Canon imagePROGRAF TX", "large_format_printer", "Canon"),
    (r"imagePROGRAF", "Canon imagePROGRAF", "large_format_printer", "Canon"),

    # Generic
    (r"Canon\s*Printer", "Canon Printer", "printer", "Canon"),
    (r"Canon", "Canon Device", "printer", "Canon"),
]

EPSON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:48": ("printer", "Printer", "Epson Printer"),
    "00:26:AB": ("printer", "Printer", "Epson Printer"),
    "04:59:62": ("printer", "Printer", "Epson Printer"),
    "44:D2:44": ("printer", "Printer", "Epson Printer"),
    "64:EB:8C": ("printer", "Printer", "Epson Printer"),
    "7C:BD:FD": ("printer", "Printer", "Epson Printer"),
    "A4:EE:57": ("printer", "Printer", "Epson Printer"),
    "AC:18:26": ("printer", "Printer", "Epson Printer"),
    "B0:E8:92": ("printer", "Printer", "Epson Printer"),
}

EPSON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # EcoTank
    (r"EcoTank\s*ET-\d+", "Epson EcoTank", "inkjet_printer", "Epson"),
    (r"ET-\d{4}", "Epson EcoTank", "inkjet_printer", "Epson"),
    (r"L\d{4}", "Epson EcoTank", "inkjet_printer", "Epson"),

    # Expression
    (r"Expression\s*Photo\s*XP-\d+", "Epson Expression Photo", "photo_printer", "Epson"),
    (r"Expression\s*Premium\s*XP-\d+", "Epson Expression Premium", "inkjet_printer", "Epson"),
    (r"Expression\s*Home\s*XP-\d+", "Epson Expression Home", "inkjet_printer", "Epson"),
    (r"XP-\d+", "Epson Expression", "inkjet_printer", "Epson"),

    # WorkForce
    (r"WorkForce\s*Pro\s*WF-\d+", "Epson WorkForce Pro", "mfp", "Epson"),
    (r"WorkForce\s*WF-\d+", "Epson WorkForce", "mfp", "Epson"),
    (r"WF-\d+", "Epson WorkForce", "mfp", "Epson"),
    (r"WorkForce\s*Enterprise", "Epson WorkForce Enterprise", "mfp", "Epson"),

    # SureColor (Large format)
    (r"SureColor\s*P\d+", "Epson SureColor P", "large_format_printer", "Epson"),
    (r"SureColor\s*T\d+", "Epson SureColor T", "large_format_printer", "Epson"),
    (r"SureColor\s*F\d+", "Epson SureColor F", "large_format_printer", "Epson"),
    (r"SureColor\s*S\d+", "Epson SureColor S", "large_format_printer", "Epson"),

    # Projectors
    (r"EB-\d+", "Epson Projector", "projector", "Epson"),
    (r"EH-\d+", "Epson Home Cinema Projector", "projector", "Epson"),
    (r"Pro\s*L\d+", "Epson Pro Laser Projector", "projector", "Epson"),

    # Generic
    (r"EPSON", "Epson Device", "printer", "Epson"),
    (r"Epson", "Epson Device", "printer", "Epson"),
]

BROTHER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1B:A9 - IEEE assigns to Unknown, not BROTHER
    "00:80:77": ("printer", "Printer", "Brother Printer"),
    "30:05:5C": ("printer", "Printer", "Brother Printer"),
    "D4:B1:93": ("printer", "Printer", "Brother Printer"),
}

BROTHER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # MFC (Multi-Function Center)
    (r"MFC-L\d+", "Brother MFC Laser", "mfp", "Brother"),
    (r"MFC-J\d+", "Brother MFC Inkjet", "mfp", "Brother"),
    (r"MFC-\d+", "Brother MFC", "mfp", "Brother"),

    # HL (Laser printers)
    (r"HL-L\d+", "Brother HL Laser", "laser_printer", "Brother"),
    (r"HL-\d+", "Brother HL", "laser_printer", "Brother"),

    # DCP (Digital Copier/Printer)
    (r"DCP-L\d+", "Brother DCP Laser", "mfp", "Brother"),
    (r"DCP-J\d+", "Brother DCP Inkjet", "mfp", "Brother"),
    (r"DCP-\d+", "Brother DCP", "mfp", "Brother"),

    # INKvestment
    (r"INKvestment\s*Tank", "Brother INKvestment Tank", "inkjet_printer", "Brother"),

    # Label printers
    (r"QL-\d+", "Brother QL Label Printer", "label_printer", "Brother"),
    (r"PT-\d+", "Brother P-touch", "label_printer", "Brother"),
    (r"TD-\d+", "Brother TD Label Printer", "label_printer", "Brother"),
    (r"RJ-\d+", "Brother RJ Mobile Printer", "mobile_printer", "Brother"),

    # ADS (Scanners)
    (r"ADS-\d+", "Brother ADS Scanner", "scanner", "Brother"),

    # Generic
    (r"Brother", "Brother Device", "printer", "Brother"),
]

HP_PRINTER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:01:E6": ("printer", "Printer", "HP Printer"),
    # REMOVED: 00:0B:CD - IEEE assigns to Unknown, not HP_PRINTER
    "00:0F:61": ("printer", "Printer", "HP Printer"),
    "00:10:83": ("printer", "Printer", "HP Printer"),
    # REMOVED: 00:11:0A - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:12:79 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:14:38 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:17:A4 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:1A:4B - IEEE assigns to Unknown, not HP_PRINTER
    "00:1C:C4": ("printer", "Printer", "HP Printer"),
    # REMOVED: 00:1E:0B - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:21:5A - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:22:64 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:23:7D - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:24:81 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:25:B3 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 00:26:55 - IEEE assigns to Unknown, not HP_PRINTER
    "10:60:4B": ("printer", "Printer", "HP Printer"),
    "18:A9:05": ("printer", "Printer", "HP Printer"),
    "28:92:4A": ("printer", "Printer", "HP Printer"),
    # REMOVED: 38:63:BB - IEEE assigns to Unknown, not HP_PRINTER
    "40:B0:34": ("printer", "Printer", "HP Printer"),
    "58:20:B1": ("printer", "Printer", "HP Printer"),
    "68:B5:99": ("printer", "Printer", "HP Printer"),
    # REMOVED: 80:CE:62 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 94:57:A5 - IEEE assigns to Unknown, not HP_PRINTER
    # REMOVED: 98:E7:F5 - IEEE assigns to Huawei Technologies, not HP
    # REMOVED: A0:1D:48 - IEEE assigns to Unknown, not HP_PRINTER
    "C8:D3:FF": ("printer", "Printer", "HP Printer"),
    "D4:85:64": ("printer", "Printer", "HP Printer"),
    # REMOVED: EC:B1:D7 - IEEE assigns to Unknown, not HP_PRINTER
}

HP_PRINTER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # LaserJet
    (r"LaserJet\s*Pro\s*MFP\s*M\d+", "HP LaserJet Pro MFP", "mfp", "HP"),
    (r"LaserJet\s*Pro\s*M\d+", "HP LaserJet Pro", "laser_printer", "HP"),
    (r"LaserJet\s*Enterprise\s*MFP\s*M\d+", "HP LaserJet Enterprise MFP", "mfp", "HP"),
    (r"LaserJet\s*Enterprise\s*M\d+", "HP LaserJet Enterprise", "laser_printer", "HP"),
    (r"LaserJet\s*MFP\s*M\d+", "HP LaserJet MFP", "mfp", "HP"),
    (r"LaserJet\s*M\d+", "HP LaserJet", "laser_printer", "HP"),
    (r"Color\s*LaserJet", "HP Color LaserJet", "laser_printer", "HP"),
    (r"LaserJet", "HP LaserJet", "laser_printer", "HP"),

    # OfficeJet
    (r"OfficeJet\s*Pro\s*\d+", "HP OfficeJet Pro", "mfp", "HP"),
    (r"OfficeJet\s*\d+", "HP OfficeJet", "inkjet_printer", "HP"),

    # ENVY
    (r"ENVY\s*Photo\s*\d+", "HP ENVY Photo", "photo_printer", "HP"),
    (r"ENVY\s*Inspire\s*\d+", "HP ENVY Inspire", "inkjet_printer", "HP"),
    (r"ENVY\s*\d+", "HP ENVY", "inkjet_printer", "HP"),

    # DeskJet
    (r"DeskJet\s*Plus\s*\d+", "HP DeskJet Plus", "inkjet_printer", "HP"),
    (r"DeskJet\s*\d+", "HP DeskJet", "inkjet_printer", "HP"),

    # Smart Tank
    (r"Smart\s*Tank\s*Plus\s*\d+", "HP Smart Tank Plus", "inkjet_printer", "HP"),
    (r"Smart\s*Tank\s*\d+", "HP Smart Tank", "inkjet_printer", "HP"),

    # DesignJet (Large format)
    (r"DesignJet\s*Z\d+", "HP DesignJet Z", "large_format_printer", "HP"),
    (r"DesignJet\s*T\d+", "HP DesignJet T", "large_format_printer", "HP"),
    (r"DesignJet", "HP DesignJet", "large_format_printer", "HP"),

    # PageWide
    (r"PageWide\s*Pro\s*\d+", "HP PageWide Pro", "mfp", "HP"),
    (r"PageWide\s*Enterprise", "HP PageWide Enterprise", "mfp", "HP"),
    (r"PageWide", "HP PageWide", "printer", "HP"),

    # Generic
    (r"HP\s*Printer", "HP Printer", "printer", "HP"),
]

# XEROX PRINTER PATTERNS

XEROX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:AA": ("printer", "Printer", "Xerox"),
    "00:00:74": ("printer", "Printer", "Xerox"),
    "00:04:B5": ("printer", "Printer", "Xerox"),
    "08:00:37": ("printer", "Printer", "Xerox"),
}

XEROX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # VersaLink Series
    (r"VersaLink\s*C[4-9]\d{2}", "Xerox VersaLink C-Series", "mfp", "Xerox"),
    (r"VersaLink\s*B[4-9]\d{2}", "Xerox VersaLink B-Series", "mfp", "Xerox"),
    (r"VersaLink", "Xerox VersaLink", "mfp", "Xerox"),
    # AltaLink Series
    (r"AltaLink\s*C\d{4}", "Xerox AltaLink C-Series", "mfp", "Xerox"),
    (r"AltaLink\s*B\d{4}", "Xerox AltaLink B-Series", "mfp", "Xerox"),
    (r"AltaLink", "Xerox AltaLink", "mfp", "Xerox"),
    # PrimeLink Series
    (r"PrimeLink\s*C\d{4}", "Xerox PrimeLink", "mfp", "Xerox"),
    (r"PrimeLink", "Xerox PrimeLink", "mfp", "Xerox"),
    # WorkCentre
    (r"WorkCentre\s*\d{4}", "Xerox WorkCentre", "mfp", "Xerox"),
    # Phaser
    (r"Phaser\s*\d{4}", "Xerox Phaser", "printer", "Xerox"),
    # Generic
    (r"Xerox", "Xerox Printer", "printer", "Xerox"),
]

# LEXMARK PRINTER PATTERNS

LEXMARK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:04:00": ("printer", "Printer", "Lexmark"),
    "00:20:00": ("printer", "Printer", "Lexmark"),
    "00:21:B7": ("printer", "Printer", "Lexmark"),
}

LEXMARK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # CX Series (Color MFP)
    (r"CX\d{3}", "Lexmark CX Series", "mfp", "Lexmark"),
    # CS Series (Color)
    (r"CS\d{3}", "Lexmark CS Series", "printer", "Lexmark"),
    # MX Series (Mono MFP)
    (r"MX\d{3}", "Lexmark MX Series", "mfp", "Lexmark"),
    # MS Series (Mono)
    (r"MS\d{3}", "Lexmark MS Series", "printer", "Lexmark"),
    # XC/XM (Enterprise)
    (r"XC\d{4}", "Lexmark XC Series", "mfp", "Lexmark"),
    (r"XM\d{4}", "Lexmark XM Series", "mfp", "Lexmark"),
    # Generic
    (r"Lexmark", "Lexmark Printer", "printer", "Lexmark"),
]

# KYOCERA PRINTER PATTERNS

KYOCERA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:C0:EE": ("printer", "Printer", "Kyocera"),
    "00:17:C8": ("printer", "Printer", "Kyocera"),
}

KYOCERA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ECOSYS (Laser)
    (r"ECOSYS\s*P\d{4}", "Kyocera ECOSYS P", "printer", "Kyocera"),
    (r"ECOSYS\s*M\d{4}", "Kyocera ECOSYS M", "mfp", "Kyocera"),
    (r"ECOSYS", "Kyocera ECOSYS", "printer", "Kyocera"),
    # TASKalfa (Enterprise)
    (r"TASKalfa\s*\d{3,4}[ci]+", "Kyocera TASKalfa", "mfp", "Kyocera"),
    (r"TASKalfa", "Kyocera TASKalfa", "mfp", "Kyocera"),
    # Generic
    (r"Kyocera", "Kyocera Printer", "printer", "Kyocera"),
]

# RICOH PRINTER PATTERNS

RICOH_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:00:74 - IEEE assigns to Unknown, not RICOH
    "00:26:73": ("printer", "Printer", "Ricoh"),
    "58:38:79": ("printer", "Printer", "Ricoh"),
}

RICOH_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # IM Series
    (r"IM\s*C\d{4}", "Ricoh IM C Series", "mfp", "Ricoh"),
    (r"IM\s*\d{3,4}", "Ricoh IM Series", "mfp", "Ricoh"),
    # MP Series
    (r"MP\s*C\d{4}", "Ricoh MP C Series", "mfp", "Ricoh"),
    (r"MP\s*\d{4}", "Ricoh MP Series", "mfp", "Ricoh"),
    # SP Series (Desktop)
    (r"SP\s*C\d{3}", "Ricoh SP C Series", "printer", "Ricoh"),
    (r"SP\s*\d{3}", "Ricoh SP Series", "printer", "Ricoh"),
    # Pro Series (Production)
    (r"Pro\s*C\d{4}", "Ricoh Pro C Series", "production_printer", "Ricoh"),
    # Generic
    (r"Ricoh", "Ricoh Printer", "printer", "Ricoh"),
]

# KONICA MINOLTA PRINTER PATTERNS

KONICA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1E:8F - IEEE assigns to Unknown, not KONICA
    "00:50:AA": ("printer", "Printer", "Konica Minolta"),
}

KONICA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # bizhub Series
    (r"bizhub\s*C\d{3,4}", "Konica Minolta bizhub C", "mfp", "Konica Minolta"),
    (r"bizhub\s*\d{3,4}", "Konica Minolta bizhub", "mfp", "Konica Minolta"),
    (r"bizhub", "Konica Minolta bizhub", "mfp", "Konica Minolta"),
    # AccurioPress (Production)
    (r"AccurioPress\s*C\d{4}", "Konica Minolta AccurioPress", "production_printer", "Konica Minolta"),
    (r"AccurioPress", "Konica Minolta AccurioPress", "production_printer", "Konica Minolta"),
    # Generic
    (r"Konica\s*Minolta", "Konica Minolta", "printer", "Konica Minolta"),
]


# POLYCOM / YEALINK VOIP PATTERNS

POLYCOM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:04:F2": ("voip_phone", "VoIP", "Polycom Phone"),
    "00:E0:DB": ("voip_phone", "VoIP", "Polycom Phone"),
    "64:16:7F": ("voip_phone", "VoIP", "Polycom Phone"),
    # REMOVED: 00:90:FB - IEEE assigns to Unknown, not POLYCOM
}

POLYCOM_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # VVX Series (IP Phones)
    (r"VVX\s*601", "Polycom VVX 601", "voip_phone", "Polycom UC"),
    (r"VVX\s*501", "Polycom VVX 501", "voip_phone", "Polycom UC"),
    (r"VVX\s*450", "Polycom VVX 450", "voip_phone", "Polycom UC"),
    (r"VVX\s*411", "Polycom VVX 411", "voip_phone", "Polycom UC"),
    (r"VVX\s*401", "Polycom VVX 401", "voip_phone", "Polycom UC"),
    (r"VVX\s*350", "Polycom VVX 350", "voip_phone", "Polycom UC"),
    (r"VVX\s*311", "Polycom VVX 311", "voip_phone", "Polycom UC"),
    (r"VVX\s*301", "Polycom VVX 301", "voip_phone", "Polycom UC"),
    (r"VVX\s*250", "Polycom VVX 250", "voip_phone", "Polycom UC"),
    (r"VVX\s*201", "Polycom VVX 201", "voip_phone", "Polycom UC"),
    (r"VVX\s*\d+", "Polycom VVX", "voip_phone", "Polycom UC"),

    # CCX Series (Teams/Zoom phones)
    (r"CCX\s*700", "Polycom CCX 700", "voip_phone", "Polycom UC"),
    (r"CCX\s*600", "Polycom CCX 600", "voip_phone", "Polycom UC"),
    (r"CCX\s*500", "Polycom CCX 500", "voip_phone", "Polycom UC"),
    (r"CCX\s*400", "Polycom CCX 400", "voip_phone", "Polycom UC"),
    (r"CCX\s*\d+", "Polycom CCX", "voip_phone", "Polycom UC"),

    # Trio (Conference phones)
    (r"Trio\s*C60", "Polycom Trio C60", "conference_phone", "Polycom UC"),
    (r"Trio\s*8800", "Polycom Trio 8800", "conference_phone", "Polycom UC"),
    (r"Trio\s*8500", "Polycom Trio 8500", "conference_phone", "Polycom UC"),
    (r"Trio\s*8300", "Polycom Trio 8300", "conference_phone", "Polycom UC"),
    (r"Trio\s*\d+", "Polycom Trio", "conference_phone", "Polycom UC"),

    # Video conferencing
    (r"RealPresence\s*Group\s*\d+", "Polycom RealPresence Group", "video_conference", "Polycom"),
    (r"RealPresence\s*Debut", "Polycom RealPresence Debut", "video_conference", "Polycom"),
    (r"RealPresence\s*Trio", "Polycom RealPresence Trio", "video_conference", "Polycom"),
    (r"Studio\s*X\d+", "Poly Studio X", "video_bar", "Poly"),
    (r"Studio\s*E\d+", "Poly Studio E", "video_bar", "Poly"),

    # Generic
    (r"Polycom", "Polycom Device", "voip_phone", "Polycom UC"),
    (r"Poly\s", "Poly Device", "voip_phone", "Poly"),
]

YEALINK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:15:65": ("voip_phone", "VoIP", "Yealink Phone"),
    "00:1F:C1": ("voip_phone", "VoIP", "Yealink Phone"),
    "80:5E:C0": ("voip_phone", "VoIP", "Yealink Phone"),
    "80:5E:C0": ("voip_phone", "VoIP", "Yealink Phone"),
    "58:7B:E5": ("voip_phone", "VoIP", "Yealink Phone"),
}

YEALINK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # T5x Series (Premium)
    (r"T58A", "Yealink T58A", "voip_phone", "Yealink"),
    (r"T57W", "Yealink T57W", "voip_phone", "Yealink"),
    (r"T56A", "Yealink T56A", "voip_phone", "Yealink"),
    (r"T54W", "Yealink T54W", "voip_phone", "Yealink"),
    (r"T53W", "Yealink T53W", "voip_phone", "Yealink"),
    (r"T53", "Yealink T53", "voip_phone", "Yealink"),
    (r"T5\d[WA]?", "Yealink T5x", "voip_phone", "Yealink"),

    # T4x Series (Professional)
    (r"T48U", "Yealink T48U", "voip_phone", "Yealink"),
    (r"T48S", "Yealink T48S", "voip_phone", "Yealink"),
    (r"T46U", "Yealink T46U", "voip_phone", "Yealink"),
    (r"T46S", "Yealink T46S", "voip_phone", "Yealink"),
    (r"T43U", "Yealink T43U", "voip_phone", "Yealink"),
    (r"T42U", "Yealink T42U", "voip_phone", "Yealink"),
    (r"T42S", "Yealink T42S", "voip_phone", "Yealink"),
    (r"T41S", "Yealink T41S", "voip_phone", "Yealink"),
    (r"T4\d[US]?", "Yealink T4x", "voip_phone", "Yealink"),

    # T3x Series (Entry)
    (r"T33G", "Yealink T33G", "voip_phone", "Yealink"),
    (r"T31G", "Yealink T31G", "voip_phone", "Yealink"),
    (r"T31P", "Yealink T31P", "voip_phone", "Yealink"),
    (r"T31", "Yealink T31", "voip_phone", "Yealink"),
    (r"T3\d[GP]?", "Yealink T3x", "voip_phone", "Yealink"),

    # W Series (DECT)
    (r"W80DM", "Yealink W80 DECT Manager", "dect_base", "Yealink"),
    (r"W80B", "Yealink W80 Base", "dect_base", "Yealink"),
    (r"W73H", "Yealink W73H Handset", "dect_phone", "Yealink"),
    (r"W56H", "Yealink W56H Handset", "dect_phone", "Yealink"),
    (r"W\d+", "Yealink DECT", "dect_phone", "Yealink"),

    # Conference phones
    (r"CP\s*965", "Yealink CP965", "conference_phone", "Yealink"),
    (r"CP\s*960", "Yealink CP960", "conference_phone", "Yealink"),
    (r"CP\s*930W", "Yealink CP930W", "conference_phone", "Yealink"),
    (r"CP\s*920", "Yealink CP920", "conference_phone", "Yealink"),
    (r"CP\s*\d+", "Yealink CP Conference", "conference_phone", "Yealink"),

    # Video
    (r"VC\d+", "Yealink Video Conferencing", "video_conference", "Yealink"),
    (r"UVC\d+", "Yealink USB Camera", "webcam", "Yealink"),
    (r"MeetingBar\s*A\d+", "Yealink MeetingBar", "video_bar", "Yealink"),

    # Generic
    (r"Yealink", "Yealink Device", "voip_phone", "Yealink"),
]

CISCO_VOIP_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:08:20": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:0B:BE": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:0F:23": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:11:92": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:12:80": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:13:C4": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:19:AA": ("voip_phone", "VoIP", "Cisco IP Phone"),
    # REMOVED: 00:1B:54 - IEEE assigns to Unknown, not CISCO_VOIP
    "00:1E:13": ("voip_phone", "VoIP", "Cisco IP Phone"),
    # REMOVED: 00:21:A0 - IEEE assigns to Unknown, not CISCO_VOIP
    "00:22:90": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "00:23:5D": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "08:CC:68": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "0C:F5:A4": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "1C:E6:C7": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "38:20:56": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "50:3D:E5": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "84:B8:02": ("voip_phone", "VoIP", "Cisco IP Phone"),
    "B4:E9:B0": ("voip_phone", "VoIP", "Cisco IP Phone"),
    # REMOVED: E4:C7:22 - IEEE assigns to Unknown, not CISCO_VOIP
    "F8:0B:CB": ("voip_phone", "VoIP", "Cisco IP Phone"),
}

CISCO_VOIP_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 88xx Series
    (r"CP-8865", "Cisco IP Phone 8865", "voip_phone", "Cisco"),
    (r"CP-8861", "Cisco IP Phone 8861", "voip_phone", "Cisco"),
    (r"CP-8851", "Cisco IP Phone 8851", "voip_phone", "Cisco"),
    (r"CP-8845", "Cisco IP Phone 8845", "voip_phone", "Cisco"),
    (r"CP-8841", "Cisco IP Phone 8841", "voip_phone", "Cisco"),
    (r"CP-8832", "Cisco IP Conference Phone 8832", "conference_phone", "Cisco"),
    (r"CP-88\d{2}", "Cisco IP Phone 88xx", "voip_phone", "Cisco"),

    # 78xx Series
    (r"CP-7861", "Cisco IP Phone 7861", "voip_phone", "Cisco"),
    (r"CP-7841", "Cisco IP Phone 7841", "voip_phone", "Cisco"),
    (r"CP-7832", "Cisco IP Conference Phone 7832", "conference_phone", "Cisco"),
    (r"CP-7821", "Cisco IP Phone 7821", "voip_phone", "Cisco"),
    (r"CP-7811", "Cisco IP Phone 7811", "voip_phone", "Cisco"),
    (r"CP-78\d{2}", "Cisco IP Phone 78xx", "voip_phone", "Cisco"),

    # Webex Desk
    (r"Webex\s*Desk\s*Pro", "Cisco Webex Desk Pro", "video_phone", "Cisco"),
    (r"Webex\s*Desk", "Cisco Webex Desk", "video_phone", "Cisco"),

    # Webex Room
    (r"Room\s*Kit\s*Pro", "Cisco Room Kit Pro", "video_conference", "Cisco"),
    (r"Room\s*Kit\s*Plus", "Cisco Room Kit Plus", "video_conference", "Cisco"),
    (r"Room\s*Kit\s*Mini", "Cisco Room Kit Mini", "video_conference", "Cisco"),
    (r"Room\s*Kit", "Cisco Room Kit", "video_conference", "Cisco"),
    (r"Room\s*Bar\s*Pro", "Cisco Room Bar Pro", "video_bar", "Cisco"),
    (r"Room\s*Bar", "Cisco Room Bar", "video_bar", "Cisco"),

    # Webex Board
    (r"Webex\s*Board\s*\d+", "Cisco Webex Board", "interactive_display", "Cisco"),

    # ATA
    (r"ATA\s*19\d", "Cisco ATA 19x", "ata", "Cisco"),

    # Generic
    (r"Cisco\s*IP\s*Phone", "Cisco IP Phone", "voip_phone", "Cisco"),
]

# GRANDSTREAM VOIP PATTERNS

GRANDSTREAM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0B:82 - IEEE assigns to Unknown, not GRANDSTREAM
    # REMOVED: C0:74:AD - IEEE assigns to Unknown, not GRANDSTREAM
}

GRANDSTREAM_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # GRP Series (Carrier-Grade)
    (r"GRP\s*26\d{2}", "Grandstream GRP2600 Series", "voip_phone", "Grandstream"),
    # GXP Series
    (r"GXP\s*21\d{2}", "Grandstream GXP2100 Series", "voip_phone", "Grandstream"),
    (r"GXP\s*17\d{2}", "Grandstream GXP1700 Series", "voip_phone", "Grandstream"),
    (r"GXP\s*16\d{2}", "Grandstream GXP1600 Series", "voip_phone", "Grandstream"),
    # GXV Video Phones
    (r"GXV\s*33\d{2}", "Grandstream GXV3300 Series", "video_phone", "Grandstream"),
    (r"GXV\s*34\d{2}", "Grandstream GXV3400 Series", "video_phone", "Grandstream"),
    # UCM IP PBX
    (r"UCM\s*63\d{2}", "Grandstream UCM6300 Series", "ip_pbx", "Grandstream"),
    (r"UCM\s*62\d{2}", "Grandstream UCM6200 Series", "ip_pbx", "Grandstream"),
    (r"UCM\s*\d+", "Grandstream UCM IP PBX", "ip_pbx", "Grandstream"),
    # GWN Access Points
    (r"GWN\s*76\d{2}", "Grandstream GWN7600 AP", "access_point", "Grandstream"),
    # HT ATA
    (r"HT\s*8\d{2}", "Grandstream HT800 ATA", "ata", "Grandstream"),
    # Generic
    (r"Grandstream", "Grandstream", "voip_phone", "Grandstream"),
]

# AVAYA VOIP PATTERNS

AVAYA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:04:0D - IEEE assigns to Unknown, not AVAYA
    "00:1B:4F": ("voip_phone", "VoIP", "Avaya"),
    "24:D9:21": ("voip_phone", "VoIP", "Avaya"),
    "70:38:EE": ("voip_phone", "VoIP", "Avaya"),
    "B4:B0:17": ("voip_phone", "VoIP", "Avaya"),
}

AVAYA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # J-Series IP Phones
    (r"J189", "Avaya J189 IP Phone", "voip_phone", "Avaya"),
    (r"J179", "Avaya J179 IP Phone", "voip_phone", "Avaya"),
    (r"J169", "Avaya J169 IP Phone", "voip_phone", "Avaya"),
    (r"J159", "Avaya J159 IP Phone", "voip_phone", "Avaya"),
    (r"J139", "Avaya J139 IP Phone", "voip_phone", "Avaya"),
    (r"J129", "Avaya J129 IP Phone", "voip_phone", "Avaya"),
    (r"J1\d{2}", "Avaya J-Series Phone", "voip_phone", "Avaya"),
    # 9600 Series
    (r"96\d{2}[GSP]?", "Avaya 9600 Series", "voip_phone", "Avaya"),
    # IP Office
    (r"IP\s*Office\s*500", "Avaya IP Office 500", "ip_pbx", "IP Office"),
    (r"IP\s*Office", "Avaya IP Office", "ip_pbx", "IP Office"),
    # Aura
    (r"Communication\s*Manager", "Avaya Aura CM", "ip_pbx", "Aura"),
    (r"Session\s*Manager", "Avaya Aura SM", "sbc", "Aura"),
    (r"Avaya\s*Aura", "Avaya Aura", "ip_pbx", "Aura"),
    # Conferencing
    (r"Scopia", "Avaya Scopia", "video_conferencing", "Scopia"),
    # Generic
    (r"Avaya", "Avaya", "voip_phone", "Avaya"),
]

# MITEL VOIP PATTERNS

MITEL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:08:5D": ("voip_phone", "VoIP", "Mitel"),
    "00:10:BC": ("voip_phone", "VoIP", "Mitel"),
    "08:00:0F": ("voip_phone", "VoIP", "Mitel"),
}

MITEL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 6900 Series IP Phones
    (r"6940", "Mitel 6940 IP Phone", "voip_phone", "Mitel"),
    (r"6930", "Mitel 6930 IP Phone", "voip_phone", "Mitel"),
    (r"6920", "Mitel 6920 IP Phone", "voip_phone", "Mitel"),
    (r"6910", "Mitel 6910 IP Phone", "voip_phone", "Mitel"),
    (r"69\d{2}", "Mitel 6900 Series", "voip_phone", "Mitel"),
    # 6800 Series
    (r"68\d{2}", "Mitel 6800 Series", "voip_phone", "Mitel"),
    # MiVoice
    (r"MiVoice\s*Business", "Mitel MiVoice Business", "ip_pbx", "MiVoice"),
    (r"MiVoice\s*Office\s*400", "Mitel MiVoice Office 400", "ip_pbx", "MiVoice"),
    (r"MiVoice\s*5000", "Mitel MiVoice 5000", "ip_pbx", "MiVoice"),
    (r"MiVoice\s*MX-ONE", "Mitel MiVoice MX-ONE", "ip_pbx", "MiVoice"),
    (r"MiVoice", "Mitel MiVoice", "ip_pbx", "MiVoice"),
    # MiCollab
    (r"MiCollab", "Mitel MiCollab", "uc", "MiCollab"),
    # MiContact Center
    (r"MiContact\s*Center", "Mitel MiContact Center", "contact_center", "MiContact"),
    # CloudLink
    (r"CloudLink", "Mitel CloudLink", "cloud_pbx", "CloudLink"),
    # Generic
    (r"Mitel", "Mitel", "voip_phone", "Mitel"),
]


# CRESTRON / EXTRON AV PATTERNS

CRESTRON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:10:7F": ("av_controller", "AV Control", "Crestron"),
    "00:1C:91": ("av_controller", "AV Control", "Crestron"),
}

CRESTRON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Control processors
    (r"CP4-R", "Crestron CP4-R", "av_controller", "Crestron"),
    (r"CP4", "Crestron CP4", "av_controller", "Crestron"),
    (r"CP3-R", "Crestron CP3-R", "av_controller", "Crestron"),
    (r"CP3", "Crestron CP3", "av_controller", "Crestron"),
    (r"MC4-R", "Crestron MC4-R", "av_controller", "Crestron"),
    (r"MC4", "Crestron MC4", "av_controller", "Crestron"),
    (r"MC3", "Crestron MC3", "av_controller", "Crestron"),
    (r"PRO4", "Crestron PRO4", "av_controller", "Crestron"),
    (r"PRO3", "Crestron PRO3", "av_controller", "Crestron"),

    # Touch panels
    (r"TSW-\d+", "Crestron TSW Touch Panel", "touch_panel", "Crestron"),
    (r"TS-\d+", "Crestron TS Touch Panel", "touch_panel", "Crestron"),
    (r"TSR-\d+", "Crestron TSR Remote", "remote", "Crestron"),

    # DM (DigitalMedia)
    (r"DM-NVX-\d+", "Crestron DM NVX", "av_encoder", "Crestron"),
    (r"DM-MD\d+", "Crestron DM Matrix", "av_switcher", "Crestron"),
    (r"DM-RMC-\d+", "Crestron DM Receiver", "av_receiver", "Crestron"),
    (r"DM-TX-\d+", "Crestron DM Transmitter", "av_transmitter", "Crestron"),
    (r"DGE-\d+", "Crestron DGE", "av_processor", "Crestron"),

    # Flex UC
    (r"Flex\s*UC-[BCMEMX]+", "Crestron Flex UC", "video_conference", "Crestron"),

    # Zūm
    (r"CLW-\d+", "Crestron CLW", "av_controller", "Crestron"),

    # Generic
    (r"Crestron", "Crestron Device", "av_controller", "Crestron"),
]

EXTRON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:05:A6": ("av_switcher", "AV Control", "Extron"),
    # REMOVED: 00:1C:91 - IEEE assigns to Unknown, not EXTRON
}

EXTRON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Matrix switchers
    (r"DXP\s*\d+", "Extron DXP Matrix", "av_switcher", "Extron"),
    (r"CrossPoint\s*\d+", "Extron CrossPoint", "av_switcher", "Extron"),
    (r"MAV\s*Plus\s*\d+", "Extron MAV Plus", "av_switcher", "Extron"),
    (r"IN\d+\s*\d+", "Extron IN Matrix", "av_switcher", "Extron"),
    (r"FOX\s*Matrix", "Extron FOX Matrix", "av_switcher", "Extron"),

    # Scalers/Processors
    (r"DSC\s*\d+", "Extron DSC Scaler", "av_scaler", "Extron"),
    (r"DVS\s*\d+", "Extron DVS", "av_scaler", "Extron"),
    (r"DSP\s*\d+", "Extron DSP", "dsp", "Extron"),
    (r"DTP\s*\d+", "Extron DTP", "av_transmitter", "Extron"),

    # Streaming
    (r"SMP\s*\d+", "Extron SMP Streaming", "av_encoder", "Extron"),
    (r"SME\s*\d+", "Extron SME Encoder", "av_encoder", "Extron"),
    (r"SMD\s*\d+", "Extron SMD Decoder", "av_decoder", "Extron"),

    # Control
    (r"IPCP\s*\d+", "Extron IPCP Controller", "av_controller", "Extron"),
    (r"IPL\s*\d+", "Extron IPL Controller", "av_controller", "Extron"),
    (r"TLP\s*Pro\s*\d+", "Extron TLP Pro Touch Panel", "touch_panel", "Extron"),
    (r"TLP\s*\d+", "Extron TLP Touch Panel", "touch_panel", "Extron"),

    # Distribution amplifiers
    (r"DA\s*HD\s*\d+", "Extron DA HD", "av_distributor", "Extron"),
    (r"DA\s*\d+", "Extron DA", "av_distributor", "Extron"),

    # Generic
    (r"Extron", "Extron Device", "av_switcher", "Extron"),
]


# RASPBERRY PI / ARDUINO / MAKER PATTERNS

RASPBERRY_PI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "B8:27:EB": ("sbc", "IoT", "Raspberry Pi"),
    "DC:A6:32": ("sbc", "IoT", "Raspberry Pi"),
    "E4:5F:01": ("sbc", "IoT", "Raspberry Pi"),
    "D8:3A:DD": ("sbc", "IoT", "Raspberry Pi"),
    "28:CD:C1": ("sbc", "IoT", "Raspberry Pi"),
    "2C:CF:67": ("sbc", "IoT", "Raspberry Pi"),
}

RASPBERRY_PI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Raspberry Pi models
    (r"Raspberry\s*Pi\s*5", "Raspberry Pi 5", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*4\s*Model\s*B", "Raspberry Pi 4 Model B", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*4", "Raspberry Pi 4", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*400", "Raspberry Pi 400", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*3\s*Model\s*B\+", "Raspberry Pi 3B+", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*3\s*Model\s*B", "Raspberry Pi 3B", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*3\s*Model\s*A\+", "Raspberry Pi 3A+", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*Zero\s*2\s*W", "Raspberry Pi Zero 2 W", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*Zero\s*W", "Raspberry Pi Zero W", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*Zero", "Raspberry Pi Zero", "sbc", "Raspberry Pi OS"),
    (r"Raspberry\s*Pi\s*Pico\s*W", "Raspberry Pi Pico W", "microcontroller", "RP2040"),
    (r"Raspberry\s*Pi\s*Pico", "Raspberry Pi Pico", "microcontroller", "RP2040"),

    # CM (Compute Module)
    (r"Compute\s*Module\s*4", "Raspberry Pi CM4", "sbc", "Raspberry Pi OS"),
    (r"Compute\s*Module\s*3\+", "Raspberry Pi CM3+", "sbc", "Raspberry Pi OS"),
    (r"CM4", "Raspberry Pi CM4", "sbc", "Raspberry Pi OS"),
    (r"CM3\+", "Raspberry Pi CM3+", "sbc", "Raspberry Pi OS"),

    # Generic
    (r"Raspberry\s*Pi", "Raspberry Pi", "sbc", "Raspberry Pi OS"),
    (r"raspberrypi", "Raspberry Pi", "sbc", "Raspberry Pi OS"),
    (r"Raspbian", "Raspberry Pi", "sbc", "Raspberry Pi OS"),
]

ESPRESSIF_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "08:3A:F2": ("microcontroller", "IoT", "ESP Device"),
    "08:B6:1F": ("microcontroller", "IoT", "ESP Device"),
    "10:06:1C": ("microcontroller", "IoT", "ESP Device"),
    "10:52:1C": ("microcontroller", "IoT", "ESP Device"),
    "18:FE:34": ("microcontroller", "IoT", "ESP Device"),
    "24:0A:C4": ("microcontroller", "IoT", "ESP Device"),
    "24:62:AB": ("microcontroller", "IoT", "ESP Device"),
    "24:6F:28": ("microcontroller", "IoT", "ESP Device"),
    "24:A1:60": ("microcontroller", "IoT", "ESP Device"),
    "24:B2:DE": ("microcontroller", "IoT", "ESP Device"),
    "24:D7:EB": ("microcontroller", "IoT", "ESP Device"),
    "2C:F4:32": ("microcontroller", "IoT", "ESP Device"),
    "30:83:98": ("microcontroller", "IoT", "ESP Device"),
    "30:AE:A4": ("microcontroller", "IoT", "ESP Device"),
    "34:85:18": ("microcontroller", "IoT", "ESP Device"),
    "34:86:5D": ("microcontroller", "IoT", "ESP Device"),
    "34:94:54": ("microcontroller", "IoT", "ESP Device"),
    "34:AB:95": ("microcontroller", "IoT", "ESP Device"),
    "34:B4:72": ("microcontroller", "IoT", "ESP Device"),
    "3C:61:05": ("microcontroller", "IoT", "ESP Device"),
    "3C:71:BF": ("microcontroller", "IoT", "ESP Device"),
    "40:22:D8": ("microcontroller", "IoT", "ESP Device"),
    "40:F5:20": ("microcontroller", "IoT", "ESP Device"),
    "44:17:93": ("microcontroller", "IoT", "ESP Device"),
    "48:3F:DA": ("microcontroller", "IoT", "ESP Device"),
    "48:55:19": ("microcontroller", "IoT", "ESP Device"),
    "4C:11:AE": ("microcontroller", "IoT", "ESP Device"),
    "4C:75:25": ("microcontroller", "IoT", "ESP Device"),
    "54:32:04": ("microcontroller", "IoT", "ESP Device"),
    "58:BF:25": ("microcontroller", "IoT", "ESP Device"),
    "5C:CF:7F": ("microcontroller", "IoT", "ESP Device"),
    "60:01:94": ("microcontroller", "IoT", "ESP Device"),
    "68:C6:3A": ("microcontroller", "IoT", "ESP Device"),
    "70:03:9F": ("microcontroller", "IoT", "ESP Device"),
    "78:21:84": ("microcontroller", "IoT", "ESP Device"),
    "7C:9E:BD": ("microcontroller", "IoT", "ESP Device"),
    # REMOVED: 80:7D:3A - IEEE assigns to Unknown, not ESPRESSIF
    "84:0D:8E": ("microcontroller", "IoT", "ESP Device"),
    "84:CC:A8": ("microcontroller", "IoT", "ESP Device"),
    "84:F3:EB": ("microcontroller", "IoT", "ESP Device"),
    "8C:AA:B5": ("microcontroller", "IoT", "ESP Device"),
    "90:15:06": ("microcontroller", "IoT", "ESP Device"),
    "90:38:0C": ("microcontroller", "IoT", "ESP Device"),
    "94:3C:C6": ("microcontroller", "IoT", "ESP Device"),
    "94:B5:55": ("microcontroller", "IoT", "ESP Device"),
    "94:B9:7E": ("microcontroller", "IoT", "ESP Device"),
    "98:CD:AC": ("microcontroller", "IoT", "ESP Device"),
    "98:F4:AB": ("microcontroller", "IoT", "ESP Device"),
    "9C:9C:1F": ("microcontroller", "IoT", "ESP Device"),
    "A0:20:A6": ("microcontroller", "IoT", "ESP Device"),
    "A4:7B:9D": ("microcontroller", "IoT", "ESP Device"),
    "A4:CF:12": ("microcontroller", "IoT", "ESP Device"),
    "A4:E5:7C": ("microcontroller", "IoT", "ESP Device"),
    "A8:03:2A": ("microcontroller", "IoT", "ESP Device"),
    "AC:67:B2": ("microcontroller", "IoT", "ESP Device"),
    "B4:E6:2D": ("microcontroller", "IoT", "ESP Device"),
    "B8:F0:09": ("microcontroller", "IoT", "ESP Device"),
    "BC:DD:C2": ("microcontroller", "IoT", "ESP Device"),
    "BC:FF:4D": ("microcontroller", "IoT", "ESP Device"),
    "C4:4F:33": ("microcontroller", "IoT", "ESP Device"),
    "C4:5B:BE": ("microcontroller", "IoT", "ESP Device"),
    "C8:2B:96": ("microcontroller", "IoT", "ESP Device"),
    "CC:50:E3": ("microcontroller", "IoT", "ESP Device"),
    "D8:A0:1D": ("microcontroller", "IoT", "ESP Device"),
    "D8:BF:C0": ("microcontroller", "IoT", "ESP Device"),
    "DC:4F:22": ("microcontroller", "IoT", "ESP Device"),
    "E0:98:06": ("microcontroller", "IoT", "ESP Device"),
    "E8:DB:84": ("microcontroller", "IoT", "ESP Device"),
    "EC:94:CB": ("microcontroller", "IoT", "ESP Device"),
    "EC:FA:BC": ("microcontroller", "IoT", "ESP Device"),
    "F0:08:D1": ("microcontroller", "IoT", "ESP Device"),
    "F4:CF:A2": ("microcontroller", "IoT", "ESP Device"),
    "FC:F5:C4": ("microcontroller", "IoT", "ESP Device"),
}

ESPRESSIF_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ESP32 variants
    (r"ESP32-S3", "ESP32-S3", "microcontroller", "ESP-IDF"),
    (r"ESP32-S2", "ESP32-S2", "microcontroller", "ESP-IDF"),
    (r"ESP32-C6", "ESP32-C6", "microcontroller", "ESP-IDF"),
    (r"ESP32-C3", "ESP32-C3", "microcontroller", "ESP-IDF"),
    (r"ESP32-H2", "ESP32-H2", "microcontroller", "ESP-IDF"),
    (r"ESP32-WROOM", "ESP32-WROOM", "microcontroller", "ESP-IDF"),
    (r"ESP32-WROVER", "ESP32-WROVER", "microcontroller", "ESP-IDF"),
    (r"ESP32", "ESP32", "microcontroller", "ESP-IDF"),

    # ESP8266
    (r"ESP8266", "ESP8266", "microcontroller", "ESP-IDF"),
    (r"ESP-12", "ESP8266 ESP-12", "microcontroller", "ESP-IDF"),
    (r"ESP-01", "ESP8266 ESP-01", "microcontroller", "ESP-IDF"),
    (r"NodeMCU", "NodeMCU", "microcontroller", "ESP-IDF"),

    # Generic
    (r"Espressif", "Espressif Device", "microcontroller", "ESP-IDF"),
    (r"ESP-IDF", "ESP Device", "microcontroller", "ESP-IDF"),
]


# TESLA / EV CHARGER PATTERNS

TESLA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 4C:FC:AA - IEEE assigns to Unknown, not TESLA
    # REMOVED: 98:ED:5C - IEEE assigns to Unknown, not TESLA
}

TESLA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Wall Connector
    (r"Tesla\s*Wall\s*Connector\s*Gen\s*3", "Tesla Wall Connector Gen 3", "ev_charger", "Tesla"),
    (r"Tesla\s*Wall\s*Connector", "Tesla Wall Connector", "ev_charger", "Tesla"),
    (r"TWC\s*Gen\s*3", "Tesla Wall Connector Gen 3", "ev_charger", "Tesla"),
    (r"TWC", "Tesla Wall Connector", "ev_charger", "Tesla"),

    # Universal Wall Connector
    (r"Tesla\s*Universal\s*Wall\s*Connector", "Tesla Universal Wall Connector", "ev_charger", "Tesla"),
    (r"TUWC", "Tesla Universal Wall Connector", "ev_charger", "Tesla"),

    # Powerwall
    (r"Powerwall\s*3", "Tesla Powerwall 3", "battery", "Tesla"),
    (r"Powerwall\s*2", "Tesla Powerwall 2", "battery", "Tesla"),
    (r"Powerwall\+", "Tesla Powerwall+", "battery", "Tesla"),
    (r"Powerwall", "Tesla Powerwall", "battery", "Tesla"),

    # Gateway
    (r"Tesla\s*Gateway\s*2", "Tesla Gateway 2", "energy_gateway", "Tesla"),
    (r"Tesla\s*Gateway", "Tesla Gateway", "energy_gateway", "Tesla"),
    (r"TEG", "Tesla Energy Gateway", "energy_gateway", "Tesla"),

    # Generic
    (r"Tesla\s*Energy", "Tesla Energy", "energy_gateway", "Tesla"),
    (r"Tesla", "Tesla Device", "ev_charger", "Tesla"),
]

CHARGEPOINT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:21:B7 - IEEE assigns to Unknown, not CHARGEPOINT
    # REMOVED: 84:D4:7E - IEEE assigns to Unknown, not CHARGEPOINT
}

CHARGEPOINT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Home Chargers
    (r"ChargePoint\s*Home\s*Flex", "ChargePoint Home Flex", "ev_charger", "ChargePoint"),
    (r"ChargePoint\s*Home", "ChargePoint Home", "ev_charger", "ChargePoint"),
    (r"CPH50", "ChargePoint Home Flex", "ev_charger", "ChargePoint"),
    (r"CPH25", "ChargePoint Home", "ev_charger", "ChargePoint"),

    # Commercial
    (r"CT4\d+", "ChargePoint CT4000", "ev_charger", "ChargePoint"),
    (r"CT5\d+", "ChargePoint CT5000", "ev_charger", "ChargePoint"),
    (r"CPF50", "ChargePoint CPF50", "ev_charger", "ChargePoint"),
    (r"CPE\d+", "ChargePoint Express", "dc_fast_charger", "ChargePoint"),
    (r"Express\s*Plus", "ChargePoint Express Plus", "dc_fast_charger", "ChargePoint"),
    (r"Express\s*\d+", "ChargePoint Express", "dc_fast_charger", "ChargePoint"),

    # Generic
    (r"ChargePoint", "ChargePoint Charger", "ev_charger", "ChargePoint"),
]


# ZEBRA / BARCODE SCANNER PATTERNS

ZEBRA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:A0:F8 - IEEE assigns to Unknown, not ZEBRA
    "40:83:DE": ("barcode_scanner", "Industrial", "Zebra Scanner"),
    "84:24:8D": ("barcode_scanner", "Industrial", "Zebra Scanner"),
    # REMOVED: B0:A7:B9 - IEEE assigns to Unknown, not ZEBRA
    # REMOVED: E0:55:3D - IEEE assigns to Unknown, not ZEBRA
}

ZEBRA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # DS Series (Handheld)
    (r"DS9908", "Zebra DS9908", "barcode_scanner", "Zebra"),
    (r"DS9308", "Zebra DS9308", "barcode_scanner", "Zebra"),
    (r"DS8178", "Zebra DS8178", "barcode_scanner", "Zebra"),
    (r"DS7708", "Zebra DS7708", "barcode_scanner", "Zebra"),
    (r"DS4608", "Zebra DS4608", "barcode_scanner", "Zebra"),
    (r"DS3678", "Zebra DS3678", "barcode_scanner", "Zebra"),
    (r"DS2278", "Zebra DS2278", "barcode_scanner", "Zebra"),
    (r"DS22\d{2}", "Zebra DS22xx", "barcode_scanner", "Zebra"),

    # Mobile computers
    (r"TC78", "Zebra TC78", "mobile_computer", "Zebra"),
    (r"TC73", "Zebra TC73", "mobile_computer", "Zebra"),
    (r"TC72", "Zebra TC72", "mobile_computer", "Zebra"),
    (r"TC58", "Zebra TC58", "mobile_computer", "Zebra"),
    (r"TC53", "Zebra TC53", "mobile_computer", "Zebra"),
    (r"TC52", "Zebra TC52", "mobile_computer", "Zebra"),
    (r"TC26", "Zebra TC26", "mobile_computer", "Zebra"),
    (r"TC21", "Zebra TC21", "mobile_computer", "Zebra"),
    (r"TC\d{2}", "Zebra TC Mobile Computer", "mobile_computer", "Zebra"),

    # MC Series
    (r"MC9300", "Zebra MC9300", "mobile_computer", "Zebra"),
    (r"MC9200", "Zebra MC9200", "mobile_computer", "Zebra"),
    (r"MC3300", "Zebra MC3300", "mobile_computer", "Zebra"),
    (r"MC2200", "Zebra MC2200", "mobile_computer", "Zebra"),
    (r"MC\d{4}", "Zebra MC Mobile Computer", "mobile_computer", "Zebra"),

    # ET (Tablets)
    (r"ET80", "Zebra ET80", "rugged_tablet", "Zebra"),
    (r"ET60", "Zebra ET60", "rugged_tablet", "Zebra"),
    (r"ET56", "Zebra ET56", "rugged_tablet", "Zebra"),
    (r"ET5\d", "Zebra ET5x", "rugged_tablet", "Zebra"),

    # Printers
    (r"ZT\d{3}", "Zebra ZT Printer", "label_printer", "Zebra"),
    (r"ZD\d{3}", "Zebra ZD Printer", "label_printer", "Zebra"),
    (r"ZQ\d{3}", "Zebra ZQ Mobile Printer", "mobile_printer", "Zebra"),
    (r"ZC\d{3}", "Zebra ZC Card Printer", "card_printer", "Zebra"),

    # Generic
    (r"Zebra\s*Technologies", "Zebra Device", "barcode_scanner", "Zebra"),
    (r"Zebra", "Zebra Device", "barcode_scanner", "Zebra"),
]


# LENOVO / ASUS / MSI COMPUTER PATTERNS

LENOVO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:06:1B": ("computer", "Computer", "Lenovo"),
    # REMOVED: 00:0A:E4 - IEEE assigns to Unknown, not LENOVO
    # REMOVED: 00:1E:4F - IEEE assigns to Unknown, not LENOVO
    "14:FD:A2": ("computer", "Computer", "Lenovo"),
    # REMOVED: 2C:59:E5 - IEEE assigns to Unknown, not LENOVO
    # REMOVED: 3C:52:82 - IEEE assigns to Hewlett Packard, not Lenovo
    "64:9B:4D": ("computer", "Computer", "Lenovo"),
    # REMOVED: 90:6C:AC - IEEE assigns to Unknown, not LENOVO
    "9C:9D:5B": ("computer", "Computer", "Lenovo"),
    # REMOVED: D0:67:E5 - IEEE assigns to Unknown, not LENOVO
    # REMOVED: F4:8E:38 - IEEE assigns to Unknown, not LENOVO
}

LENOVO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ThinkPad
    (r"ThinkPad\s*X1\s*Carbon", "Lenovo ThinkPad X1 Carbon", "laptop", "Windows"),
    (r"ThinkPad\s*X1\s*Yoga", "Lenovo ThinkPad X1 Yoga", "laptop", "Windows"),
    (r"ThinkPad\s*T\d{2}", "Lenovo ThinkPad T Series", "laptop", "Windows"),
    (r"ThinkPad\s*X\d{3}", "Lenovo ThinkPad X Series", "laptop", "Windows"),
    (r"ThinkPad\s*L\d{2}", "Lenovo ThinkPad L Series", "laptop", "Windows"),
    (r"ThinkPad\s*E\d{2}", "Lenovo ThinkPad E Series", "laptop", "Windows"),
    (r"ThinkPad\s*P\d{2}", "Lenovo ThinkPad P Workstation", "workstation", "Windows"),
    (r"ThinkPad", "Lenovo ThinkPad", "laptop", "Windows"),

    # ThinkCentre
    (r"ThinkCentre\s*M\d{2,3}", "Lenovo ThinkCentre M Series", "desktop", "Windows"),
    (r"ThinkCentre\s*Tiny", "Lenovo ThinkCentre Tiny", "desktop", "Windows"),
    (r"ThinkCentre", "Lenovo ThinkCentre", "desktop", "Windows"),

    # ThinkStation
    (r"ThinkStation\s*P\d{3}", "Lenovo ThinkStation P Series", "workstation", "Windows"),
    (r"ThinkStation", "Lenovo ThinkStation", "workstation", "Windows"),

    # IdeaPad
    (r"IdeaPad\s*Flex", "Lenovo IdeaPad Flex", "laptop", "Windows"),
    (r"IdeaPad\s*Slim", "Lenovo IdeaPad Slim", "laptop", "Windows"),
    (r"IdeaPad\s*Gaming", "Lenovo IdeaPad Gaming", "laptop", "Windows"),
    (r"IdeaPad\s*\d", "Lenovo IdeaPad", "laptop", "Windows"),
    (r"IdeaPad", "Lenovo IdeaPad", "laptop", "Windows"),

    # Legion (Gaming)
    (r"Legion\s*Pro\s*\d", "Lenovo Legion Pro", "laptop", "Windows"),
    (r"Legion\s*Slim\s*\d", "Lenovo Legion Slim", "laptop", "Windows"),
    (r"Legion\s*\d", "Lenovo Legion", "laptop", "Windows"),
    (r"Legion", "Lenovo Legion", "laptop", "Windows"),

    # Yoga
    (r"Yoga\s*\d+", "Lenovo Yoga", "laptop", "Windows"),
    (r"Yoga\s*Pro", "Lenovo Yoga Pro", "laptop", "Windows"),
    (r"Yoga", "Lenovo Yoga", "laptop", "Windows"),

    # Servers
    (r"ThinkSystem\s*SR\d+", "Lenovo ThinkSystem SR", "server", "Linux"),
    (r"ThinkSystem\s*SD\d+", "Lenovo ThinkSystem SD", "server", "Linux"),
    (r"ThinkSystem\s*ST\d+", "Lenovo ThinkSystem ST", "server", "Linux"),
    (r"ThinkSystem", "Lenovo ThinkSystem", "server", "Linux"),

    # Generic
    (r"Lenovo", "Lenovo Device", "computer", "Windows"),
]

ASUS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # ASUSTek COMPUTER INC. (IEEE MA-L) — covers routers, computers, etc.
    "00:0C:6E": ("computer", "Computer", "ASUS"),
    "00:0E:A6": ("computer", "Computer", "ASUS"),
    "00:11:2F": ("computer", "Computer", "ASUS"),
    "00:11:D8": ("computer", "Computer", "ASUS"),
    "00:13:D4": ("computer", "Computer", "ASUS"),
    "00:15:F2": ("computer", "Computer", "ASUS"),
    "00:17:31": ("computer", "Computer", "ASUS"),
    "00:18:F3": ("computer", "Computer", "ASUS"),
    "00:1A:92": ("computer", "Computer", "ASUS"),
    "00:1B:FC": ("computer", "Computer", "ASUS"),
    "00:1D:60": ("computer", "Computer", "ASUS"),
    "00:1E:8C": ("computer", "Computer", "ASUS"),
    "00:1F:C6": ("computer", "Computer", "ASUS"),
    "00:22:15": ("computer", "Computer", "ASUS"),
    "00:23:54": ("computer", "Computer", "ASUS"),
    "00:24:8C": ("computer", "Computer", "ASUS"),
    "00:26:18": ("computer", "Computer", "ASUS"),
    "00:E0:18": ("computer", "Computer", "ASUS"),
    "04:42:1A": ("computer", "Computer", "ASUS"),
    "04:92:26": ("computer", "Computer", "ASUS"),
    "04:D4:C4": ("computer", "Computer", "ASUS"),
    "04:D9:F5": ("computer", "Computer", "ASUS"),
    "08:60:6E": ("computer", "Computer", "ASUS"),
    "08:62:66": ("computer", "Computer", "ASUS"),
    "08:BF:B8": ("computer", "Computer", "ASUS"),
    "0C:9D:92": ("computer", "Computer", "ASUS"),
    "10:7B:44": ("computer", "Computer", "ASUS"),
    "10:7C:61": ("computer", "Computer", "ASUS"),
    "10:BF:48": ("computer", "Computer", "ASUS"),
    "10:C3:7B": ("computer", "Computer", "ASUS"),
    "14:DA:E9": ("computer", "Computer", "ASUS"),
    "14:DD:A9": ("computer", "Computer", "ASUS"),
    "18:31:BF": ("computer", "Computer", "ASUS"),
    "1C:87:2C": ("computer", "Computer", "ASUS"),
    "1C:B7:2C": ("computer", "Computer", "ASUS"),
    "20:CF:30": ("computer", "Computer", "ASUS"),
    "24:4B:FE": ("computer", "Computer", "ASUS"),
    "2C:4D:54": ("computer", "Computer", "ASUS"),
    "2C:56:DC": ("computer", "Computer", "ASUS"),
    "2C:FD:A1": ("computer", "Computer", "ASUS"),
    "30:5A:3A": ("computer", "Computer", "ASUS"),
    "30:85:A9": ("computer", "Computer", "ASUS"),
    "30:C5:99": ("computer", "Computer", "ASUS"),
    "34:97:F6": ("computer", "Computer", "ASUS"),
    "38:2C:4A": ("computer", "Computer", "ASUS"),
    "38:D5:47": ("computer", "Computer", "ASUS"),
    "3C:7C:3F": ("computer", "Computer", "ASUS"),
    "40:16:7E": ("computer", "Computer", "ASUS"),
    "40:B0:76": ("computer", "Computer", "ASUS"),
    "48:5B:39": ("computer", "Computer", "ASUS"),
    "4C:ED:FB": ("computer", "Computer", "ASUS"),
    "50:46:5D": ("computer", "Computer", "ASUS"),
    "50:EB:F6": ("computer", "Computer", "ASUS"),
    "54:04:A6": ("computer", "Computer", "ASUS"),
    "54:A0:50": ("computer", "Computer", "ASUS"),
    "58:11:22": ("computer", "Computer", "ASUS"),
    "60:45:CB": ("computer", "Computer", "ASUS"),
    "60:A4:4C": ("computer", "Computer", "ASUS"),
    "60:CF:84": ("computer", "Computer", "ASUS"),
    "70:4D:7B": ("computer", "Computer", "ASUS"),
    "70:8B:CD": ("computer", "Computer", "ASUS"),
    "74:D0:2B": ("computer", "Computer", "ASUS"),
    "78:24:AF": ("computer", "Computer", "ASUS"),
    "7C:10:C9": ("computer", "Computer", "ASUS"),
    "88:D7:F6": ("computer", "Computer", "ASUS"),
    "90:E6:BA": ("computer", "Computer", "ASUS"),
    "9C:5C:8E": ("computer", "Computer", "ASUS"),
    "A0:36:BC": ("computer", "Computer", "ASUS"),  # Shared OUI: routers + laptops/Chromebooks
    "A0:AD:9F": ("computer", "Computer", "ASUS"),
    "A8:5E:45": ("computer", "Computer", "ASUS"),
    "AC:22:0B": ("computer", "Computer", "ASUS"),
    "AC:9E:17": ("computer", "Computer", "ASUS"),
    "B0:6E:BF": ("computer", "Computer", "ASUS"),
    "B0:82:E2": ("computer", "Computer", "ASUS"),
    "BC:AE:C5": ("computer", "Computer", "ASUS"),
    "BC:EE:7B": ("computer", "Computer", "ASUS"),
    "BC:FC:E7": ("computer", "Computer", "ASUS"),
    "C8:60:00": ("computer", "Computer", "ASUS"),
    "C8:7F:54": ("computer", "Computer", "ASUS"),
    "CC:28:AA": ("computer", "Computer", "ASUS"),
    "D0:17:C2": ("computer", "Computer", "ASUS"),
    "D4:5D:64": ("computer", "Computer", "ASUS"),
    "D8:50:E6": ("computer", "Computer", "ASUS"),
    "E0:3F:49": ("computer", "Computer", "ASUS"),
    "E0:CB:4E": ("computer", "Computer", "ASUS"),
    "E8:9C:25": ("computer", "Computer", "ASUS"),
    "F0:2F:74": ("computer", "Computer", "ASUS"),
    "F0:79:59": ("computer", "Computer", "ASUS"),
    "F4:6D:04": ("computer", "Computer", "ASUS"),
    "F8:32:E4": ("computer", "Computer", "ASUS"),
    "FC:34:97": ("computer", "Computer", "ASUS"),
    "FC:C2:33": ("computer", "Computer", "ASUS"),
}

ASUS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ROG (Gaming)
    (r"ROG\s*Strix", "ASUS ROG Strix", "laptop", "Windows"),
    (r"ROG\s*Zephyrus", "ASUS ROG Zephyrus", "laptop", "Windows"),
    (r"ROG\s*Flow", "ASUS ROG Flow", "laptop", "Windows"),
    (r"ROG\s*Phone", "ASUS ROG Phone", "phone", "Android"),
    (r"ROG", "ASUS ROG", "laptop", "Windows"),

    # ZenBook
    (r"ZenBook\s*Pro", "ASUS ZenBook Pro", "laptop", "Windows"),
    (r"ZenBook\s*Duo", "ASUS ZenBook Duo", "laptop", "Windows"),
    (r"ZenBook\s*Flip", "ASUS ZenBook Flip", "laptop", "Windows"),
    (r"ZenBook\s*S", "ASUS ZenBook S", "laptop", "Windows"),
    (r"ZenBook\s*\d+", "ASUS ZenBook", "laptop", "Windows"),
    (r"ZenBook", "ASUS ZenBook", "laptop", "Windows"),

    # VivoBook
    (r"VivoBook\s*Pro", "ASUS VivoBook Pro", "laptop", "Windows"),
    (r"VivoBook\s*Flip", "ASUS VivoBook Flip", "laptop", "Windows"),
    (r"VivoBook\s*S\d+", "ASUS VivoBook S", "laptop", "Windows"),
    (r"VivoBook", "ASUS VivoBook", "laptop", "Windows"),

    # TUF Gaming
    (r"TUF\s*Gaming", "ASUS TUF Gaming", "laptop", "Windows"),
    (r"TUF\s*Dash", "ASUS TUF Dash", "laptop", "Windows"),
    (r"TUF", "ASUS TUF", "laptop", "Windows"),

    # ProArt
    (r"ProArt\s*Studiobook", "ASUS ProArt Studiobook", "workstation", "Windows"),
    (r"ProArt", "ASUS ProArt", "workstation", "Windows"),

    # Routers
    (r"RT-AX\d+", "ASUS RT-AX Router", "router", "ASUSWRT"),
    (r"RT-AC\d+", "ASUS RT-AC Router", "router", "ASUSWRT"),
    (r"ZenWiFi", "ASUS ZenWiFi", "router", "ASUSWRT"),
    (r"AiMesh", "ASUS AiMesh", "router", "ASUSWRT"),

    # Servers/Workstations
    (r"RS\d+", "ASUS Server", "server", "Linux"),
    (r"ESC\d+", "ASUS ESC Workstation", "workstation", "Windows"),

    # Generic
    (r"ASUS", "ASUS Device", "computer", "Windows"),
]


# REOLINK CAMERA PATTERNS

REOLINK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Reolink Innovation (assigned OUIs)
    "EC:71:DB": ("ip_camera", "Surveillance", "Reolink Camera"),
    "DC:87:BC": ("ip_camera", "Surveillance", "Reolink Camera"),
}

REOLINK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 4K/8MP Cameras
    (r"RLC-810A", "Reolink RLC-810A", "ip_camera", None),
    (r"RLC-811A", "Reolink RLC-811A", "ip_camera", None),
    (r"RLC-820A", "Reolink RLC-820A", "ip_camera", None),
    (r"RLC-822A", "Reolink RLC-822A", "ip_camera", None),
    (r"RLC-823A", "Reolink RLC-823A PTZ", "ptz_camera", None),
    (r"RLC-842A", "Reolink RLC-842A", "ip_camera", None),

    # 5MP Cameras
    (r"RLC-510A", "Reolink RLC-510A", "ip_camera", None),
    (r"RLC-511A", "Reolink RLC-511A", "ip_camera", None),
    (r"RLC-520A", "Reolink RLC-520A", "ip_camera", None),
    (r"RLC-522A", "Reolink RLC-522A", "ip_camera", None),
    (r"RLC-523WA", "Reolink RLC-523WA PTZ", "ptz_camera", None),
    (r"RLC-542WA", "Reolink RLC-542WA", "ip_camera", None),

    # Duo/Multi-lens
    (r"Duo\s*3\s*PoE", "Reolink Duo 3 PoE", "ip_camera", None),
    (r"Duo\s*2\s*PoE", "Reolink Duo 2 PoE", "ip_camera", None),
    (r"Duo\s*WiFi", "Reolink Duo WiFi", "ip_camera", None),
    (r"TrackMix", "Reolink TrackMix PTZ", "ptz_camera", None),

    # Battery Cameras
    (r"Argus\s*4\s*Pro", "Reolink Argus 4 Pro", "ip_camera", None),
    (r"Argus\s*3\s*Pro", "Reolink Argus 3 Pro", "ip_camera", None),
    (r"Argus\s*PT", "Reolink Argus PT", "ptz_camera", None),
    (r"Argus\s*Eco", "Reolink Argus Eco", "ip_camera", None),
    (r"Argus", "Reolink Argus", "ip_camera", None),

    # Doorbell
    (r"Doorbell.*PoE", "Reolink Video Doorbell PoE", "doorbell_camera", None),
    (r"Doorbell.*WiFi", "Reolink Video Doorbell WiFi", "doorbell_camera", None),

    # NVR
    (r"RLN\d+-\d+", "Reolink NVR", "nvr", None),
    (r"RLN36", "Reolink RLN36 NVR", "nvr", None),
    (r"RLN16", "Reolink RLN16 NVR", "nvr", None),
    (r"RLN8", "Reolink RLN8 NVR", "nvr", None),

    # Generic
    (r"Reolink", "Reolink Camera", "ip_camera", None),
]


# AMCREST CAMERA PATTERNS

AMCREST_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Amcrest (uses various OEMs)
    # REMOVED: 9C:8E:CD - IEEE assigns to Unknown, not AMCREST
    # REMOVED: 3C:EF:8C - IEEE assigns to Unknown, not AMCREST
    # REMOVED: E0:50:8B - IEEE assigns to Unknown, not AMCREST
}

AMCREST_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 4K/8MP Cameras
    (r"IP8M-2796E", "Amcrest UltraHD 4K Bullet", "ip_camera", None),
    (r"IP8M-2793E", "Amcrest UltraHD 4K Dome", "ip_camera", None),
    (r"IP8M-T2599E", "Amcrest UltraHD 4K Turret", "ip_camera", None),
    (r"IP8M.*PTZ", "Amcrest UltraHD 4K PTZ", "ptz_camera", None),

    # 5MP Cameras
    (r"IP5M-B1186E", "Amcrest 5MP Bullet", "ip_camera", None),
    (r"IP5M-D1188E", "Amcrest 5MP Dome", "ip_camera", None),
    (r"IP5M-T1179E", "Amcrest 5MP Turret", "ip_camera", None),

    # 4MP Cameras
    (r"IP4M-1051", "Amcrest ProHD 4MP", "ip_camera", None),
    (r"IP4M-1041", "Amcrest UltraHD 4MP Dome", "ip_camera", None),
    (r"IP4M-1028E", "Amcrest UltraHD 4MP Bullet", "ip_camera", None),

    # PTZ Cameras
    (r"IP2M-841", "Amcrest 2MP PTZ", "ptz_camera", None),
    (r"IP4M-1053E", "Amcrest 4MP PTZ", "ptz_camera", None),

    # Doorbell
    (r"AD410", "Amcrest SmartHome Video Doorbell", "doorbell_camera", None),
    (r"AD110", "Amcrest 1080P Video Doorbell", "doorbell_camera", None),

    # NVR/DVR
    (r"NV\d{4}", "Amcrest NVR", "nvr", None),
    (r"AMDV\d{4}", "Amcrest DVR", "dvr", None),

    # Generic
    (r"Amcrest", "Amcrest Camera", "ip_camera", None),
]


# LOREX CAMERA PATTERNS

LOREX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Lorex Technology
    # REMOVED: A4:DA:22 - IEEE assigns to Unknown, not LOREX
}

LOREX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 4K Cameras
    (r"E893AB", "Lorex 4K IP Bullet", "ip_camera", None),
    (r"E893DD", "Lorex 4K IP Dome", "ip_camera", None),
    (r"E896AB", "Lorex 4K Smart Bullet", "ip_camera", None),
    (r"E896DD", "Lorex 4K Smart Dome", "ip_camera", None),
    (r"LNE\d+", "Lorex IP Camera", "ip_camera", None),
    (r"LNB\d+", "Lorex IP Bullet", "ip_camera", None),
    (r"LND\d+", "Lorex IP Dome", "ip_camera", None),

    # PTZ Cameras
    (r"LNZ\d+", "Lorex PTZ Camera", "ptz_camera", None),
    (r"E841CD", "Lorex Pan-Tilt Camera", "ptz_camera", None),

    # 2K Cameras
    (r"E454AB", "Lorex 2K IP Bullet", "ip_camera", None),
    (r"E454AD", "Lorex 2K IP Dome", "ip_camera", None),
    (r"W461ASD", "Lorex 2K Wire-Free", "ip_camera", None),

    # Doorbell
    (r"LNWDB1", "Lorex Video Doorbell", "doorbell_camera", None),
    (r"2K.*Doorbell", "Lorex 2K Doorbell", "doorbell_camera", None),

    # NVR/DVR Systems
    (r"N\d{3}[A-Z]+", "Lorex NVR", "nvr", None),
    (r"NR\d{3}", "Lorex NVR", "nvr", None),
    (r"D\d{3}[A-Z]+", "Lorex DVR", "dvr", None),
    (r"LHV\d+", "Lorex DVR", "dvr", None),
    (r"LNR\d+", "Lorex NVR", "nvr", None),

    # Fusion Systems
    (r"Fusion\s*4K", "Lorex Fusion 4K", "nvr", None),

    # Generic
    (r"Lorex", "Lorex Camera", "ip_camera", None),
]


# VIVOTEK CAMERA PATTERNS

VIVOTEK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # VIVOTEK Inc.
    "00:02:D1": ("ip_camera", "Surveillance", "VIVOTEK Camera"),
}

VIVOTEK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Bullet Cameras
    (r"IB9\d{3}", "VIVOTEK Bullet Camera", "ip_camera", None),
    (r"IB9391-EHT", "VIVOTEK IB9391-EHT", "ip_camera", None),
    (r"IB9387-EHT", "VIVOTEK IB9387-EHT", "ip_camera", None),
    (r"IB9365-EHT", "VIVOTEK IB9365-EHT", "ip_camera", None),

    # Dome Cameras
    (r"FD9\d{3}", "VIVOTEK Dome Camera", "ip_camera", None),
    (r"FD9391-EHTV", "VIVOTEK FD9391-EHTV", "ip_camera", None),
    (r"FD9387-EHTV", "VIVOTEK FD9387-EHTV", "ip_camera", None),
    (r"FD9365-EHTV", "VIVOTEK FD9365-EHTV", "ip_camera", None),

    # Fisheye Cameras
    (r"FE9\d{3}", "VIVOTEK Fisheye Camera", "ip_camera", None),
    (r"FE9391-EV", "VIVOTEK FE9391-EV Fisheye", "ip_camera", None),

    # PTZ Cameras
    (r"SD9\d{3}", "VIVOTEK PTZ Camera", "ptz_camera", None),
    (r"SD9394-EHL", "VIVOTEK SD9394-EHL PTZ", "ptz_camera", None),
    (r"SD9384-EHL", "VIVOTEK SD9384-EHL PTZ", "ptz_camera", None),

    # Mobile/Vehicle
    (r"MD9\d{3}", "VIVOTEK Mobile Camera", "ip_camera", None),

    # NVR
    (r"ND9\d{3}", "VIVOTEK NVR", "nvr", None),
    (r"ND9541P", "VIVOTEK ND9541P NVR", "nvr", None),
    (r"ND9425P", "VIVOTEK ND9425P NVR", "nvr", None),

    # Generic
    (r"VIVOTEK", "VIVOTEK Camera", "ip_camera", None),
]


# HANWHA (SAMSUNG WISENET) CAMERA PATTERNS

HANWHA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Hanwha Techwin (formerly Samsung Techwin)
    "00:09:18": ("ip_camera", "Surveillance", "Hanwha Wisenet Camera"),
    # REMOVED: 00:1E:E5 - IEEE assigns to Unknown, not HANWHA
    # REMOVED: 00:26:73 - IEEE assigns to Unknown, not HANWHA
}

HANWHA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # X-Series (Premium)
    (r"XNV-\d+", "Hanwha Wisenet X Vandal Dome", "ip_camera", None),
    (r"XNB-\d+", "Hanwha Wisenet X Bullet", "ip_camera", None),
    (r"XND-\d+", "Hanwha Wisenet X Dome", "ip_camera", None),
    (r"XNP-\d+", "Hanwha Wisenet X PTZ", "ptz_camera", None),
    (r"XNF-\d+", "Hanwha Wisenet X Fisheye", "ip_camera", None),
    (r"XNO-\d+", "Hanwha Wisenet X Bullet", "ip_camera", None),

    # P-Series (Professional)
    (r"PNV-\d+", "Hanwha Wisenet P Vandal Dome", "ip_camera", None),
    (r"PNB-\d+", "Hanwha Wisenet P Bullet", "ip_camera", None),
    (r"PND-\d+", "Hanwha Wisenet P Dome", "ip_camera", None),
    (r"PNP-\d+", "Hanwha Wisenet P PTZ", "ptz_camera", None),
    (r"PNM-\d+", "Hanwha Wisenet P Multi-Sensor", "ip_camera", None),
    (r"PNO-\d+", "Hanwha Wisenet P Bullet", "ip_camera", None),

    # Q-Series (Value)
    (r"QNV-\d+", "Hanwha Wisenet Q Vandal Dome", "ip_camera", None),
    (r"QNB-\d+", "Hanwha Wisenet Q Bullet", "ip_camera", None),
    (r"QND-\d+", "Hanwha Wisenet Q Dome", "ip_camera", None),
    (r"QNO-\d+", "Hanwha Wisenet Q Bullet", "ip_camera", None),
    (r"QNE-\d+", "Hanwha Wisenet Q Flateye", "ip_camera", None),

    # L-Series (Lite)
    (r"LNV-\d+", "Hanwha Wisenet L Vandal Dome", "ip_camera", None),
    (r"LNB-\d+", "Hanwha Wisenet L Bullet", "ip_camera", None),
    (r"LND-\d+", "Hanwha Wisenet L Dome", "ip_camera", None),
    (r"LNO-\d+", "Hanwha Wisenet L Bullet", "ip_camera", None),

    # NVR/DVR
    (r"XRN-\d+", "Hanwha Wisenet X NVR", "nvr", None),
    (r"PRN-\d+", "Hanwha Wisenet P NVR", "nvr", None),
    (r"QRN-\d+", "Hanwha Wisenet Q NVR", "nvr", None),
    (r"HRX-\d+", "Hanwha Wisenet DVR", "dvr", None),

    # WAVE VMS
    (r"WAVE", "Hanwha WAVE VMS", "vms", None),

    # Generic/Legacy Samsung
    (r"Wisenet", "Hanwha Wisenet Camera", "ip_camera", None),
    (r"Samsung.*SNV", "Samsung Wisenet Vandal Dome", "ip_camera", None),
    (r"Samsung.*SNB", "Samsung Wisenet Bullet", "ip_camera", None),
    (r"Samsung.*SND", "Samsung Wisenet Dome", "ip_camera", None),
    (r"Samsung.*SNP", "Samsung Wisenet PTZ", "ptz_camera", None),
]


# FOSCAM CAMERA PATTERNS

FOSCAM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Foscam
}

FOSCAM_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Indoor Cameras - require Foscam prefix to avoid matching generic patterns
    (r"Foscam\s*FI\d{4}W", "Foscam Indoor WiFi Camera", "ip_camera", None),
    (r"Foscam\s*R\d+", "Foscam R-Series PTZ", "ptz_camera", None),
    (r"Foscam\s*R4S", "Foscam R4S 4MP PTZ", "ptz_camera", None),
    (r"Foscam\s*R2M", "Foscam R2M 2MP PTZ", "ptz_camera", None),
    (r"Foscam\s*X\d+", "Foscam X-Series", "ip_camera", None),
    (r"Foscam\s*X5", "Foscam X5 5MP", "ip_camera", None),

    # Outdoor Cameras
    (r"Foscam\s*FI\d{4}", "Foscam Outdoor Camera", "ip_camera", None),
    (r"Foscam\s*G\d+", "Foscam G-Series Outdoor", "ip_camera", None),
    (r"Foscam\s*G4P", "Foscam G4P 4MP Bullet", "ip_camera", None),
    (r"Foscam\s*G4EP", "Foscam G4EP 4MP Dome", "ip_camera", None),
    (r"Foscam\s*SD\d+", "Foscam SD-Series PTZ", "ptz_camera", None),
    (r"Foscam\s*SD4H", "Foscam SD4H 4MP PTZ", "ptz_camera", None),

    # Battery Cameras
    (r"Foscam\s*E1", "Foscam E1 Wire-Free", "ip_camera", None),
    (r"Foscam\s*S1", "Foscam S1 Spotlight", "ip_camera", None),

    # Doorbell
    (r"Foscam\s*VD1", "Foscam Video Doorbell", "doorbell_camera", None),

    # NVR
    (r"Foscam\s*FN\d{4}", "Foscam NVR", "nvr", None),
    (r"Foscam\s*FN7108HE", "Foscam FN7108HE 8CH NVR", "nvr", None),

    # Generic
    (r"Foscam", "Foscam Camera", "ip_camera", None),
]


# ARLO CAMERA PATTERNS

ARLO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Arlo Technologies (NETGEAR subsidiary)
    # REMOVED: C4:05:28 - IEEE assigns to Huawei Technologies, not Arlo
}

ARLO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Pro Series
    (r"Arlo\s*Pro\s*5", "Arlo Pro 5 2K", "ip_camera", None),
    (r"Arlo\s*Pro\s*4", "Arlo Pro 4", "ip_camera", None),
    (r"Arlo\s*Pro\s*3", "Arlo Pro 3", "ip_camera", None),
    (r"Arlo\s*Pro\s*2", "Arlo Pro 2", "ip_camera", None),
    (r"Arlo\s*Pro", "Arlo Pro", "ip_camera", None),

    # Ultra Series
    (r"Arlo\s*Ultra\s*2", "Arlo Ultra 2", "ip_camera", None),
    (r"Arlo\s*Ultra", "Arlo Ultra 4K", "ip_camera", None),

    # Essential Series
    (r"Arlo\s*Essential.*XL", "Arlo Essential XL", "ip_camera", None),
    (r"Arlo\s*Essential.*Spotlight", "Arlo Essential Spotlight", "ip_camera", None),
    (r"Arlo\s*Essential.*Indoor", "Arlo Essential Indoor", "ip_camera", None),
    (r"Arlo\s*Essential", "Arlo Essential", "ip_camera", None),

    # Go Series (Mobile)
    (r"Arlo\s*Go\s*2", "Arlo Go 2", "ip_camera", None),
    (r"Arlo\s*Go", "Arlo Go LTE", "ip_camera", None),

    # Floodlight
    (r"Arlo\s*Floodlight", "Arlo Floodlight", "ip_camera", None),

    # Doorbell
    (r"Arlo.*Doorbell.*Wired", "Arlo Video Doorbell Wired", "doorbell_camera", None),
    (r"Arlo.*Doorbell.*Wire-Free", "Arlo Video Doorbell", "doorbell_camera", None),
    (r"Arlo.*Doorbell", "Arlo Video Doorbell", "doorbell_camera", None),

    # Base Stations
    (r"Arlo\s*SmartHub", "Arlo SmartHub", "iot_hub", None),
    (r"Arlo.*Base.*Station", "Arlo Base Station", "iot_hub", None),
    (r"VMB\d+", "Arlo Base Station", "iot_hub", None),

    # Generic
    (r"Arlo", "Arlo Camera", "ip_camera", None),
]


# EUFY CAMERA PATTERNS

EUFY_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Eufy (Anker subsidiary)
}

EUFY_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Indoor Cameras
    (r"Indoor\s*Cam\s*S350", "eufy Indoor Cam S350", "ip_camera", None),
    (r"Indoor\s*Cam\s*C220", "eufy Indoor Cam C220", "ip_camera", None),
    (r"Indoor\s*Cam\s*2K", "eufy Indoor Cam 2K", "ip_camera", None),
    (r"Indoor\s*Cam", "eufy Indoor Cam", "ip_camera", None),

    # Outdoor Cameras
    (r"Cam\s*3", "eufy Cam 3", "ip_camera", None),
    (r"Cam\s*2\s*Pro", "eufy Cam 2 Pro", "ip_camera", None),
    (r"Cam\s*2C", "eufy Cam 2C", "ip_camera", None),
    (r"Cam\s*2", "eufy Cam 2", "ip_camera", None),
    (r"SoloCam.*S340", "eufy SoloCam S340", "ip_camera", None),
    (r"SoloCam.*S230", "eufy SoloCam S230", "ip_camera", None),
    (r"SoloCam.*L40", "eufy SoloCam L40", "ip_camera", None),
    (r"SoloCam", "eufy SoloCam", "ip_camera", None),

    # Floodlight Cameras
    (r"Floodlight\s*Cam\s*E340", "eufy Floodlight Cam E340", "ip_camera", None),
    (r"Floodlight\s*Cam\s*S330", "eufy Floodlight Cam S330", "ip_camera", None),
    (r"Floodlight\s*Cam", "eufy Floodlight Cam", "ip_camera", None),

    # Doorbell
    (r"Doorbell.*Dual", "eufy Video Doorbell Dual", "doorbell_camera", None),
    (r"Doorbell.*S330", "eufy Video Doorbell S330", "doorbell_camera", None),
    (r"Doorbell.*E340", "eufy Video Doorbell E340", "doorbell_camera", None),
    (r"Doorbell.*2K", "eufy Video Doorbell 2K", "doorbell_camera", None),
    (r"Doorbell", "eufy Video Doorbell", "doorbell_camera", None),

    # HomeBase
    (r"HomeBase\s*3", "eufy HomeBase 3", "iot_hub", None),
    (r"HomeBase\s*2", "eufy HomeBase 2", "iot_hub", None),
    (r"HomeBase", "eufy HomeBase", "iot_hub", None),

    # Garage Camera
    (r"Garage.*Cam", "eufy Garage-Control Cam", "ip_camera", None),

    # Generic
    (r"eufy", "eufy Camera", "ip_camera", None),
    (r"eufyCam", "eufy Camera", "ip_camera", None),
]


# BOSCH SECURITY CAMERA PATTERNS

BOSCH_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Bosch Security Systems
    # REMOVED: 00:1D:D8 - IEEE assigns to Unknown, not BOSCH
}

BOSCH_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # FLEXIDOME
    (r"FLEXIDOME.*IP.*8000i", "Bosch FLEXIDOME IP 8000i", "ip_camera", None),
    (r"FLEXIDOME.*IP.*5000i", "Bosch FLEXIDOME IP 5000i", "ip_camera", None),
    (r"FLEXIDOME.*IP.*4000i", "Bosch FLEXIDOME IP 4000i", "ip_camera", None),
    (r"FLEXIDOME.*IP.*3000i", "Bosch FLEXIDOME IP 3000i", "ip_camera", None),
    (r"NDE-\d+", "Bosch FLEXIDOME", "ip_camera", None),
    (r"NDV-\d+", "Bosch FLEXIDOME Vandal", "ip_camera", None),
    (r"NIN-\d+", "Bosch FLEXIDOME IR", "ip_camera", None),

    # DINION
    (r"DINION.*IP.*8000", "Bosch DINION IP 8000", "ip_camera", None),
    (r"DINION.*IP.*5000", "Bosch DINION IP 5000", "ip_camera", None),
    (r"DINION.*IP.*4000", "Bosch DINION IP 4000", "ip_camera", None),
    (r"NBN-\d+", "Bosch DINION Bullet", "ip_camera", None),
    (r"NBE-\d+", "Bosch DINION", "ip_camera", None),

    # AUTODOME
    (r"AUTODOME.*IP.*7000", "Bosch AUTODOME IP 7000", "ptz_camera", None),
    (r"AUTODOME.*IP.*5000", "Bosch AUTODOME IP 5000", "ptz_camera", None),
    (r"NDP-\d+", "Bosch AUTODOME PTZ", "ptz_camera", None),

    # MIC (Moving/Positioning)
    (r"MIC.*IP.*fusion", "Bosch MIC IP Fusion", "ptz_camera", None),
    (r"MIC.*IP.*starlight", "Bosch MIC IP Starlight", "ptz_camera", None),
    (r"MIC-\d+", "Bosch MIC PTZ", "ptz_camera", None),

    # NVR/DIVAR
    (r"DIVAR.*IP.*7000", "Bosch DIVAR IP 7000", "nvr", None),
    (r"DIVAR.*IP.*6000", "Bosch DIVAR IP 6000", "nvr", None),
    (r"DIVAR.*IP.*5000", "Bosch DIVAR IP 5000", "nvr", None),
    (r"DIVAR.*IP", "Bosch DIVAR IP", "nvr", None),

    # BVMS
    (r"BVMS", "Bosch Video Management System", "vms", None),

    # Generic
    (r"Bosch.*Security", "Bosch Security Camera", "ip_camera", None),
]


# UNIVIEW CAMERA PATTERNS

UNIVIEW_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Uniview / Zhejiang Uniview Technologies
}

UNIVIEW_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Prime Series
    (r"IPC68\d+", "Uniview Prime Dome", "ip_camera", None),
    (r"IPC66\d+", "Uniview Prime PTZ", "ptz_camera", None),
    (r"IPC38\d+", "Uniview Prime Bullet", "ip_camera", None),
    (r"IPC36\d+", "Uniview Prime Turret", "ip_camera", None),
    (r"IPC32\d+", "Uniview Prime Dome", "ip_camera", None),

    # Pro Series
    (r"IPC2\d{3}", "Uniview Pro Camera", "ip_camera", None),
    (r"IPC3\d{3}", "Uniview Pro Bullet", "ip_camera", None),

    # Easy Series
    (r"IPC21\d+", "Uniview Easy Dome", "ip_camera", None),
    (r"IPC23\d+", "Uniview Easy Bullet", "ip_camera", None),
    (r"IPC25\d+", "Uniview Easy Turret", "ip_camera", None),

    # ColorHunter
    (r"ColorHunter", "Uniview ColorHunter", "ip_camera", None),

    # LightHunter
    (r"LightHunter", "Uniview LightHunter", "ip_camera", None),

    # NVR
    (r"NVR30\d+", "Uniview 32CH NVR", "nvr", None),
    (r"NVR50\d+", "Uniview Enterprise NVR", "nvr", None),
    (r"NVR20\d+", "Uniview NVR", "nvr", None),

    # Generic
    (r"Uniview", "Uniview Camera", "ip_camera", None),
    (r"UNV", "Uniview Camera", "ip_camera", None),
]


# PELCO CAMERA PATTERNS

PELCO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Pelco by Motorola Solutions
    # REMOVED: 00:1E:C0 - IEEE assigns to Unknown, not PELCO
}

PELCO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Sarix Series
    (r"Sarix.*Pro\s*4", "Pelco Sarix Pro 4", "ip_camera", None),
    (r"Sarix.*Pro\s*3", "Pelco Sarix Pro 3", "ip_camera", None),
    (r"Sarix.*Value", "Pelco Sarix Value", "ip_camera", None),
    (r"Sarix.*Enhanced", "Pelco Sarix Enhanced", "ip_camera", None),
    (r"Sarix", "Pelco Sarix", "ip_camera", None),
    (r"IXE\d+", "Pelco Sarix Series", "ip_camera", None),
    (r"IXP\d+", "Pelco Sarix Pro", "ip_camera", None),
    (r"IME\d+", "Pelco Sarix Mini", "ip_camera", None),

    # Spectra Series (PTZ)
    (r"Spectra.*Pro.*4K", "Pelco Spectra Pro 4K", "ptz_camera", None),
    (r"Spectra.*Pro", "Pelco Spectra Pro", "ptz_camera", None),
    (r"Spectra.*Enhanced", "Pelco Spectra Enhanced", "ptz_camera", None),
    (r"Spectra", "Pelco Spectra", "ptz_camera", None),
    (r"SD\d+-\d+", "Pelco Spectra", "ptz_camera", None),

    # Optera Series (Panoramic)
    (r"Optera\s*4K", "Pelco Optera 4K Panoramic", "ip_camera", None),
    (r"Optera", "Pelco Optera Panoramic", "ip_camera", None),
    (r"IMM\d+", "Pelco Optera", "ip_camera", None),

    # ExSite
    (r"ExSite.*Enhanced", "Pelco ExSite Enhanced", "ip_camera", None),
    (r"ExSite", "Pelco ExSite", "ip_camera", None),

    # NVR/VMS
    (r"VXP-P2", "Pelco VideoXpert Pro 2", "nvr", None),
    (r"VXP-E2", "Pelco VideoXpert Enterprise 2", "nvr", None),
    (r"VideoXpert", "Pelco VideoXpert", "nvr", None),
    (r"DX\d+", "Pelco DVR", "dvr", None),

    # Generic
    (r"Pelco", "Pelco Camera", "ip_camera", None),
]


# GEOVISION CAMERA PATTERNS

GEOVISION_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # GeoVision Inc.
    "00:13:E2": ("ip_camera", "Surveillance", "GeoVision Camera"),
    "00:2A:7E": ("ip_camera", "Surveillance", "GeoVision Camera"),
}

GEOVISION_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Bullet Cameras
    (r"GV-ABL\d+", "GeoVision Bullet Camera", "ip_camera", None),
    (r"GV-BL\d+", "GeoVision Bullet", "ip_camera", None),
    (r"GV-TBL\d+", "GeoVision Target Bullet", "ip_camera", None),

    # Dome Cameras
    (r"GV-ADR\d+", "GeoVision AI Dome", "ip_camera", None),
    (r"GV-EFD\d+", "GeoVision Fisheye Dome", "ip_camera", None),
    (r"GV-EVD\d+", "GeoVision Vandal Dome", "ip_camera", None),
    (r"GV-TDR\d+", "GeoVision Target Dome", "ip_camera", None),
    (r"GV-FD\d+", "GeoVision Dome", "ip_camera", None),

    # PTZ Cameras
    (r"GV-SD\d+", "GeoVision PTZ Dome", "ptz_camera", None),
    (r"GV-PPTZ\d+", "GeoVision PTZ", "ptz_camera", None),

    # Turret
    (r"GV-TFD\d+", "GeoVision Turret", "ip_camera", None),
    (r"GV-EBD\d+", "GeoVision Eyeball", "ip_camera", None),

    # NVR/DVR
    (r"GV-NVR", "GeoVision NVR", "nvr", None),
    (r"GV-SNVR\d+", "GeoVision NVR", "nvr", None),
    (r"GV-DVR", "GeoVision DVR", "dvr", None),

    # Access Control
    (r"GV-AS\d+", "GeoVision Access Controller", "access_controller", None),

    # Generic
    (r"GeoVision", "GeoVision Camera", "ip_camera", None),
    (r"GV-", "GeoVision Device", "ip_camera", None),
]


# MOBOTIX CAMERA PATTERNS

MOBOTIX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # MOBOTIX AG
    # REMOVED: 00:03:C5 - IEEE assigns to Unknown, not MOBOTIX
}

MOBOTIX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # MOVE Series
    (r"MOVE.*VandalDome", "MOBOTIX MOVE VandalDome", "ip_camera", None),
    (r"MOVE.*SpeedDome", "MOBOTIX MOVE SpeedDome", "ptz_camera", None),
    (r"MOVE.*Bullet", "MOBOTIX MOVE Bullet", "ip_camera", None),
    (r"MOVE", "MOBOTIX MOVE", "ip_camera", None),

    # M-Series (Hemispheric) - require MOBOTIX prefix to avoid conflicts
    (r"MOBOTIX\s*M73", "MOBOTIX M73", "ip_camera", None),
    (r"MOBOTIX\s*M16", "MOBOTIX M16", "ip_camera", None),
    (r"MOBOTIX\s*M26", "MOBOTIX M26", "ip_camera", None),
    (r"MOBOTIX\s*M\d+", "MOBOTIX M-Series", "ip_camera", None),

    # S-Series - require MOBOTIX prefix to avoid matching Samsung S24 etc
    (r"MOBOTIX\s*S74", "MOBOTIX S74", "ip_camera", None),
    (r"MOBOTIX\s*S16", "MOBOTIX S16", "ip_camera", None),
    (r"MOBOTIX\s*S26", "MOBOTIX S26", "ip_camera", None),
    (r"MOBOTIX\s*S\d+", "MOBOTIX S-Series", "ip_camera", None),

    # D-Series (Dome) - require MOBOTIX prefix
    (r"MOBOTIX\s*D71", "MOBOTIX D71", "ip_camera", None),
    (r"MOBOTIX\s*D16", "MOBOTIX D16", "ip_camera", None),
    (r"MOBOTIX\s*D26", "MOBOTIX D26", "ip_camera", None),
    (r"MOBOTIX\s*D\d+", "MOBOTIX D-Series", "ip_camera", None),

    # P-Series
    (r"MOBOTIX\s*P26", "MOBOTIX P26", "ip_camera", None),

    # Q-Series
    (r"MOBOTIX\s*Q71", "MOBOTIX Q71", "ip_camera", None),
    (r"MOBOTIX\s*Q26", "MOBOTIX Q26", "ip_camera", None),

    # V-Series
    (r"MOBOTIX\s*V26", "MOBOTIX V26", "ip_camera", None),
    (r"MOBOTIX\s*V16", "MOBOTIX V16", "ip_camera", None),

    # Thermal
    (r"M73.*Thermal", "MOBOTIX M73 Thermal", "thermal_camera", None),
    (r"S74.*Thermal", "MOBOTIX S74 Thermal", "thermal_camera", None),

    # Generic
    (r"MOBOTIX", "MOBOTIX Camera", "ip_camera", None),
]


# AVIGILON (MOTOROLA) CAMERA PATTERNS

AVIGILON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Avigilon (Motorola Solutions)
    # REMOVED: 00:18:85 - IEEE assigns to Unknown, not AVIGILON
    # REMOVED: 00:1E:C0 - IEEE assigns to Unknown, not AVIGILON
}

AVIGILON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # H5A (AI-enabled)
    (r"H5A.*Dome", "Avigilon H5A Dome", "ip_camera", None),
    (r"H5A.*Bullet", "Avigilon H5A Bullet", "ip_camera", None),
    (r"H5A.*PTZ", "Avigilon H5A PTZ", "ptz_camera", None),
    (r"H5A.*Fisheye", "Avigilon H5A Fisheye", "ip_camera", None),
    (r"H5A", "Avigilon H5A", "ip_camera", None),

    # H5 Pro
    (r"H5.*Pro", "Avigilon H5 Pro", "ip_camera", None),

    # H5M
    (r"H5M", "Avigilon H5M Mini Dome", "ip_camera", None),

    # H5SL
    (r"H5SL", "Avigilon H5SL", "ip_camera", None),

    # H4 Series
    (r"H4A.*PTZ", "Avigilon H4A PTZ", "ptz_camera", None),
    (r"H4.*Multisensor", "Avigilon H4 Multisensor", "ip_camera", None),
    (r"H4A", "Avigilon H4A", "ip_camera", None),

    # Legacy H3
    (r"H3.*PTZ", "Avigilon H3 PTZ", "ptz_camera", None),
    (r"H3", "Avigilon H3", "ip_camera", None),

    # NVR/ACC
    (r"NVR\d+.*Pro", "Avigilon NVR Pro", "nvr", None),
    (r"ACC\s*7", "Avigilon ACC 7", "nvr", None),
    (r"ACC.*Enterprise", "Avigilon ACC Enterprise", "nvr", None),
    (r"ACC", "Avigilon Control Center", "nvr", None),

    # Alta (Cloud)
    (r"Alta", "Avigilon Alta Cloud", "ip_camera", None),

    # Generic
    (r"Avigilon", "Avigilon Camera", "ip_camera", None),
]


# VERKADA CAMERA PATTERNS

VERKADA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verkada Inc.
    # REMOVED: 44:17:93 - IEEE assigns to Unknown, not VERKADA
}

VERKADA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Indoor Cameras
    (r"CD\d{2}", "Verkada Indoor Dome", "ip_camera", None),
    (r"CD62", "Verkada CD62 Indoor", "ip_camera", None),
    (r"CD52", "Verkada CD52 Indoor", "ip_camera", None),
    (r"CD42", "Verkada CD42 Indoor", "ip_camera", None),
    (r"CD32", "Verkada CD32 Indoor", "ip_camera", None),

    # Outdoor Cameras
    (r"CB\d{2}", "Verkada Outdoor Bullet", "ip_camera", None),
    (r"CB62", "Verkada CB62 Bullet", "ip_camera", None),
    (r"CB52", "Verkada CB52 Bullet", "ip_camera", None),

    # Mini Cameras
    (r"CM\d{2}", "Verkada Mini", "ip_camera", None),
    (r"CM61", "Verkada CM61 Mini", "ip_camera", None),
    (r"CM41", "Verkada CM41 Mini", "ip_camera", None),

    # Dome
    (r"D\d{2}", "Verkada Dome", "ip_camera", None),

    # Fisheye
    (r"CF\d{2}", "Verkada Fisheye", "ip_camera", None),
    (r"CF81", "Verkada CF81 Fisheye", "ip_camera", None),

    # Intercom
    (r"TD52", "Verkada Video Intercom", "intercom", None),
    (r"TD\d{2}", "Verkada Intercom", "intercom", None),

    # Access Control
    (r"AD31", "Verkada Access Controller", "access_controller", None),
    (r"AC\d{2}", "Verkada Access Controller", "access_controller", None),

    # Sensors
    (r"SV\d{2}", "Verkada Environmental Sensor", "sensor", None),

    # Generic
    (r"Verkada", "Verkada Camera", "ip_camera", None),
]


# TV VENDOR PATTERNS

# SONY TV PATTERNS
SONY_TV_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Sony Corporation
    "00:01:4A": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "00:0A:D9": ("smart_tv", "Consumer Electronics", "Sony Device"),
    # REMOVED: 00:0D:4B - IEEE assigns to Unknown, not SONY_TV
    "00:13:A9": ("smart_tv", "Consumer Electronics", "Sony Device"),
    "00:18:13": ("smart_tv", "Consumer Electronics", "Sony Device"),
    "00:1A:80": ("smart_tv", "Consumer Electronics", "Sony Device"),
    "00:1D:28": ("smart_tv", "Consumer Electronics", "Sony TV"),
    # REMOVED: 00:24:BE - IEEE assigns to Unknown, not SONY_TV
    "28:3F:69": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "30:17:C8": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "40:B8:37": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "54:42:49": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "70:9E:29": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "78:84:3C": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "AC:9B:0A": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "B4:52:7E": ("smart_tv", "Consumer Electronics", "Sony TV"),
    "FC:F1:52": ("smart_tv", "Consumer Electronics", "Sony TV"),
}

SONY_TV_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # BRAVIA Series
    (r"BRAVIA.*XR.*A95L", "Sony BRAVIA XR A95L OLED", "smart_tv", "Google TV"),
    (r"BRAVIA.*XR.*A80L", "Sony BRAVIA XR A80L OLED", "smart_tv", "Google TV"),
    (r"BRAVIA.*XR.*X95L", "Sony BRAVIA XR X95L", "smart_tv", "Google TV"),
    (r"BRAVIA.*XR.*X90L", "Sony BRAVIA XR X90L", "smart_tv", "Google TV"),
    (r"BRAVIA.*XR", "Sony BRAVIA XR", "smart_tv", "Google TV"),
    (r"BRAVIA.*4K", "Sony BRAVIA 4K", "smart_tv", "Google TV"),
    (r"BRAVIA.*8K", "Sony BRAVIA 8K", "smart_tv", "Google TV"),
    (r"BRAVIA", "Sony BRAVIA TV", "smart_tv", "Google TV"),

    # Model Numbers
    (r"XBR-\d+X\d+", "Sony XBR 4K TV", "smart_tv", "Android TV"),
    (r"KD-\d+X\d+", "Sony 4K TV", "smart_tv", "Google TV"),
    (r"XR-\d+A\d+", "Sony OLED TV", "smart_tv", "Google TV"),
    (r"KDL-\d+W\d+", "Sony KDL Series", "smart_tv", "Android TV"),

    # PlayStation (gaming/streaming)
    (r"PlayStation\s*5", "Sony PlayStation 5", "gaming_console", "PlayStation OS"),
    (r"PlayStation\s*4", "Sony PlayStation 4", "gaming_console", "PlayStation OS"),
    (r"PS5", "Sony PlayStation 5", "gaming_console", "PlayStation OS"),
    (r"PS4", "Sony PlayStation 4", "gaming_console", "PlayStation OS"),

    # Generic
    (r"Sony.*TV", "Sony Smart TV", "smart_tv", "Google TV"),
    (r"Sony.*Android\s*TV", "Sony Android TV", "smart_tv", "Android TV"),
]

# VIZIO TV PATTERNS
VIZIO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Vizio Inc.
    "00:19:9D": ("smart_tv", "Consumer Electronics", "Vizio TV"),
    "2C:64:1F": ("smart_tv", "Consumer Electronics", "Vizio TV"),
}

VIZIO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # P-Series (Premium)
    (r"P-Series.*Quantum.*X", "Vizio P-Series Quantum X", "smart_tv", "SmartCast"),
    (r"P-Series.*Quantum", "Vizio P-Series Quantum", "smart_tv", "SmartCast"),
    (r"P\d+Q\d+-J", "Vizio P-Series Quantum", "smart_tv", "SmartCast"),

    # M-Series
    (r"M-Series.*Quantum", "Vizio M-Series Quantum", "smart_tv", "SmartCast"),
    (r"M\d+Q\d+-J", "Vizio M-Series Quantum", "smart_tv", "SmartCast"),

    # V-Series
    (r"V-Series", "Vizio V-Series", "smart_tv", "SmartCast"),
    (r"V\d+\w+-J", "Vizio V-Series", "smart_tv", "SmartCast"),

    # D-Series
    (r"D-Series", "Vizio D-Series", "smart_tv", "SmartCast"),
    (r"D\d+\w+-D", "Vizio D-Series", "smart_tv", "SmartCast"),

    # OLED
    (r"OLED.*4K", "Vizio OLED 4K", "smart_tv", "SmartCast"),
    (r"OLED\d+-H", "Vizio OLED", "smart_tv", "SmartCast"),

    # Soundbars
    (r"Elevate", "Vizio Elevate Soundbar", "soundbar", None),
    (r"M-Series.*Soundbar", "Vizio M-Series Soundbar", "soundbar", None),
    (r"V-Series.*Soundbar", "Vizio V-Series Soundbar", "soundbar", None),

    # Generic
    (r"SmartCast", "Vizio SmartCast TV", "smart_tv", "SmartCast"),
    (r"VIZIO", "Vizio TV", "smart_tv", "SmartCast"),
]

# TCL TV PATTERNS
TCL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # TCL Corporation
    # REMOVED: 10:68:3F - IEEE assigns to Unknown, not TCL
    # REMOVED: 50:55:27 - IEEE assigns to Unknown, not TCL
}

TCL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # QM-Series (Premium)
    (r"QM8.*Class", "TCL QM8 QLED", "smart_tv", "Google TV"),
    (r"QM7.*Class", "TCL QM7 QLED", "smart_tv", "Google TV"),
    (r"Q7.*Class", "TCL Q7 QLED", "smart_tv", "Google TV"),
    (r"Q6.*Class", "TCL Q6 QLED", "smart_tv", "Google TV"),

    # S-Series
    (r"S5.*Class", "TCL S5 Series", "smart_tv", "Google TV"),
    (r"S4.*Class", "TCL S4 Series", "smart_tv", "Google TV"),
    (r"S3.*Class", "TCL S3 Series", "smart_tv", "Roku TV"),

    # Roku TVs
    (r"TCL.*Roku", "TCL Roku TV", "smart_tv", "Roku TV"),
    (r"\d+S\d+", "TCL S-Class Roku TV", "smart_tv", "Roku TV"),
    (r"\d+R\d+", "TCL R-Series Roku TV", "smart_tv", "Roku TV"),

    # Model patterns
    (r"65Q\d+", "TCL 65\" QLED", "smart_tv", "Google TV"),
    (r"55Q\d+", "TCL 55\" QLED", "smart_tv", "Google TV"),
    (r"75S\d+", "TCL 75\" Smart TV", "smart_tv", "Google TV"),
    (r"65S\d+", "TCL 65\" Smart TV", "smart_tv", "Google TV"),
    (r"55S\d+", "TCL 55\" Smart TV", "smart_tv", "Google TV"),

    # Generic
    (r"TCL.*Google\s*TV", "TCL Google TV", "smart_tv", "Google TV"),
    (r"TCL.*Smart\s*TV", "TCL Smart TV", "smart_tv", "Google TV"),
    (r"TCL.*TV", "TCL TV", "smart_tv", None),
]

# HISENSE TV PATTERNS
HISENSE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Hisense Electric Co.
}

HISENSE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # U-Series (Premium)
    (r"U8N", "Hisense U8N Mini-LED", "smart_tv", "Google TV"),
    (r"U8K", "Hisense U8K Mini-LED", "smart_tv", "Google TV"),
    (r"U7K", "Hisense U7K ULED", "smart_tv", "Google TV"),
    (r"U6K", "Hisense U6K ULED", "smart_tv", "Google TV"),
    (r"ULED", "Hisense ULED TV", "smart_tv", "Google TV"),

    # A-Series
    (r"A7K", "Hisense A7K", "smart_tv", "VIDAA"),
    (r"A6K", "Hisense A6K", "smart_tv", "VIDAA"),
    (r"A4K", "Hisense A4K", "smart_tv", "VIDAA"),

    # Laser TV
    (r"Laser\s*TV.*L9", "Hisense L9 Laser TV", "projector", None),
    (r"Laser\s*TV.*PX", "Hisense PX Laser Cinema", "projector", None),
    (r"Laser\s*TV", "Hisense Laser TV", "projector", None),

    # Roku TVs
    (r"Hisense.*Roku", "Hisense Roku TV", "smart_tv", "Roku TV"),
    (r"R6.*Series", "Hisense R6 Roku TV", "smart_tv", "Roku TV"),

    # Model patterns
    (r"65U\d+N", "Hisense 65\" ULED", "smart_tv", "Google TV"),
    (r"55U\d+N", "Hisense 55\" ULED", "smart_tv", "Google TV"),
    (r"75U\d+", "Hisense 75\" 4K", "smart_tv", "Google TV"),

    # Generic
    (r"VIDAA", "Hisense VIDAA TV", "smart_tv", "VIDAA"),
    (r"Hisense.*Smart\s*TV", "Hisense Smart TV", "smart_tv", None),
    (r"Hisense", "Hisense TV", "smart_tv", None),
]


# IOT / SMART HOME DEVICE PATTERNS

# SHELLY (Smart Relays/Switches)
SHELLY_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 34:94:54 - IEEE assigns to Unknown, not SHELLY
    # REMOVED: 3C:61:05 - IEEE assigns to Unknown, not SHELLY
    # REMOVED: 44:17:93 - IEEE assigns to Unknown, not SHELLY
    # REMOVED: 84:CC:A8 - IEEE assigns to Unknown, not SHELLY
    # REMOVED: 98:CD:AC - IEEE assigns to Unknown, not SHELLY
    # REMOVED: A4:CF:12 - IEEE assigns to Unknown, not SHELLY
    # REMOVED: BC:FF:4D - IEEE assigns to Unknown, not SHELLY
    # REMOVED: C4:5B:BE - IEEE assigns to Unknown, not SHELLY
    # REMOVED: E8:DB:84 - IEEE assigns to Unknown, not SHELLY
    # REMOVED: E8:68:E7 - IEEE assigns to Unknown, not SHELLY
}

SHELLY_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Gen 3
    (r"Shelly\s*1\s*PM\s*Gen\s*3", "Shelly 1 PM Gen 3", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*1\s*Gen\s*3", "Shelly 1 Gen 3", "smart_switch", "Shelly Firmware"),
    # Gen 2
    (r"Shelly\s*Plus\s*1\s*PM", "Shelly Plus 1 PM", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*Plus\s*1", "Shelly Plus 1", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*Plus\s*2\s*PM", "Shelly Plus 2 PM", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*Pro\s*4\s*PM", "Shelly Pro 4 PM", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*Pro\s*3", "Shelly Pro 3", "smart_switch", "Shelly Firmware"),
    # Gen 1
    (r"Shelly\s*1\s*PM", "Shelly 1 PM", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*1L", "Shelly 1L", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*1", "Shelly 1", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*2\.5", "Shelly 2.5", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*2", "Shelly 2", "smart_switch", "Shelly Firmware"),
    (r"Shelly\s*Dimmer\s*2", "Shelly Dimmer 2", "dimmer", "Shelly Firmware"),
    (r"Shelly\s*Dimmer", "Shelly Dimmer", "dimmer", "Shelly Firmware"),
    (r"Shelly\s*EM", "Shelly EM", "energy_monitor", "Shelly Firmware"),
    (r"Shelly\s*3EM", "Shelly 3EM", "energy_monitor", "Shelly Firmware"),
    (r"Shelly\s*Plug\s*S", "Shelly Plug S", "smart_plug", "Shelly Firmware"),
    (r"Shelly\s*Plug", "Shelly Plug", "smart_plug", "Shelly Firmware"),
    (r"Shelly\s*RGBW2", "Shelly RGBW2", "led_controller", "Shelly Firmware"),
    (r"Shelly\s*Bulb", "Shelly Bulb", "smart_bulb", "Shelly Firmware"),
    (r"Shelly\s*Duo", "Shelly Duo", "smart_bulb", "Shelly Firmware"),
    (r"Shelly\s*H&T", "Shelly H&T Sensor", "sensor", "Shelly Firmware"),
    (r"Shelly\s*Door.*Window", "Shelly Door/Window Sensor", "sensor", "Shelly Firmware"),
    (r"Shelly\s*Motion", "Shelly Motion Sensor", "sensor", "Shelly Firmware"),
    (r"Shelly\s*Button", "Shelly Button", "smart_button", "Shelly Firmware"),
    (r"Shelly\s*i3", "Shelly i3", "smart_switch", "Shelly Firmware"),
    (r"Shelly", "Shelly Device", "smart_switch", "Shelly Firmware"),
]

# SONOFF (Smart Switches)
SONOFF_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 24:62:AB - IEEE assigns to Unknown, not SONOFF
    # REMOVED: 60:01:94 - IEEE assigns to Unknown, not SONOFF
    # REMOVED: 68:C6:3A - IEEE assigns to Unknown, not SONOFF
    # REMOVED: A0:20:A6 - IEEE assigns to Unknown, not SONOFF
    # REMOVED: DC:4F:22 - IEEE assigns to Unknown, not SONOFF
}

SONOFF_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # WiFi Switches
    (r"Sonoff\s*Basic\s*R4", "Sonoff Basic R4", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Basic\s*R3", "Sonoff Basic R3", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Basic", "Sonoff Basic", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Mini\s*R4", "Sonoff Mini R4", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Mini\s*R3", "Sonoff Mini R3", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Mini", "Sonoff Mini", "smart_switch", "eWeLink"),
    (r"Sonoff\s*4CH\s*Pro", "Sonoff 4CH Pro", "smart_switch", "eWeLink"),
    (r"Sonoff\s*4CH", "Sonoff 4CH", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Dual\s*R3", "Sonoff Dual R3", "smart_switch", "eWeLink"),
    (r"Sonoff\s*Dual", "Sonoff Dual", "smart_switch", "eWeLink"),
    (r"Sonoff\s*POW\s*R3", "Sonoff POW R3", "smart_switch", "eWeLink"),
    (r"Sonoff\s*POW", "Sonoff POW", "smart_switch", "eWeLink"),
    (r"Sonoff\s*TH\d+", "Sonoff TH", "smart_switch", "eWeLink"),
    (r"Sonoff\s*S31", "Sonoff S31", "smart_plug", "eWeLink"),
    (r"Sonoff\s*S26", "Sonoff S26", "smart_plug", "eWeLink"),
    # Sensors
    (r"Sonoff\s*SNZB-\d+", "Sonoff Zigbee Sensor", "sensor", "eWeLink"),
    (r"Sonoff\s*Zigbee\s*Bridge", "Sonoff Zigbee Bridge", "bridge", "eWeLink"),
    (r"Sonoff\s*RF\s*Bridge", "Sonoff RF Bridge", "bridge", "eWeLink"),
    (r"Sonoff", "Sonoff Device", "smart_switch", "eWeLink"),
]

# NANOLEAF (Smart Lighting)
NANOLEAF_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

NANOLEAF_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Nanoleaf\s*Shapes", "Nanoleaf Shapes", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf\s*Canvas", "Nanoleaf Canvas", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf\s*Elements", "Nanoleaf Elements", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf\s*Lines", "Nanoleaf Lines", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf\s*Essentials", "Nanoleaf Essentials", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf\s*Light\s*Panels", "Nanoleaf Light Panels", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf\s*Aurora", "Nanoleaf Aurora", "smart_light", "Nanoleaf App"),
    (r"Nanoleaf", "Nanoleaf Device", "smart_light", "Nanoleaf App"),
]

# GOVEE (Smart LED Lighting)
GOVEE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

GOVEE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Govee\s*H\d{4}", "Govee H-Series Light", "smart_light", "Govee Home"),
    (r"Govee\s*Glide", "Govee Glide", "smart_light", "Govee Home"),
    (r"Govee\s*Lyra", "Govee Lyra", "smart_light", "Govee Home"),
    (r"Govee\s*Curtain\s*Light", "Govee Curtain Light", "smart_light", "Govee Home"),
    (r"Govee\s*LED\s*Strip", "Govee LED Strip", "smart_light", "Govee Home"),
    (r"Govee\s*RGBIC", "Govee RGBIC", "smart_light", "Govee Home"),
    (r"Govee\s*TV\s*Backlight", "Govee TV Backlight", "smart_light", "Govee Home"),
    (r"Govee\s*Floor\s*Lamp", "Govee Floor Lamp", "smart_light", "Govee Home"),
    (r"Govee\s*Table\s*Lamp", "Govee Table Lamp", "smart_light", "Govee Home"),
    (r"Govee", "Govee Device", "smart_light", "Govee Home"),
]

# INSTEON (Home Automation)
INSTEON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

INSTEON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Insteon\s*Hub", "Insteon Hub", "smart_hub", "Insteon"),
    (r"Insteon\s*Dimmer", "Insteon Dimmer", "dimmer", "Insteon"),
    (r"Insteon\s*Switch", "Insteon Switch", "smart_switch", "Insteon"),
    (r"Insteon\s*Keypad", "Insteon Keypad", "smart_switch", "Insteon"),
    (r"Insteon\s*Thermostat", "Insteon Thermostat", "thermostat", "Insteon"),
    (r"Insteon\s*Motion\s*Sensor", "Insteon Motion Sensor", "sensor", "Insteon"),
    (r"Insteon\s*Leak\s*Sensor", "Insteon Leak Sensor", "sensor", "Insteon"),
    (r"Insteon\s*Open.*Close\s*Sensor", "Insteon Open/Close Sensor", "sensor", "Insteon"),
    (r"Insteon\s*Plug-in", "Insteon Plug-in Module", "smart_plug", "Insteon"),
    (r"Insteon", "Insteon Device", "smart_switch", "Insteon"),
]

# ECOVACS (Robot Vacuums)
ECOVACS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

ECOVACS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"DEEBOT\s*X2", "Ecovacs DEEBOT X2", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT\s*X1", "Ecovacs DEEBOT X1", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT\s*T20", "Ecovacs DEEBOT T20", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT\s*T10", "Ecovacs DEEBOT T10", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT\s*N10", "Ecovacs DEEBOT N10", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT\s*N8", "Ecovacs DEEBOT N8", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT\s*OZMO", "Ecovacs DEEBOT OZMO", "robot_vacuum", "Ecovacs Home"),
    (r"DEEBOT", "Ecovacs DEEBOT", "robot_vacuum", "Ecovacs Home"),
    (r"WINBOT", "Ecovacs WINBOT", "robot_cleaner", "Ecovacs Home"),
    (r"Ecovacs", "Ecovacs Device", "robot_vacuum", "Ecovacs Home"),
]

# IROBOT (Roomba Robot Vacuums)
IROBOT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "50:14:79": ("robot_vacuum", "Smart Home", "iRobot"),
}

IROBOT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Roomba j-series
    (r"Roomba\s*j9", "iRobot Roomba j9", "robot_vacuum", "iRobot Home"),
    (r"Roomba\s*j7", "iRobot Roomba j7", "robot_vacuum", "iRobot Home"),
    # Roomba s-series
    (r"Roomba\s*s9", "iRobot Roomba s9", "robot_vacuum", "iRobot Home"),
    # Roomba i-series
    (r"Roomba\s*i9", "iRobot Roomba i9", "robot_vacuum", "iRobot Home"),
    (r"Roomba\s*i8", "iRobot Roomba i8", "robot_vacuum", "iRobot Home"),
    (r"Roomba\s*i7", "iRobot Roomba i7", "robot_vacuum", "iRobot Home"),
    (r"Roomba\s*i5", "iRobot Roomba i5", "robot_vacuum", "iRobot Home"),
    (r"Roomba\s*i4", "iRobot Roomba i4", "robot_vacuum", "iRobot Home"),
    (r"Roomba\s*i3", "iRobot Roomba i3", "robot_vacuum", "iRobot Home"),
    # Roomba e-series
    (r"Roomba\s*e\d", "iRobot Roomba e-series", "robot_vacuum", "iRobot Home"),
    # Roomba 900 series
    (r"Roomba\s*9\d{2}", "iRobot Roomba 900", "robot_vacuum", "iRobot Home"),
    # Braava
    (r"Braava\s*jet\s*m6", "iRobot Braava jet m6", "robot_mop", "iRobot Home"),
    (r"Braava\s*jet", "iRobot Braava jet", "robot_mop", "iRobot Home"),
    (r"Braava", "iRobot Braava", "robot_mop", "iRobot Home"),
    # Generic
    (r"Roomba", "iRobot Roomba", "robot_vacuum", "iRobot Home"),
    (r"iRobot", "iRobot Device", "robot_vacuum", "iRobot Home"),
]

# ROBOROCK (Robot Vacuums)
ROBOROCK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "B0:4A:39": ("robot_vacuum", "Smart Home", "Roborock"),
    # REMOVED: B4:6B:FC - IEEE assigns to Unknown, not ROBOROCK
}

ROBOROCK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Roborock\s*S8\s*Pro\s*Ultra", "Roborock S8 Pro Ultra", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S8\s*MaxV", "Roborock S8 MaxV", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S8", "Roborock S8", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S7\s*MaxV", "Roborock S7 MaxV", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S7", "Roborock S7", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S6\s*MaxV", "Roborock S6 MaxV", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S6", "Roborock S6", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S5\s*Max", "Roborock S5 Max", "robot_vacuum", "Roborock"),
    (r"Roborock\s*S5", "Roborock S5", "robot_vacuum", "Roborock"),
    (r"Roborock\s*Q\d+", "Roborock Q Series", "robot_vacuum", "Roborock"),
    (r"Roborock\s*E\d+", "Roborock E Series", "robot_vacuum", "Roborock"),
    (r"Roborock", "Roborock Device", "robot_vacuum", "Roborock"),
]

# DYSON (Smart Appliances)
DYSON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

DYSON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Air Purifiers
    (r"Dyson\s*Purifier\s*Hot\+Cool", "Dyson Purifier Hot+Cool", "air_purifier", "Dyson Link"),
    (r"Dyson\s*Purifier\s*Cool", "Dyson Purifier Cool", "air_purifier", "Dyson Link"),
    (r"Dyson\s*Purifier\s*Humidify", "Dyson Purifier Humidify", "air_purifier", "Dyson Link"),
    (r"Dyson\s*Pure\s*Hot\+Cool", "Dyson Pure Hot+Cool", "air_purifier", "Dyson Link"),
    (r"Dyson\s*Pure\s*Cool", "Dyson Pure Cool", "air_purifier", "Dyson Link"),
    (r"Dyson\s*TP\d{2}", "Dyson Pure Cool", "air_purifier", "Dyson Link"),
    (r"Dyson\s*HP\d{2}", "Dyson Pure Hot+Cool", "air_purifier", "Dyson Link"),
    (r"Dyson\s*PH\d{2}", "Dyson Pure Humidify", "air_purifier", "Dyson Link"),
    # Fans
    (r"Dyson\s*AM\d{2}", "Dyson Air Multiplier Fan", "fan", "Dyson Link"),
    (r"Dyson\s*Cool", "Dyson Cool Fan", "fan", "Dyson Link"),
    # Humidifiers
    (r"Dyson\s*Humidifier", "Dyson Humidifier", "humidifier", "Dyson Link"),
    # Robot Vacuum
    (r"Dyson\s*360\s*Vis\s*Nav", "Dyson 360 Vis Nav", "robot_vacuum", "Dyson Link"),
    (r"Dyson\s*360\s*Heurist", "Dyson 360 Heurist", "robot_vacuum", "Dyson Link"),
    (r"Dyson\s*360\s*Eye", "Dyson 360 Eye", "robot_vacuum", "Dyson Link"),
    (r"Dyson\s*360", "Dyson 360 Robot", "robot_vacuum", "Dyson Link"),
    # Generic
    (r"Dyson", "Dyson Device", "smart_appliance", "Dyson Link"),
]

# XIAOMI (Smart Devices)
XIAOMI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:9E:C8": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "04:CF:8C": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "0C:1D:AF": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "14:F6:5A": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "20:34:FB": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "28:6C:07": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "34:80:B3": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "38:A4:ED": ("smart_device", "Consumer Electronics", "Xiaomi"),
    # REMOVED: 3C:BD:D8 - IEEE assigns to Unknown, not XIAOMI
    "58:44:98": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "64:09:80": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "64:CC:2E": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "78:02:F8": ("smart_device", "Consumer Electronics", "Xiaomi"),
    # REMOVED: 78:11:DC - IEEE assigns to Unknown, not XIAOMI
    # REMOVED: 7C:1C:4E - IEEE assigns to Unknown, not XIAOMI
    "84:4E:FC": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "8C:DE:F9": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "98:FA:E3": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "AC:C1:EE": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "B0:E2:35": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "C4:0B:CB": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "D4:97:0B": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "EC:D0:9F": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "F0:B4:29": ("smart_device", "Consumer Electronics", "Xiaomi"),
    "FC:64:BA": ("smart_device", "Consumer Electronics", "Xiaomi"),
}

XIAOMI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Phones
    (r"Xiaomi\s*14", "Xiaomi 14", "smartphone", "MIUI"),
    (r"Xiaomi\s*13", "Xiaomi 13", "smartphone", "MIUI"),
    (r"Xiaomi\s*12", "Xiaomi 12", "smartphone", "MIUI"),
    (r"Redmi\s*Note\s*\d+", "Redmi Note", "smartphone", "MIUI"),
    (r"Redmi\s*\d+", "Redmi", "smartphone", "MIUI"),
    (r"POCO\s*\w+", "POCO", "smartphone", "MIUI"),
    # Smart Home
    (r"Mi\s*Robot\s*Vacuum", "Xiaomi Mi Robot Vacuum", "robot_vacuum", "Mi Home"),
    (r"Mi\s*Air\s*Purifier", "Xiaomi Mi Air Purifier", "air_purifier", "Mi Home"),
    (r"Mi\s*Smart\s*Band", "Xiaomi Mi Smart Band", "fitness_tracker", "Mi Fitness"),
    (r"Mi\s*TV", "Xiaomi Mi TV", "smart_tv", "Mi Home"),
    (r"Mi\s*Box", "Xiaomi Mi Box", "media_player", "Mi Home"),
    (r"Mi\s*Router", "Xiaomi Mi Router", "router", "Mi Home"),
    (r"Xiaomi", "Xiaomi Device", "smart_device", "Mi Home"),
    (r"Mi\s*Smart", "Xiaomi Mi Smart", "smart_device", "Mi Home"),
]

# ONEPLUS (Smartphones)
ONEPLUS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:17:C8 - IEEE assigns to Unknown, not ONEPLUS
    "94:65:2D": ("smartphone", "Mobile", "OnePlus"),
    # REMOVED: 94:D9:B3 - IEEE assigns to Unknown, not ONEPLUS
    "C0:EE:FB": ("smartphone", "Mobile", "OnePlus"),
    # Additional OnePlus OUIs
    "04:A2:17": ("smartphone", "Mobile", "OnePlus"),
    "50:19:29": ("smartphone", "Mobile", "OnePlus"),
}

ONEPLUS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"OnePlus\s*12", "OnePlus 12", "smartphone", "OxygenOS"),
    (r"OnePlus\s*11", "OnePlus 11", "smartphone", "OxygenOS"),
    (r"OnePlus\s*10\s*Pro", "OnePlus 10 Pro", "smartphone", "OxygenOS"),
    (r"OnePlus\s*10T", "OnePlus 10T", "smartphone", "OxygenOS"),
    (r"OnePlus\s*10", "OnePlus 10", "smartphone", "OxygenOS"),
    (r"OnePlus\s*Nord\s*3", "OnePlus Nord 3", "smartphone", "OxygenOS"),
    (r"OnePlus\s*Nord\s*CE", "OnePlus Nord CE", "smartphone", "OxygenOS"),
    (r"OnePlus\s*Nord\s*N\d+", "OnePlus Nord N", "smartphone", "OxygenOS"),
    (r"OnePlus\s*Nord", "OnePlus Nord", "smartphone", "OxygenOS"),
    (r"OnePlus\s*Open", "OnePlus Open", "smartphone", "OxygenOS"),
    (r"OnePlus\s*Pad", "OnePlus Pad", "tablet", "OxygenOS"),
    (r"OnePlus\s*Watch", "OnePlus Watch", "smartwatch", "RTOS"),
    (r"OnePlus\s*Buds", "OnePlus Buds", "earbuds", None),
    (r"OnePlus", "OnePlus Device", "smartphone", "OxygenOS"),
]

# OPPO (Smartphones)
OPPO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 28:6E:D4 - IEEE assigns to Huawei Technologies, not OPPO
    # REMOVED: 54:A0:50 - IEEE assigns to Unknown, not OPPO
    # REMOVED: 5C:2E:59 - IEEE assigns to Unknown, not OPPO
    # REMOVED: 64:CC:2E - IEEE assigns to Unknown, not OPPO
    "8C:0E:E3": ("smartphone", "Mobile", "OPPO"),
    "B4:0A:CA": ("smartphone", "Mobile", "OPPO"),
    "D4:50:3F": ("smartphone", "Mobile", "OPPO"),
    # REMOVED: EC:F0:FE - IEEE assigns to Unknown, not OPPO
}

OPPO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"OPPO\s*Find\s*X7", "OPPO Find X7", "smartphone", "ColorOS"),
    (r"OPPO\s*Find\s*X6", "OPPO Find X6", "smartphone", "ColorOS"),
    (r"OPPO\s*Find\s*X5", "OPPO Find X5", "smartphone", "ColorOS"),
    (r"OPPO\s*Find\s*N3", "OPPO Find N3", "smartphone", "ColorOS"),
    (r"OPPO\s*Find\s*N2", "OPPO Find N2", "smartphone", "ColorOS"),
    (r"OPPO\s*Find", "OPPO Find", "smartphone", "ColorOS"),
    (r"OPPO\s*Reno\s*\d+", "OPPO Reno", "smartphone", "ColorOS"),
    (r"OPPO\s*A\d+", "OPPO A Series", "smartphone", "ColorOS"),
    (r"OPPO\s*F\d+", "OPPO F Series", "smartphone", "ColorOS"),
    (r"OPPO\s*K\d+", "OPPO K Series", "smartphone", "ColorOS"),
    (r"OPPO\s*Pad", "OPPO Pad", "tablet", "ColorOS"),
    (r"OPPO\s*Watch", "OPPO Watch", "smartwatch", "ColorOS Watch"),
    (r"OPPO\s*Enco", "OPPO Enco", "earbuds", None),
    (r"OPPO", "OPPO Device", "smartphone", "ColorOS"),
]

# VIVO (Smartphones)
VIVO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 34:CE:00 - IEEE assigns to Unknown, not VIVO
    # REMOVED: 4C:49:E3 - IEEE assigns to Unknown, not VIVO
    # REMOVED: 78:44:76 - IEEE assigns to Unknown, not VIVO
    "BC:1A:EA": ("smartphone", "Mobile", "Vivo"),
}

VIVO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"vivo\s*X\d+\s*Pro", "Vivo X Pro", "smartphone", "Funtouch OS"),
    (r"vivo\s*X\d+", "Vivo X Series", "smartphone", "Funtouch OS"),
    (r"vivo\s*V\d+", "Vivo V Series", "smartphone", "Funtouch OS"),
    (r"vivo\s*Y\d+", "Vivo Y Series", "smartphone", "Funtouch OS"),
    (r"vivo\s*T\d+", "Vivo T Series", "smartphone", "Funtouch OS"),
    (r"vivo\s*S\d+", "Vivo S Series", "smartphone", "Funtouch OS"),
    (r"iQOO\s*\d+\s*Pro", "iQOO Pro", "smartphone", "Funtouch OS"),
    (r"iQOO\s*Neo\s*\d+", "iQOO Neo", "smartphone", "Funtouch OS"),
    (r"iQOO\s*\d+", "iQOO", "smartphone", "Funtouch OS"),
    (r"iQOO", "iQOO Device", "smartphone", "Funtouch OS"),
    (r"vivo\s*Pad", "Vivo Pad", "tablet", "OriginOS"),
    (r"vivo\s*Watch", "Vivo Watch", "smartwatch", None),
    (r"vivo\s*TWS", "Vivo TWS", "earbuds", None),
    (r"vivo", "Vivo Device", "smartphone", "Funtouch OS"),
]

# REALME (Smartphones)
REALME_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 2C:4D:54 - IEEE assigns to Unknown, not REALME
    # REMOVED: 50:55:27 - IEEE assigns to Unknown, not REALME
    # REMOVED: 88:C9:E8 - IEEE assigns to Unknown, not REALME
    # REMOVED: A0:02:DC - IEEE assigns to Unknown, not REALME
}

REALME_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"realme\s*GT\s*5\s*Pro", "Realme GT 5 Pro", "smartphone", "Realme UI"),
    (r"realme\s*GT\s*5", "Realme GT 5", "smartphone", "Realme UI"),
    (r"realme\s*GT\s*Neo\s*\d+", "Realme GT Neo", "smartphone", "Realme UI"),
    (r"realme\s*GT\s*\d+", "Realme GT", "smartphone", "Realme UI"),
    (r"realme\s*GT", "Realme GT", "smartphone", "Realme UI"),
    (r"realme\s*\d+\s*Pro\+", "Realme Pro+", "smartphone", "Realme UI"),
    (r"realme\s*\d+\s*Pro", "Realme Pro", "smartphone", "Realme UI"),
    (r"realme\s*\d+", "Realme Device", "smartphone", "Realme UI"),
    (r"realme\s*C\d+", "Realme C Series", "smartphone", "Realme UI"),
    (r"realme\s*Narzo\s*\d+", "Realme Narzo", "smartphone", "Realme UI"),
    (r"realme\s*Pad", "Realme Pad", "tablet", "Realme UI"),
    (r"realme\s*Watch", "Realme Watch", "smartwatch", None),
    (r"realme\s*Buds", "Realme Buds", "earbuds", None),
    (r"realme", "Realme Device", "smartphone", "Realme UI"),
]

# HONOR (Smartphones)
HONOR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:66:4B": ("smartphone", "Mobile", "Honor"),
    "10:44:00": ("smartphone", "Mobile", "Honor"),
    "24:09:95": ("smartphone", "Mobile", "Honor"),
    "54:BA:D6": ("smartphone", "Mobile", "Honor"),
    "B4:CD:27": ("smartphone", "Mobile", "Honor"),
    "D8:C7:71": ("smartphone", "Mobile", "Honor"),
    "F4:63:1F": ("smartphone", "Mobile", "Honor"),
}

HONOR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"HONOR\s*Magic\s*6\s*Pro", "Honor Magic 6 Pro", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic\s*6", "Honor Magic 6", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic\s*V3", "Honor Magic V3", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic\s*V2", "Honor Magic V2", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic\s*Vs", "Honor Magic Vs", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic\s*5\s*Pro", "Honor Magic 5 Pro", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic\s*5", "Honor Magic 5", "smartphone", "MagicOS"),
    (r"HONOR\s*Magic", "Honor Magic", "smartphone", "MagicOS"),
    (r"HONOR\s*\d+\s*Pro", "Honor Pro", "smartphone", "MagicOS"),
    (r"HONOR\s*\d+", "Honor", "smartphone", "MagicOS"),
    (r"HONOR\s*X\d+", "Honor X Series", "smartphone", "MagicOS"),
    (r"HONOR\s*Play\s*\d+", "Honor Play", "smartphone", "MagicOS"),
    (r"HONOR\s*Pad", "Honor Pad", "tablet", "MagicOS"),
    (r"HONOR\s*Watch", "Honor Watch", "smartwatch", "LiteOS"),
    (r"HONOR\s*Earbuds", "Honor Earbuds", "earbuds", None),
    (r"HONOR", "Honor Device", "smartphone", "MagicOS"),
]

# NOTHING (Smartphones)
NOTHING_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

NOTHING_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Nothing\s*Phone\s*\(2a\)", "Nothing Phone (2a)", "smartphone", "Nothing OS"),
    (r"Nothing\s*Phone\s*\(2\)", "Nothing Phone (2)", "smartphone", "Nothing OS"),
    (r"Nothing\s*Phone\s*\(1\)", "Nothing Phone (1)", "smartphone", "Nothing OS"),
    (r"Nothing\s*Phone", "Nothing Phone", "smartphone", "Nothing OS"),
    (r"Nothing\s*Ear\s*\(2\)", "Nothing Ear (2)", "earbuds", None),
    (r"Nothing\s*Ear\s*\(1\)", "Nothing Ear (1)", "earbuds", None),
    (r"Nothing\s*Ear", "Nothing Ear", "earbuds", None),
    (r"CMF\s*Phone", "CMF Phone", "smartphone", "Nothing OS"),
    (r"CMF\s*Buds", "CMF Buds", "earbuds", None),
    (r"Nothing", "Nothing Device", "smartphone", "Nothing OS"),
]

# GOOGLE PIXEL (Smartphones)
PIXEL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "3C:28:6D": ("smartphone", "Mobile", "Google Pixel"),
    # REMOVED: 54:60:09 - IEEE assigns to Unknown, not PIXEL
    # REMOVED: 94:EB:2C - IEEE assigns to Unknown, not PIXEL
    # REMOVED: F4:F5:D8 - IEEE assigns to Unknown, not PIXEL
    # MOVED: F8:0F:F9 to GOOGLE_MAC_PREFIXES — used by Nest/Home, not Pixel-specific
}

PIXEL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Pixel\s*9\s*Pro\s*XL", "Google Pixel 9 Pro XL", "smartphone", "Android"),
    (r"Pixel\s*9\s*Pro\s*Fold", "Google Pixel 9 Pro Fold", "smartphone", "Android"),
    (r"Pixel\s*9\s*Pro", "Google Pixel 9 Pro", "smartphone", "Android"),
    (r"Pixel\s*9", "Google Pixel 9", "smartphone", "Android"),
    (r"Pixel\s*8\s*Pro", "Google Pixel 8 Pro", "smartphone", "Android"),
    (r"Pixel\s*8a", "Google Pixel 8a", "smartphone", "Android"),
    (r"Pixel\s*8", "Google Pixel 8", "smartphone", "Android"),
    (r"Pixel\s*Fold", "Google Pixel Fold", "smartphone", "Android"),
    (r"Pixel\s*7\s*Pro", "Google Pixel 7 Pro", "smartphone", "Android"),
    (r"Pixel\s*7a", "Google Pixel 7a", "smartphone", "Android"),
    (r"Pixel\s*7", "Google Pixel 7", "smartphone", "Android"),
    (r"Pixel\s*6\s*Pro", "Google Pixel 6 Pro", "smartphone", "Android"),
    (r"Pixel\s*6a", "Google Pixel 6a", "smartphone", "Android"),
    (r"Pixel\s*6", "Google Pixel 6", "smartphone", "Android"),
    (r"Pixel\s*Tablet", "Google Pixel Tablet", "tablet", "Android"),
    (r"Pixel\s*Watch\s*2", "Google Pixel Watch 2", "smartwatch", "Wear OS"),
    (r"Pixel\s*Watch", "Google Pixel Watch", "smartwatch", "Wear OS"),
    (r"Pixel\s*Buds\s*Pro", "Google Pixel Buds Pro", "earbuds", None),
    (r"Pixel\s*Buds", "Google Pixel Buds", "earbuds", None),
    (r"Pixel", "Google Pixel", "smartphone", "Android"),
]

# SONY MOBILE (Xperia)
SONY_MOBILE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0A:D9 - IEEE assigns to Unknown, not SONY_MOBILE
    "00:0E:07": ("smartphone", "Mobile", "Sony"),
    # REMOVED: 00:13:A9 - IEEE assigns to Unknown, not SONY_MOBILE
    # REMOVED: 00:18:13 - IEEE assigns to Unknown, not SONY_MOBILE
    # REMOVED: 00:1A:80 - IEEE assigns to Unknown, not SONY_MOBILE
    # REMOVED: 00:1D:28 - IEEE assigns to Unknown, not SONY_MOBILE
    # REMOVED: 00:1E:A4 - IEEE assigns to Unknown, not SONY_MOBILE
    # REMOVED: 00:24:BE - IEEE assigns to Unknown, not SONY_MOBILE
    "28:0D:FC": ("smartphone", "Mobile", "Sony"),
    # REMOVED: 30:17:C8 - IEEE assigns to Unknown, not SONY_MOBILE
    # REMOVED: 40:B8:37 - IEEE assigns to Unknown, not SONY_MOBILE
    "58:48:22": ("smartphone", "Mobile", "Sony"),
    "70:26:05": ("smartphone", "Mobile", "Sony"),
    "84:00:D2": ("smartphone", "Mobile", "Sony"),
    "94:CE:2C": ("smartphone", "Mobile", "Sony"),
    # REMOVED: AC:9B:0A - IEEE assigns to Unknown, not SONY_MOBILE
    "B4:52:7D": ("smartphone", "Mobile", "Sony"),
    "BC:60:A7": ("smartphone", "Mobile", "Sony"),
    "FC:0F:E6": ("smartphone", "Mobile", "Sony"),
}

SONY_MOBILE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Xperia\s*1\s*VI", "Sony Xperia 1 VI", "smartphone", "Android"),
    (r"Xperia\s*1\s*V", "Sony Xperia 1 V", "smartphone", "Android"),
    (r"Xperia\s*1\s*IV", "Sony Xperia 1 IV", "smartphone", "Android"),
    (r"Xperia\s*5\s*V", "Sony Xperia 5 V", "smartphone", "Android"),
    (r"Xperia\s*5\s*IV", "Sony Xperia 5 IV", "smartphone", "Android"),
    (r"Xperia\s*10\s*VI", "Sony Xperia 10 VI", "smartphone", "Android"),
    (r"Xperia\s*10\s*V", "Sony Xperia 10 V", "smartphone", "Android"),
    (r"Xperia\s*Pro-I", "Sony Xperia Pro-I", "smartphone", "Android"),
    (r"Xperia\s*Pro", "Sony Xperia Pro", "smartphone", "Android"),
    (r"Xperia\s*\d+", "Sony Xperia", "smartphone", "Android"),
    (r"Xperia", "Sony Xperia", "smartphone", "Android"),
]

# LG MOBILE (Smartphones - discontinued but still in use)
LG_MOBILE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1C:43 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:1E:75 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:1F:6B - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:22:A9 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:23:AE - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:24:83 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:25:E5 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:26:E2 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:34:DA - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:AA:70 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 00:E0:91 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 10:68:3F - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 14:C9:13 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 20:21:A5 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 40:B0:FA - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 50:55:27 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 78:5D:C8 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: 88:C9:D0 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: A8:16:B2 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: AC:0D:1B - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: BC:F5:AC - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: E8:5B:5B - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: F0:1C:13 - IEEE assigns to Unknown, not LG_MOBILE
    # REMOVED: F8:0C:F3 - IEEE assigns to Unknown, not LG_MOBILE
}

LG_MOBILE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # LG Mobile phone patterns - LG exited mobile market in 2021
    # NOTE: No generic LG fallback - LG TVs are far more common than phones
    # Let LG_BANNER_PATTERNS (which defaults to TV) handle generic LG matches
    (r"LG\s*Wing", "LG Wing", "smartphone", "Android"),
    (r"LG\s*Velvet", "LG Velvet", "smartphone", "Android"),
    (r"LG\s*V\d+", "LG V Series", "smartphone", "Android"),
    (r"LG\s*G\d+", "LG G Series", "smartphone", "Android"),
    (r"LG\s*K\d+", "LG K Series", "smartphone", "Android"),
    (r"LG\s*Stylo\s*\d+", "LG Stylo", "smartphone", "Android"),
    (r"LG\s*Q\d+", "LG Q Series", "smartphone", "Android"),
    (r"LG\s*Optimus", "LG Optimus", "smartphone", "Android"),
    (r"LG\s*Nexus", "LG Nexus", "smartphone", "Android"),
    # NOTE: Generic "LG" removed - would incorrectly classify TVs/appliances as phones
]

# HTC (Smartphones)
HTC_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:09:2D": ("smartphone", "Mobile", "HTC"),
    "00:23:76": ("smartphone", "Mobile", "HTC"),
    "18:87:96": ("smartphone", "Mobile", "HTC"),
    "1C:B0:94": ("smartphone", "Mobile", "HTC"),
    "2C:8A:72": ("smartphone", "Mobile", "HTC"),
    "38:E7:D8": ("smartphone", "Mobile", "HTC"),
    "40:4E:36": ("smartphone", "Mobile", "HTC"),
    "50:2E:5C": ("smartphone", "Mobile", "HTC"),
    "64:A7:69": ("smartphone", "Mobile", "HTC"),
    "7C:61:93": ("smartphone", "Mobile", "HTC"),
    "80:01:84": ("smartphone", "Mobile", "HTC"),
    # REMOVED: 84:7A:88 - IEEE assigns to Unknown, not HTC
    "90:21:55": ("smartphone", "Mobile", "HTC"),
    "98:0D:2E": ("smartphone", "Mobile", "HTC"),
    "A0:F4:50": ("smartphone", "Mobile", "HTC"),
    # REMOVED: B4:CE:F6 - IEEE assigns to Unknown, not HTC
    "D8:B3:77": ("smartphone", "Mobile", "HTC"),
    "E8:99:C4": ("smartphone", "Mobile", "HTC"),
    "F8:DB:7F": ("smartphone", "Mobile", "HTC"),
}

HTC_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # HTC VR Headsets (VIVE) - check these first as HTC pivoted to VR
    (r"HTC\s*VIVE\s*XR", "HTC VIVE XR Elite", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE\s*Pro\s*2", "HTC VIVE Pro 2", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE\s*Pro", "HTC VIVE Pro", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE\s*Focus\s*3", "HTC VIVE Focus 3", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE\s*Focus", "HTC VIVE Focus", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE\s*Flow", "HTC VIVE Flow", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE\s*Cosmos", "HTC VIVE Cosmos", "vr_headset", "VIVE"),
    (r"HTC\s*VIVE", "HTC VIVE", "vr_headset", "VIVE"),
    (r"VIVE\s*XR", "HTC VIVE XR", "vr_headset", "VIVE"),
    (r"VIVE\s*Pro", "HTC VIVE Pro", "vr_headset", "VIVE"),
    (r"VIVE\s*Focus", "HTC VIVE Focus", "vr_headset", "VIVE"),
    (r"VIVE\s*Flow", "HTC VIVE Flow", "vr_headset", "VIVE"),
    (r"VIVE", "HTC VIVE", "vr_headset", "VIVE"),
    # HTC Smartphones (legacy - HTC largely exited smartphone market)
    (r"HTC\s*U\d+", "HTC U Series", "smartphone", "Android"),
    (r"HTC\s*Desire\s*\d+", "HTC Desire", "smartphone", "Android"),
    (r"HTC\s*One\s*M\d+", "HTC One M", "smartphone", "Android"),
    (r"HTC\s*One", "HTC One", "smartphone", "Android"),
    (r"HTC\s*Wildfire", "HTC Wildfire", "smartphone", "Android"),
    (r"HTC\s*10", "HTC 10", "smartphone", "Android"),
    (r"HTC\s*Bolt", "HTC Bolt", "smartphone", "Android"),
    # NOTE: Generic "HTC" removed - HTC is now primarily VR (VIVE), default to VR
    # If needed, could default to vr_headset instead of smartphone
]

# TRANSSION (Infinix, Tecno, Itel parent company)
INFINIX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 84:25:DB - IEEE assigns to Unknown, not INFINIX
}

INFINIX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Infinix\s*Zero\s*\d+", "Infinix Zero", "smartphone", "XOS"),
    (r"Infinix\s*Note\s*\d+", "Infinix Note", "smartphone", "XOS"),
    (r"Infinix\s*Hot\s*\d+", "Infinix Hot", "smartphone", "XOS"),
    (r"Infinix\s*Smart\s*\d+", "Infinix Smart", "smartphone", "XOS"),
    (r"Infinix\s*GT\s*\d+", "Infinix GT", "smartphone", "XOS"),
    (r"Infinix", "Infinix Device", "smartphone", "XOS"),
]

TECNO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 74:23:44 - IEEE assigns to Unknown, not TECNO
    # REMOVED: DC:E5:5B - IEEE assigns to Unknown, not TECNO
}

TECNO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"TECNO\s*Phantom\s*V", "Tecno Phantom V", "smartphone", "HiOS"),
    (r"TECNO\s*Phantom\s*X\d+", "Tecno Phantom X", "smartphone", "HiOS"),
    (r"TECNO\s*Phantom", "Tecno Phantom", "smartphone", "HiOS"),
    (r"TECNO\s*Camon\s*\d+", "Tecno Camon", "smartphone", "HiOS"),
    (r"TECNO\s*Spark\s*\d+", "Tecno Spark", "smartphone", "HiOS"),
    (r"TECNO\s*Pova\s*\d+", "Tecno Pova", "smartphone", "HiOS"),
    (r"TECNO\s*Pop\s*\d+", "Tecno Pop", "smartphone", "HiOS"),
    (r"TECNO", "Tecno Device", "smartphone", "HiOS"),
]

# MEIZU (Smartphones)
MEIZU_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 0C:1D:AF - IEEE assigns to Unknown, not MEIZU
    # REMOVED: 24:69:A5 - IEEE assigns to Huawei Technologies, not Meizu
    # REMOVED: 40:22:D8 - IEEE assigns to Unknown, not MEIZU
    # REMOVED: 58:44:98 - IEEE assigns to Unknown, not MEIZU
    "BC:76:70": ("smartphone", "Mobile", "Meizu"),
}

MEIZU_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Meizu\s*21\s*Pro", "Meizu 21 Pro", "smartphone", "Flyme"),
    (r"Meizu\s*21", "Meizu 21", "smartphone", "Flyme"),
    (r"Meizu\s*20\s*Pro", "Meizu 20 Pro", "smartphone", "Flyme"),
    (r"Meizu\s*20", "Meizu 20", "smartphone", "Flyme"),
    (r"Meizu\s*\d+", "Meizu", "smartphone", "Flyme"),
    (r"Meizu", "Meizu Device", "smartphone", "Flyme"),
]

# ASUS MOBILE (ROG Phone, ZenFone)
ASUS_MOBILE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1A:92 - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: 08:60:6E - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: 14:DA:E9 - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: 2C:4D:54 - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: 40:B0:76 - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: 54:04:A6 - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: 74:D0:2B - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: BC:EE:7B - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: C8:60:00 - IEEE assigns to Unknown, not ASUS_MOBILE
    # REMOVED: F4:6D:04 - IEEE assigns to Unknown, not ASUS_MOBILE
}

ASUS_MOBILE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"ROG\s*Phone\s*8\s*Pro", "ASUS ROG Phone 8 Pro", "smartphone", "Android"),
    (r"ROG\s*Phone\s*8", "ASUS ROG Phone 8", "smartphone", "Android"),
    (r"ROG\s*Phone\s*7", "ASUS ROG Phone 7", "smartphone", "Android"),
    (r"ROG\s*Phone\s*6", "ASUS ROG Phone 6", "smartphone", "Android"),
    (r"ROG\s*Phone", "ASUS ROG Phone", "smartphone", "Android"),
    (r"ZenFone\s*11\s*Ultra", "ASUS ZenFone 11 Ultra", "smartphone", "Android"),
    (r"ZenFone\s*10", "ASUS ZenFone 10", "smartphone", "Android"),
    (r"ZenFone\s*9", "ASUS ZenFone 9", "smartphone", "Android"),
    (r"ZenFone", "ASUS ZenFone", "smartphone", "Android"),
    (r"ASUS\s*Zenfone", "ASUS ZenFone", "smartphone", "Android"),
]

# LENOVO MOBILE (Smartphones & Tablets)
LENOVO_MOBILE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:09:2D - IEEE assigns to Unknown, not LENOVO_MOBILE
    # REMOVED: 00:1E:37 - IEEE assigns to Unknown, not LENOVO_MOBILE
    # REMOVED: 28:D2:44 - IEEE assigns to Unknown, not LENOVO_MOBILE
    # REMOVED: 98:E7:F4 - IEEE assigns to Unknown, not LENOVO_MOBILE
    # REMOVED: F0:03:8C - IEEE assigns to Unknown, not LENOVO_MOBILE
}

LENOVO_MOBILE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Lenovo\s*Legion\s*Phone\s*Duel", "Lenovo Legion Phone Duel", "smartphone", "Android"),
    (r"Lenovo\s*Legion\s*Y\d+", "Lenovo Legion Phone", "smartphone", "Android"),
    (r"Lenovo\s*Tab\s*P\d+", "Lenovo Tab P", "tablet", "Android"),
    (r"Lenovo\s*Tab\s*M\d+", "Lenovo Tab M", "tablet", "Android"),
    (r"Lenovo\s*Yoga\s*Tab", "Lenovo Yoga Tab", "tablet", "Android"),
    (r"Lenovo\s*K\d+", "Lenovo K Series", "smartphone", "Android"),
    (r"Lenovo\s*Z\d+", "Lenovo Z Series", "smartphone", "Android"),
    (r"Lenovo\s*A\d+", "Lenovo A Series", "smartphone", "Android"),
    (r"Lenovo\s*Tab", "Lenovo Tab", "tablet", "Android"),
    (r"Lenovo\s*Phone", "Lenovo Phone", "smartphone", "Android"),
]


# BOSE (Audio)
BOSE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0C:8A": ("speaker", "Audio", "Bose"),
    "04:52:C7": ("speaker", "Audio", "Bose"),
    "08:DF:1F": ("speaker", "Audio", "Bose"),
    "2C:41:A1": ("speaker", "Audio", "Bose"),
    "4C:87:5D": ("speaker", "Audio", "Bose"),
    # REMOVED: 88:C9:E8 - IEEE assigns to Unknown, not BOSE
    "C8:7B:23": ("speaker", "Audio", "Bose"),
    # Additional Bose OUIs
    "14:83:FE": ("speaker", "Audio", "Bose"),
    "40:39:95": ("speaker", "Audio", "Bose"),
    "60:AB:D2": ("speaker", "Audio", "Bose"),
    "78:2B:64": ("speaker", "Audio", "Bose"),
}

BOSE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Soundbars
    (r"Bose\s*Smart\s*Soundbar\s*\d+", "Bose Smart Soundbar", "soundbar", "Bose Music"),
    (r"Bose\s*Soundbar\s*\d+", "Bose Soundbar", "soundbar", "Bose Music"),
    (r"Bose\s*TV\s*Speaker", "Bose TV Speaker", "soundbar", "Bose Music"),
    # Speakers
    (r"Bose\s*Home\s*Speaker\s*\d+", "Bose Home Speaker", "smart_speaker", "Bose Music"),
    (r"Bose\s*Portable\s*Home\s*Speaker", "Bose Portable Home Speaker", "smart_speaker", "Bose Music"),
    (r"Bose\s*SoundLink\s*Flex", "Bose SoundLink Flex", "speaker", "Bose Connect"),
    (r"Bose\s*SoundLink\s*Revolve", "Bose SoundLink Revolve", "speaker", "Bose Connect"),
    (r"Bose\s*SoundLink\s*Mini", "Bose SoundLink Mini", "speaker", "Bose Connect"),
    (r"Bose\s*SoundLink", "Bose SoundLink", "speaker", "Bose Connect"),
    # Headphones
    (r"Bose\s*QuietComfort\s*Ultra", "Bose QuietComfort Ultra", "headphones", "Bose Music"),
    (r"Bose\s*QuietComfort\s*\d+", "Bose QuietComfort", "headphones", "Bose Music"),
    (r"Bose\s*Noise\s*Cancelling\s*700", "Bose NC 700", "headphones", "Bose Music"),
    (r"Bose\s*Sport\s*Earbuds", "Bose Sport Earbuds", "earbuds", "Bose Music"),
    (r"Bose\s*QuietComfort\s*Earbuds", "Bose QC Earbuds", "earbuds", "Bose Music"),
    # Generic
    (r"Bose", "Bose Device", "speaker", "Bose Music"),
]

# LOGITECH (Peripherals)
LOGITECH_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:1F:20": ("peripheral", "Peripherals", "Logitech"),
    # REMOVED: 40:B0:34 - IEEE assigns to Unknown, not LOGITECH
    "88:C6:26": ("webcam", "Peripherals", "Logitech"),
    # REMOVED: 94:65:2D - IEEE assigns to Unknown, not LOGITECH
}

LOGITECH_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Webcams
    (r"Logitech\s*Brio\s*4K", "Logitech Brio 4K", "webcam", "Logitech Capture"),
    (r"Logitech\s*Brio\s*500", "Logitech Brio 500", "webcam", "Logitech Capture"),
    (r"Logitech\s*Brio", "Logitech Brio", "webcam", "Logitech Capture"),
    (r"Logitech\s*C930", "Logitech C930", "webcam", "Logitech Capture"),
    (r"Logitech\s*C920", "Logitech C920", "webcam", "Logitech Capture"),
    (r"Logitech\s*C922", "Logitech C922", "webcam", "Logitech Capture"),
    (r"Logitech\s*StreamCam", "Logitech StreamCam", "webcam", "Logitech Capture"),
    # Conference Cameras
    (r"Logitech\s*Rally\s*Bar", "Logitech Rally Bar", "conference_camera", "Logitech Sync"),
    (r"Logitech\s*Rally\s*Camera", "Logitech Rally Camera", "conference_camera", "Logitech Sync"),
    (r"Logitech\s*MeetUp", "Logitech MeetUp", "conference_camera", "Logitech Sync"),
    (r"Logitech\s*Conference\s*Cam", "Logitech ConferenceCam", "conference_camera", "Logitech Sync"),
    # Gaming
    (r"Logitech\s*G\d{3}", "Logitech G Series", "gaming_peripheral", "G HUB"),
    (r"Logitech\s*Pro", "Logitech Pro", "gaming_peripheral", "G HUB"),
    # Circle Cameras
    (r"Logitech\s*Circle\s*View", "Logitech Circle View", "ip_camera", "HomeKit"),
    (r"Logitech\s*Circle\s*2", "Logitech Circle 2", "ip_camera", "Logi Circle"),
    (r"Logitech\s*Circle", "Logitech Circle", "ip_camera", "Logi Circle"),
    # Generic
    (r"Logitech", "Logitech Device", "peripheral", "Logitech Options"),
]

# CHROMECAST (Google Streaming)
CHROMECAST_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 6C:AD:F8 - IEEE assigns to AzureWave Technology, not Google
    # D8:6C:63 is in GOOGLE_MAC_PREFIXES (verified Google, Inc.)
    # FA:8F:CA and F8:8F:CA are in GOOGLE_MAC_PREFIXES (verified Google Chromecast)
    # Chromecast devices use generic Google OUIs — detection via mDNS/hostname
}

CHROMECAST_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Chromecast\s*with\s*Google\s*TV\s*4K", "Chromecast with Google TV 4K", "media_player", "Google Home"),
    (r"Chromecast\s*with\s*Google\s*TV", "Chromecast with Google TV", "media_player", "Google Home"),
    (r"Chromecast\s*Ultra", "Chromecast Ultra", "media_player", "Google Home"),
    (r"Chromecast\s*Audio", "Chromecast Audio", "media_player", "Google Home"),
    (r"Chromecast\s*3rd", "Chromecast 3rd Gen", "media_player", "Google Home"),
    (r"Chromecast\s*2nd", "Chromecast 2nd Gen", "media_player", "Google Home"),
    (r"Chromecast", "Google Chromecast", "media_player", "Google Home"),
]


# ECOBEE (Smart Thermostats)
ECOBEE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "44:61:32": ("thermostat", "Smart Home", "ecobee Thermostat"),
}

ECOBEE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"ecobee.*Premium", "ecobee Smart Thermostat Premium", "thermostat", None),
    (r"ecobee.*Enhanced", "ecobee Smart Thermostat Enhanced", "thermostat", None),
    (r"ecobee\s*4", "ecobee4", "thermostat", None),
    (r"ecobee\s*3.*lite", "ecobee3 lite", "thermostat", None),
    (r"ecobee\s*3", "ecobee3", "thermostat", None),
    (r"SmartThermostat", "ecobee SmartThermostat", "thermostat", None),
    (r"ecobee.*sensor", "ecobee Room Sensor", "sensor", None),
    (r"ecobee.*camera", "ecobee SmartCamera", "ip_camera", None),
    (r"ecobee", "ecobee Thermostat", "thermostat", None),
]

# NEST (Google Nest)
NEST_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 18:B4:30 - IEEE assigns to Unknown, not NEST
    # REMOVED: 64:16:66 - IEEE assigns to Unknown, not NEST
    # REMOVED: 64:48:8B - IEEE assigns to Unknown, not NEST
    # REMOVED: D8:EB:46 - IEEE assigns to Unknown, not NEST
    # REMOVED: F4:F5:D8 - IEEE assigns to Unknown, not NEST
    # REMOVED: F4:F5:E8 - IEEE assigns to Unknown, not NEST
}

NEST_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Thermostats
    (r"Nest.*Learning.*Thermostat", "Nest Learning Thermostat", "thermostat", None),
    (r"Nest.*Thermostat\s*E", "Nest Thermostat E", "thermostat", None),
    (r"Nest.*Thermostat", "Nest Thermostat", "thermostat", None),

    # Cameras
    (r"Nest\s*Cam.*Indoor", "Nest Cam Indoor", "ip_camera", None),
    (r"Nest\s*Cam.*Outdoor", "Nest Cam Outdoor", "ip_camera", None),
    (r"Nest\s*Cam.*Battery", "Nest Cam Battery", "ip_camera", None),
    (r"Nest\s*Doorbell", "Nest Doorbell", "doorbell_camera", None),
    (r"Nest\s*Hello", "Nest Hello Doorbell", "doorbell_camera", None),

    # Speakers/Displays
    (r"Nest\s*Hub\s*Max", "Google Nest Hub Max", "smart_display", "Google"),
    (r"Nest\s*Hub", "Google Nest Hub", "smart_display", "Google"),
    (r"Nest\s*Mini", "Google Nest Mini", "smart_speaker", "Google"),
    (r"Nest\s*Audio", "Google Nest Audio", "smart_speaker", "Google"),

    # Protect (Smoke/CO)
    (r"Nest\s*Protect", "Nest Protect", "smoke_detector", None),

    # WiFi
    (r"Nest\s*Wifi\s*Pro", "Nest Wifi Pro", "router", None),
    (r"Nest\s*Wifi", "Nest Wifi", "router", None),

    # Generic
    (r"Nest", "Nest Device", "iot_device", None),
]

# RING (Amazon Ring)
RING_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "34:3E:A4": ("doorbell_camera", "Smart Home", "Ring Device"),
    "44:05:A5": ("doorbell_camera", "Smart Home", "Ring Device"),
    "90:22:F0": ("doorbell_camera", "Smart Home", "Ring Device"),
}

RING_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Doorbells
    (r"Ring.*Video\s*Doorbell\s*Pro\s*2", "Ring Video Doorbell Pro 2", "doorbell_camera", None),
    (r"Ring.*Video\s*Doorbell\s*Pro", "Ring Video Doorbell Pro", "doorbell_camera", None),
    (r"Ring.*Video\s*Doorbell\s*4", "Ring Video Doorbell 4", "doorbell_camera", None),
    (r"Ring.*Video\s*Doorbell\s*3", "Ring Video Doorbell 3", "doorbell_camera", None),
    (r"Ring.*Video\s*Doorbell\s*2", "Ring Video Doorbell 2", "doorbell_camera", None),
    (r"Ring.*Video\s*Doorbell", "Ring Video Doorbell", "doorbell_camera", None),
    (r"Ring.*Doorbell", "Ring Doorbell", "doorbell_camera", None),

    # Cameras
    (r"Ring.*Spotlight\s*Cam\s*Pro", "Ring Spotlight Cam Pro", "ip_camera", None),
    (r"Ring.*Spotlight\s*Cam", "Ring Spotlight Cam", "ip_camera", None),
    (r"Ring.*Floodlight\s*Cam", "Ring Floodlight Cam", "ip_camera", None),
    (r"Ring.*Stick\s*Up\s*Cam", "Ring Stick Up Cam", "ip_camera", None),
    (r"Ring.*Indoor\s*Cam", "Ring Indoor Cam", "ip_camera", None),

    # Alarm
    (r"Ring.*Alarm\s*Pro", "Ring Alarm Pro", "alarm_panel", None),
    (r"Ring.*Alarm", "Ring Alarm", "alarm_panel", None),

    # Generic
    (r"Ring", "Ring Device", "iot_device", None),
]

# LUTRON (Lighting Control)
LUTRON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0F:E7": ("smart_home", "Smart Home", "Lutron"),  # IEEE-assigned to Lutron Electronics
    "AC:63:FE": ("lighting_controller", "Smart Home", "Lutron Device"),
}

LUTRON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Caseta
    (r"Caseta.*Pro", "Lutron Caseta Pro Bridge", "lighting_controller", None),
    (r"Caseta", "Lutron Caseta Bridge", "lighting_controller", None),

    # RA2/RA3
    (r"RadioRA\s*3", "Lutron RadioRA 3", "lighting_controller", None),
    (r"RadioRA\s*2", "Lutron RadioRA 2", "lighting_controller", None),

    # HomeWorks
    (r"HomeWorks\s*QSX", "Lutron HomeWorks QSX", "lighting_controller", None),
    (r"HomeWorks\s*QS", "Lutron HomeWorks QS", "lighting_controller", None),
    (r"HomeWorks", "Lutron HomeWorks", "lighting_controller", None),

    # Grafik
    (r"GRAFIK\s*Eye", "Lutron GRAFIK Eye", "lighting_controller", None),
    (r"GRAFIK", "Lutron GRAFIK", "lighting_controller", None),

    # Vive (lighting) - require Lutron prefix to avoid conflict with HTC VIVE
    (r"Lutron\s*Vive.*Hub", "Lutron Vive Hub", "lighting_controller", None),
    (r"Lutron\s*Vive", "Lutron Vive", "lighting_controller", None),

    # Generic
    (r"Lutron", "Lutron Controller", "lighting_controller", None),
]

# CONTROL4 (Home Automation)
CONTROL4_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0F:FF": ("automation_controller", "Smart Home", "Control4"),
}

CONTROL4_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Control4.*EA-\d+", "Control4 EA Controller", "automation_controller", "Control4 OS"),
    (r"Control4.*HC-\d+", "Control4 HC Controller", "automation_controller", "Control4 OS"),
    (r"Control4.*CA-\d+", "Control4 Automation Controller", "automation_controller", "Control4 OS"),
    (r"Control4.*T4", "Control4 T4 Touch Screen", "touch_panel", "Control4 OS"),
    (r"Control4.*T3", "Control4 T3 Touch Screen", "touch_panel", "Control4 OS"),
    (r"Control4.*DS2", "Control4 DS2 Door Station", "intercom", None),
    (r"Control4", "Control4 Device", "automation_controller", "Control4 OS"),
]

# SAVANT (Home Automation)
SAVANT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

SAVANT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Savant.*Pro\s*Host", "Savant Pro Host", "automation_controller", "Savant"),
    (r"Savant.*Smart\s*Host", "Savant Smart Host", "automation_controller", "Savant"),
    (r"Savant.*Touch\s*Screen", "Savant Touch Screen", "touch_panel", "Savant"),
    (r"Savant.*Remote", "Savant Pro Remote", "remote_control", None),
    (r"Savant", "Savant Controller", "automation_controller", "Savant"),
]

# WEMO (Belkin Smart Home)
WEMO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 08:86:3B - IEEE assigns to Unknown, not WEMO
    "24:F5:A2": ("smart_plug", "Smart Home", "Wemo Device"),
    "58:EF:68": ("smart_plug", "Smart Home", "Wemo Device"),
    "94:10:3E": ("smart_plug", "Smart Home", "Wemo Device"),
    "B4:75:0E": ("smart_plug", "Smart Home", "Wemo Device"),
}

WEMO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Wemo.*Mini", "Wemo Mini Smart Plug", "smart_plug", None),
    (r"Wemo.*Insight", "Wemo Insight Smart Plug", "smart_plug", None),
    (r"Wemo.*Smart\s*Plug", "Wemo Smart Plug", "smart_plug", None),
    (r"Wemo.*Switch", "Wemo Smart Switch", "smart_switch", None),
    (r"Wemo.*Dimmer", "Wemo Dimmer", "smart_dimmer", None),
    (r"Wemo.*Light\s*Switch", "Wemo Light Switch", "smart_switch", None),
    (r"Wemo", "Wemo Device", "smart_plug", None),
]

# TUYA (IoT Platform)
TUYA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "10:D5:61": ("iot_device", "Smart Home", "Tuya Device"),
    # REMOVED: 48:3F:DA - IEEE assigns to Unknown, not TUYA
    "50:8A:06": ("iot_device", "Smart Home", "Tuya Device"),
    # REMOVED: 60:01:94 - IEEE assigns to Unknown, not TUYA
    "7C:F6:66": ("iot_device", "Smart Home", "Tuya Device"),
    "84:E3:42": ("iot_device", "Smart Home", "Tuya Device"),
    "D4:A6:51": ("iot_device", "Smart Home", "Tuya Device"),
}

TUYA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Tuya.*Smart\s*Plug", "Tuya Smart Plug", "smart_plug", None),
    (r"Tuya.*Smart\s*Bulb", "Tuya Smart Bulb", "smart_bulb", None),
    (r"Tuya.*Camera", "Tuya Smart Camera", "ip_camera", None),
    (r"Tuya.*Sensor", "Tuya Sensor", "sensor", None),
    (r"Smart\s*Life", "Smart Life Device (Tuya)", "iot_device", None),
    (r"Tuya", "Tuya IoT Device", "iot_device", None),
]

# TP-LINK KASA (Smart Home)
KASA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 1C:3B:F3 - IEEE assigns to Unknown, not KASA
    # REMOVED: 50:C7:BF - IEEE assigns to Unknown, not KASA
    # REMOVED: 54:AF:97 - IEEE assigns to Unknown, not KASA
    # REMOVED: 60:A4:B7 - IEEE assigns to Unknown, not KASA
    # REMOVED: 98:DA:C4 - IEEE assigns to Unknown, not KASA
    # REMOVED: B0:A7:B9 - IEEE assigns to Unknown, not KASA
}

KASA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Plugs
    (r"Kasa.*EP\d+", "Kasa Smart Plug", "smart_plug", None),
    (r"Kasa.*HS\d+", "Kasa Smart Plug", "smart_plug", None),
    (r"Kasa.*KP\d+", "Kasa Smart Power Strip", "smart_plug", None),

    # Switches
    (r"Kasa.*ES\d+", "Kasa Smart Switch", "smart_switch", None),

    # Bulbs
    (r"Kasa.*KL\d+", "Kasa Smart Bulb", "smart_bulb", None),
    (r"Kasa.*LB\d+", "Kasa Smart Bulb", "smart_bulb", None),

    # Cameras
    (r"Kasa.*KC\d+", "Kasa Spot Camera", "ip_camera", None),
    (r"Kasa.*EC\d+", "Kasa Outdoor Camera", "ip_camera", None),

    # Doorbell
    (r"Kasa.*Doorbell", "Kasa Smart Doorbell", "doorbell_camera", None),

    # Generic
    (r"Kasa", "Kasa Smart Device", "iot_device", None),
]


# NETWORK EQUIPMENT - ADDITIONAL VENDORS

# ARISTA NETWORKS
ARISTA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:1C:73": ("switch", "Network Equipment", "Arista Switch"),
    "28:99:3A": ("switch", "Network Equipment", "Arista Switch"),
    "44:4C:A8": ("switch", "Network Equipment", "Arista Switch"),
    "50:01:00": ("switch", "Network Equipment", "Arista Switch"),
    "74:83:EF": ("switch", "Network Equipment", "Arista Switch"),
    "94:8E:D3": ("switch", "Network Equipment", "Arista Switch"),
    "FC:BD:67": ("switch", "Network Equipment", "Arista Switch"),
}

ARISTA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 7000 Series (Data Center)
    (r"Arista.*7800", "Arista 7800R3 Series", "switch", "EOS"),
    (r"Arista.*7500R", "Arista 7500R Series", "switch", "EOS"),
    (r"Arista.*7280R", "Arista 7280R3 Series", "switch", "EOS"),
    (r"Arista.*7050X", "Arista 7050X Series", "switch", "EOS"),
    (r"Arista.*7020R", "Arista 7020R Series", "switch", "EOS"),
    (r"Arista.*7010T", "Arista 7010T Series", "switch", "EOS"),

    # 700 Series (Campus)
    (r"Arista.*720X", "Arista 720X Series", "switch", "EOS"),
    (r"Arista.*722X", "Arista 722XPM", "switch", "EOS"),

    # CloudVision
    (r"CloudVision", "Arista CloudVision", "management", "CloudVision"),
    (r"CVP", "Arista CloudVision Portal", "management", "CloudVision"),

    # Wireless
    (r"Arista.*AP", "Arista Access Point", "access_point", "EOS"),
    (r"C-\d+", "Arista Campus AP", "access_point", "EOS"),

    # Generic
    (r"Arista.*EOS", "Arista Switch", "switch", "EOS"),
    (r"Arista", "Arista Networks", "switch", "EOS"),
]

# BROCADE / BROADCOM
BROCADE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:05:1E": ("switch", "Network Equipment", "Brocade Switch"),
    "00:05:33": ("switch", "Network Equipment", "Brocade Switch"),
    "00:27:F8": ("switch", "Network Equipment", "Brocade Switch"),
    "00:60:69": ("switch", "Network Equipment", "Brocade Switch"),
    "50:EB:1A": ("switch", "Network Equipment", "Brocade Switch"),
    "74:8E:F8": ("switch", "Network Equipment", "Brocade Switch"),
}

BROCADE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Fibre Channel
    (r"Brocade.*G720", "Brocade G720 FC Switch", "fc_switch", "FOS"),
    (r"Brocade.*G630", "Brocade G630 FC Switch", "fc_switch", "FOS"),
    (r"Brocade.*G620", "Brocade G620 FC Switch", "fc_switch", "FOS"),
    (r"Brocade.*G610", "Brocade G610 FC Switch", "fc_switch", "FOS"),
    (r"Brocade.*6520", "Brocade 6520 FC Switch", "fc_switch", "FOS"),
    (r"Brocade.*6510", "Brocade 6510 FC Switch", "fc_switch", "FOS"),

    # Directors
    (r"Brocade.*X7-8", "Brocade X7-8 Director", "fc_switch", "FOS"),
    (r"Brocade.*X7-4", "Brocade X7-4 Director", "fc_switch", "FOS"),
    (r"Brocade.*DCX", "Brocade DCX Director", "fc_switch", "FOS"),

    # ICX (Ethernet)
    (r"ICX\s*7850", "Brocade ICX 7850", "switch", "FastIron"),
    (r"ICX\s*7750", "Brocade ICX 7750", "switch", "FastIron"),
    (r"ICX\s*7650", "Brocade ICX 7650", "switch", "FastIron"),
    (r"ICX\s*7450", "Brocade ICX 7450", "switch", "FastIron"),
    (r"ICX\s*7250", "Brocade ICX 7250", "switch", "FastIron"),
    (r"ICX\s*7150", "Brocade ICX 7150", "switch", "FastIron"),

    # VDX (Ethernet Fabric)
    (r"VDX\s*8770", "Brocade VDX 8770", "switch", "NOS"),
    (r"VDX\s*6940", "Brocade VDX 6940", "switch", "NOS"),
    (r"VDX\s*6740", "Brocade VDX 6740", "switch", "NOS"),

    # Generic
    (r"Fabric\s*OS", "Brocade Fabric OS", "fc_switch", "FOS"),
    (r"Brocade", "Brocade Switch", "switch", None),
]

# ALLIED TELESIS
ALLIED_TELESIS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:00:CD": ("switch", "Network Equipment", "Allied Telesis"),
    "00:09:41": ("switch", "Network Equipment", "Allied Telesis"),
    "00:15:77": ("switch", "Network Equipment", "Allied Telesis"),
    "00:1A:EB": ("switch", "Network Equipment", "Allied Telesis"),
    "EC:CD:6D": ("switch", "Network Equipment", "Allied Telesis"),
}

ALLIED_TELESIS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # x-Series Stackable
    (r"x950-\d+", "Allied Telesis x950", "switch", "AlliedWare Plus"),
    (r"x930-\d+", "Allied Telesis x930", "switch", "AlliedWare Plus"),
    (r"x530-\d+", "Allied Telesis x530", "switch", "AlliedWare Plus"),
    (r"x330-\d+", "Allied Telesis x330", "switch", "AlliedWare Plus"),
    (r"x230-\d+", "Allied Telesis x230", "switch", "AlliedWare Plus"),

    # SwitchBlade (Chassis)
    (r"SBx908", "Allied Telesis SwitchBlade x908", "switch", "AlliedWare Plus"),
    (r"SBx8112", "Allied Telesis SwitchBlade x8112", "switch", "AlliedWare Plus"),

    # IE (Industrial)
    (r"IE\d+-\d+", "Allied Telesis Industrial Switch", "switch", "AlliedWare Plus"),
    (r"IS\d+", "Allied Telesis Industrial Switch", "switch", "AlliedWare Plus"),

    # Routers
    (r"AR\d+", "Allied Telesis Router", "router", "AlliedWare Plus"),
    (r"VRouter", "Allied Telesis VRouter", "router", "AlliedWare Plus"),

    # Wireless
    (r"TQ\d+", "Allied Telesis Access Point", "access_point", None),
    (r"AT-TQ\d+", "Allied Telesis Wireless AP", "access_point", None),

    # Generic
    (r"AlliedWare\s*Plus", "Allied Telesis Switch", "switch", "AlliedWare Plus"),
    (r"Allied\s*Telesis", "Allied Telesis Device", "switch", None),
]

# DRAYTEK
DRAYTEK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:1D:AA": ("router", "Network Equipment", "DrayTek"),
    "00:50:7F": ("router", "Network Equipment", "DrayTek"),
    "14:49:BC": ("router", "Network Equipment", "DrayTek"),
}

DRAYTEK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Vigor Routers
    (r"Vigor\s*2927", "DrayTek Vigor 2927", "router", "DrayOS"),
    (r"Vigor\s*2926", "DrayTek Vigor 2926", "router", "DrayOS"),
    (r"Vigor\s*2866", "DrayTek Vigor 2866", "router", "DrayOS"),
    (r"Vigor\s*2865", "DrayTek Vigor 2865", "router", "DrayOS"),
    (r"Vigor\s*2763", "DrayTek Vigor 2763", "router", "DrayOS"),
    (r"Vigor\s*2135", "DrayTek Vigor 2135", "router", "DrayOS"),

    # Vigor Switches
    (r"VigorSwitch.*G\d+", "DrayTek VigorSwitch", "switch", "DrayOS"),
    (r"VigorSwitch.*P\d+", "DrayTek VigorSwitch PoE", "switch", "DrayOS"),

    # Access Points
    (r"VigorAP\s*\d+", "DrayTek VigorAP", "access_point", None),

    # Generic
    (r"Vigor\s*\d+", "DrayTek Vigor", "router", "DrayOS"),
    (r"DrayTek", "DrayTek Device", "router", "DrayOS"),
]

# PEPLINK / PEPWAVE
PEPLINK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

PEPLINK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Balance (Multi-WAN)
    (r"Balance\s*\d+X?", "Peplink Balance", "router", None),
    (r"Balance\s*20X", "Peplink Balance 20X", "router", None),
    (r"Balance\s*310X", "Peplink Balance 310X", "router", None),
    (r"Balance\s*580X", "Peplink Balance 580X", "router", None),

    # MAX (Cellular)
    (r"MAX\s*BR\d+", "Peplink MAX BR", "router", None),
    (r"MAX\s*HD\d+", "Peplink MAX HD", "router", None),
    (r"MAX\s*Transit", "Peplink MAX Transit", "router", None),

    # SpeedFusion
    (r"FusionHub", "Peplink FusionHub", "router", None),
    (r"SpeedFusion", "Peplink SpeedFusion", "router", None),

    # Access Points
    (r"AP\s*One", "Pepwave AP One", "access_point", None),
    (r"Pepwave.*AP", "Pepwave Access Point", "access_point", None),

    # Generic
    (r"Peplink", "Peplink Router", "router", None),
    (r"Pepwave", "Pepwave Device", "router", None),
]

# CAMBIUM NETWORKS
CAMBIUM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:04:56": ("access_point", "Network Equipment", "Cambium"),
    # REMOVED: 58:C1:7A - IEEE assigns to Unknown, not CAMBIUM
}

CAMBIUM_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # cnPilot (Enterprise WiFi)
    (r"cnPilot\s*e\d+", "Cambium cnPilot Enterprise", "access_point", "cnMaestro"),
    (r"cnPilot\s*r\d+", "Cambium cnPilot Residential", "access_point", None),
    (r"cnPilot", "Cambium cnPilot", "access_point", "cnMaestro"),

    # ePMP (Fixed Wireless)
    (r"ePMP\s*4\d+", "Cambium ePMP 4000", "access_point", None),
    (r"ePMP\s*3\d+", "Cambium ePMP 3000", "access_point", None),
    (r"ePMP\s*2\d+", "Cambium ePMP 2000", "access_point", None),
    (r"ePMP", "Cambium ePMP", "access_point", None),

    # PMP (Point to Multipoint)
    (r"PMP\s*450", "Cambium PMP 450", "access_point", None),
    (r"PMP\s*320", "Cambium PMP 320", "access_point", None),

    # PTP (Point to Point)
    (r"PTP\s*820", "Cambium PTP 820", "wireless_bridge", None),
    (r"PTP\s*700", "Cambium PTP 700", "wireless_bridge", None),
    (r"PTP\s*650", "Cambium PTP 650", "wireless_bridge", None),
    (r"PTP\s*550", "Cambium PTP 550", "wireless_bridge", None),

    # cnMatrix (Switches)
    (r"cnMatrix", "Cambium cnMatrix Switch", "switch", None),

    # Management
    (r"cnMaestro", "Cambium cnMaestro", "management", None),

    # Generic
    (r"Cambium", "Cambium Networks", "access_point", None),
]


# THIN CLIENT PATTERNS

# DELL WYSE (Thin Clients)
DELL_WYSE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:80:64": ("thin_client", "Thin Client", "Dell Wyse"),
}

DELL_WYSE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Wyse\s*5070", "Dell Wyse 5070", "thin_client", "Wyse ThinOS"),
    (r"Wyse\s*5060", "Dell Wyse 5060", "thin_client", "Wyse ThinOS"),
    (r"Wyse\s*5040", "Dell Wyse 5040", "thin_client", "Wyse ThinOS"),
    (r"Wyse\s*3040", "Dell Wyse 3040", "thin_client", "Wyse ThinOS"),
    (r"Wyse\s*3030", "Dell Wyse 3030", "thin_client", "Wyse ThinOS"),
    (r"Wyse\s*7040", "Dell Wyse 7040", "thin_client", "Wyse ThinOS"),
    (r"OptiPlex\s*\d+.*Thin", "Dell OptiPlex Thin Client", "thin_client", "ThinOS"),
    (r"ThinOS", "Dell ThinOS Device", "thin_client", "Wyse ThinOS"),
    (r"Wyse", "Dell Wyse Thin Client", "thin_client", "Wyse ThinOS"),
]

# IGEL (Thin Clients)
IGEL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

IGEL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"IGEL\s*UD\d+", "IGEL UD", "thin_client", "IGEL OS"),
    (r"IGEL\s*UD7", "IGEL UD7", "thin_client", "IGEL OS"),
    (r"IGEL\s*UD6", "IGEL UD6", "thin_client", "IGEL OS"),
    (r"IGEL\s*UD3", "IGEL UD3", "thin_client", "IGEL OS"),
    (r"IGEL\s*UD2", "IGEL UD2", "thin_client", "IGEL OS"),
    (r"IGEL\s*OS\s*12", "IGEL OS 12", "thin_client", "IGEL OS 12"),
    (r"IGEL\s*OS\s*11", "IGEL OS 11", "thin_client", "IGEL OS 11"),
    (r"IGEL\s*OS", "IGEL OS", "thin_client", "IGEL OS"),
    (r"IGEL", "IGEL Thin Client", "thin_client", "IGEL OS"),
]


# WEARABLE / FITNESS DEVICE PATTERNS

# FITBIT
FITBIT_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

FITBIT_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Fitbit\s*Sense\s*2", "Fitbit Sense 2", "smartwatch", "Fitbit App"),
    (r"Fitbit\s*Sense", "Fitbit Sense", "smartwatch", "Fitbit App"),
    (r"Fitbit\s*Versa\s*4", "Fitbit Versa 4", "smartwatch", "Fitbit App"),
    (r"Fitbit\s*Versa\s*3", "Fitbit Versa 3", "smartwatch", "Fitbit App"),
    (r"Fitbit\s*Versa", "Fitbit Versa", "smartwatch", "Fitbit App"),
    (r"Fitbit\s*Charge\s*6", "Fitbit Charge 6", "fitness_tracker", "Fitbit App"),
    (r"Fitbit\s*Charge\s*5", "Fitbit Charge 5", "fitness_tracker", "Fitbit App"),
    (r"Fitbit\s*Charge", "Fitbit Charge", "fitness_tracker", "Fitbit App"),
    (r"Fitbit\s*Luxe", "Fitbit Luxe", "fitness_tracker", "Fitbit App"),
    (r"Fitbit\s*Inspire\s*3", "Fitbit Inspire 3", "fitness_tracker", "Fitbit App"),
    (r"Fitbit\s*Inspire", "Fitbit Inspire", "fitness_tracker", "Fitbit App"),
    (r"Fitbit\s*Aria", "Fitbit Aria Scale", "smart_scale", "Fitbit App"),
    (r"Fitbit", "Fitbit Device", "fitness_tracker", "Fitbit App"),
]

# GARMIN
GARMIN_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "0C:68:3E": ("fitness_tracker", "Wearable", "Garmin"),
    # REMOVED: D4:81:D7 - IEEE assigns to Unknown, not GARMIN
}

GARMIN_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Smartwatches
    (r"Garmin\s*fenix\s*8", "Garmin fenix 8", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*fenix\s*7", "Garmin fenix 7", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*fenix", "Garmin fenix", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Venu\s*3", "Garmin Venu 3", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Venu\s*2", "Garmin Venu 2", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Venu", "Garmin Venu", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Forerunner\s*\d+", "Garmin Forerunner", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Enduro", "Garmin Enduro", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Instinct\s*2", "Garmin Instinct 2", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Instinct", "Garmin Instinct", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Epix", "Garmin Epix", "smartwatch", "Garmin Connect"),
    # Fitness
    (r"Garmin\s*Vivosmart", "Garmin Vivosmart", "fitness_tracker", "Garmin Connect"),
    (r"Garmin\s*Vivoactive", "Garmin Vivoactive", "smartwatch", "Garmin Connect"),
    (r"Garmin\s*Vivomove", "Garmin Vivomove", "smartwatch", "Garmin Connect"),
    # Cycling/Edge
    (r"Garmin\s*Edge\s*\d+", "Garmin Edge", "cycling_computer", "Garmin Connect"),
    # GPS
    (r"Garmin\s*GPSMAP", "Garmin GPSMAP", "gps", "Garmin Connect"),
    (r"Garmin\s*Montana", "Garmin Montana", "gps", "Garmin Connect"),
    (r"Garmin", "Garmin Device", "fitness_tracker", "Garmin Connect"),
]

# WITHINGS
WITHINGS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:24:E4": ("health_device", "Wearable", "Withings"),
}

WITHINGS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Withings\s*ScanWatch\s*2", "Withings ScanWatch 2", "smartwatch", "Withings App"),
    (r"Withings\s*ScanWatch\s*Light", "Withings ScanWatch Light", "smartwatch", "Withings App"),
    (r"Withings\s*ScanWatch", "Withings ScanWatch", "smartwatch", "Withings App"),
    (r"Withings\s*Steel\s*HR", "Withings Steel HR", "smartwatch", "Withings App"),
    (r"Withings\s*Move\s*ECG", "Withings Move ECG", "smartwatch", "Withings App"),
    (r"Withings\s*Move", "Withings Move", "fitness_tracker", "Withings App"),
    (r"Withings\s*Body\s*Scan", "Withings Body Scan", "smart_scale", "Withings App"),
    (r"Withings\s*Body\s*Cardio", "Withings Body Cardio", "smart_scale", "Withings App"),
    (r"Withings\s*Body\+", "Withings Body+", "smart_scale", "Withings App"),
    (r"Withings\s*Body", "Withings Body Scale", "smart_scale", "Withings App"),
    (r"Withings\s*BPM\s*Core", "Withings BPM Core", "blood_pressure", "Withings App"),
    (r"Withings\s*BPM\s*Connect", "Withings BPM Connect", "blood_pressure", "Withings App"),
    (r"Withings\s*Sleep\s*Analyzer", "Withings Sleep Analyzer", "sleep_tracker", "Withings App"),
    (r"Withings\s*Thermo", "Withings Thermo", "thermometer", "Withings App"),
    (r"Withings", "Withings Device", "health_device", "Withings App"),
]

# OURA
OURA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

OURA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Oura\s*Ring\s*Gen\s*3", "Oura Ring Gen 3", "smart_ring", "Oura App"),
    (r"Oura\s*Ring\s*3", "Oura Ring 3", "smart_ring", "Oura App"),
    (r"Oura\s*Ring\s*Gen\s*2", "Oura Ring Gen 2", "smart_ring", "Oura App"),
    (r"Oura\s*Ring", "Oura Ring", "smart_ring", "Oura App"),
    (r"Oura", "Oura Ring", "smart_ring", "Oura App"),
]

# PELOTON
PELOTON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 68:37:E9 - IEEE assigns to Unknown, not PELOTON
}

PELOTON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Peloton\s*Bike\+", "Peloton Bike+", "fitness_equipment", "Peloton App"),
    (r"Peloton\s*Bike", "Peloton Bike", "fitness_equipment", "Peloton App"),
    (r"Peloton\s*Tread\+", "Peloton Tread+", "fitness_equipment", "Peloton App"),
    (r"Peloton\s*Tread", "Peloton Tread", "fitness_equipment", "Peloton App"),
    (r"Peloton\s*Row", "Peloton Row", "fitness_equipment", "Peloton App"),
    (r"Peloton\s*Guide", "Peloton Guide", "fitness_equipment", "Peloton App"),
    (r"Peloton", "Peloton Device", "fitness_equipment", "Peloton App"),
]


# TELECOM / MOBILE DEVICE PATTERNS

# MOTOROLA
MOTOROLA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:04:56 - IEEE assigns to Unknown, not MOTOROLA
    "00:0A:28": ("mobile", "Telecom", "Motorola"),
    "34:BB:26": ("mobile", "Telecom", "Motorola"),
    "40:88:05": ("mobile", "Telecom", "Motorola"),
    # REMOVED: 5C:5A:C7 - IEEE assigns to Unknown, not MOTOROLA
}

MOTOROLA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Phones
    (r"Moto\s*G\s*Power", "Motorola Moto G Power", "smartphone", "Android"),
    (r"Moto\s*G\s*Stylus", "Motorola Moto G Stylus", "smartphone", "Android"),
    (r"Moto\s*G\s*\d+", "Motorola Moto G", "smartphone", "Android"),
    (r"Moto\s*Edge\s*\d+", "Motorola Moto Edge", "smartphone", "Android"),
    (r"Moto\s*Edge", "Motorola Moto Edge", "smartphone", "Android"),
    (r"Motorola\s*razr\+", "Motorola razr+", "smartphone", "Android"),
    (r"Motorola\s*razr", "Motorola razr", "smartphone", "Android"),
    (r"ThinkPhone", "Motorola ThinkPhone", "smartphone", "Android"),
    # Two-Way Radios
    (r"APX\s*\d+", "Motorola APX Radio", "two_way_radio", "APX NEXT"),
    (r"XPR\s*\d+", "Motorola XPR Radio", "two_way_radio", "MOTOTRBO"),
    (r"SL\s*\d+", "Motorola SL Radio", "two_way_radio", "MOTOTRBO"),
    (r"MOTOTRBO", "Motorola MOTOTRBO", "two_way_radio", "MOTOTRBO"),
    # Generic
    (r"Motorola", "Motorola Device", "mobile", "Android"),
    (r"Moto\s*", "Motorola Device", "smartphone", "Android"),
]

# NOKIA
NOKIA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:02:EE": ("mobile", "Telecom", "Nokia"),
    "00:0E:ED": ("mobile", "Telecom", "Nokia"),
    "00:12:62": ("mobile", "Telecom", "Nokia"),
    "00:15:A0": ("mobile", "Telecom", "Nokia"),
    "00:16:4E": ("mobile", "Telecom", "Nokia"),
    "00:17:B0": ("mobile", "Telecom", "Nokia"),
    "00:18:0F": ("mobile", "Telecom", "Nokia"),
    "00:19:2D": ("mobile", "Telecom", "Nokia"),
    "00:1A:89": ("mobile", "Telecom", "Nokia"),
    "00:1B:AF": ("mobile", "Telecom", "Nokia"),
    "00:1C:35": ("mobile", "Telecom", "Nokia"),
    "00:1D:6E": ("mobile", "Telecom", "Nokia"),
    "00:1E:3A": ("mobile", "Telecom", "Nokia"),
    "00:1F:00": ("mobile", "Telecom", "Nokia"),
    "34:7E:39": ("mobile", "Telecom", "Nokia"),
    # REMOVED: CC:2D:E0 - IEEE assigns to Unknown, not NOKIA
}

NOKIA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Network Equipment
    (r"Nokia\s*AirScale", "Nokia AirScale", "base_station", "NetAct"),
    (r"Nokia\s*7750\s*SR", "Nokia 7750 SR", "router", "SR OS"),
    (r"Nokia\s*7705\s*SAR", "Nokia 7705 SAR", "router", "SR OS"),
    (r"Nokia\s*7210\s*SAS", "Nokia 7210 SAS", "switch", "SR OS"),
    (r"Nokia\s*7250\s*IXR", "Nokia 7250 IXR", "router", "SR OS"),
    (r"Nokia\s*SROS", "Nokia SR OS Router", "router", "SR OS"),
    (r"Nokia\s*Nuage", "Nokia Nuage", "sdn_controller", "Nuage VSP"),
    # Phones
    (r"Nokia\s*XR\d+", "Nokia XR", "smartphone", "Android"),
    (r"Nokia\s*G\d+", "Nokia G Series", "smartphone", "Android"),
    (r"Nokia\s*C\d+", "Nokia C Series", "smartphone", "Android"),
    # Generic
    (r"Nokia", "Nokia Device", "mobile", None),
]

# ERICSSON
ERICSSON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:01:EC": ("telecom", "Telecom", "Ericsson"),
}

ERICSSON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # 5G/LTE Radio
    (r"Ericsson\s*Radio\s*\d+", "Ericsson Radio", "base_station", "RAN"),
    (r"AIR\s*\d+", "Ericsson AIR", "base_station", "RAN"),
    (r"Baseband\s*\d+", "Ericsson Baseband", "base_station", "RAN"),
    # Routers/Core
    (r"Ericsson\s*Router\s*\d+", "Ericsson Router", "router", "Ericsson"),
    (r"Ericsson\s*6000", "Ericsson Router 6000", "router", "Ericsson"),
    (r"Ericsson\s*8000", "Ericsson Router 8000", "router", "Ericsson"),
    # Generic
    (r"Ericsson", "Ericsson Device", "telecom", "Ericsson"),
]


# PC HARDWARE VENDOR PATTERNS

# INTEL
INTEL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:02:B3": ("nic", "Hardware", "Intel"),
    # REMOVED: 00:03:47 - IEEE assigns to Unknown, not INTEL
    "00:04:23": ("nic", "Hardware", "Intel"),
    "00:07:E9": ("nic", "Hardware", "Intel"),
    # REMOVED: 00:0E:0C - IEEE assigns to Unknown, not INTEL
    "00:11:11": ("nic", "Hardware", "Intel"),
    "00:12:F0": ("nic", "Hardware", "Intel"),
    "00:13:02": ("nic", "Hardware", "Intel"),
    "00:13:20": ("nic", "Hardware", "Intel"),
    "00:13:E8": ("nic", "Hardware", "Intel"),
    "00:15:17": ("nic", "Hardware", "Intel"),
    "00:16:6F": ("nic", "Hardware", "Intel"),
    "00:16:76": ("nic", "Hardware", "Intel"),
    "00:16:EA": ("nic", "Hardware", "Intel"),
    "00:16:EB": ("nic", "Hardware", "Intel"),
    # REMOVED: 00:17:F2 - IEEE assigns to Unknown, not INTEL
    "00:18:DE": ("nic", "Hardware", "Intel"),
    "00:19:D1": ("nic", "Hardware", "Intel"),
    "00:19:D2": ("nic", "Hardware", "Intel"),
    "00:1B:21": ("nic", "Hardware", "Intel"),
    "00:1C:BF": ("nic", "Hardware", "Intel"),
    "00:1C:C0": ("nic", "Hardware", "Intel"),
    "00:1D:E1": ("nic", "Hardware", "Intel"),
    "00:1E:64": ("nic", "Hardware", "Intel"),
    "00:1E:65": ("nic", "Hardware", "Intel"),
    "00:1E:67": ("nic", "Hardware", "Intel"),
    "00:1F:3B": ("nic", "Hardware", "Intel"),
    "00:1F:3C": ("nic", "Hardware", "Intel"),
    "00:21:5C": ("nic", "Hardware", "Intel"),
    "00:21:5D": ("nic", "Hardware", "Intel"),
    "00:21:6A": ("nic", "Hardware", "Intel"),
    "00:21:6B": ("nic", "Hardware", "Intel"),
    "00:22:FA": ("nic", "Hardware", "Intel"),
    "00:22:FB": ("nic", "Hardware", "Intel"),
    "00:24:D6": ("nic", "Hardware", "Intel"),
    "00:24:D7": ("nic", "Hardware", "Intel"),
    "00:26:C6": ("nic", "Hardware", "Intel"),
    "00:26:C7": ("nic", "Hardware", "Intel"),
    "00:27:10": ("nic", "Hardware", "Intel"),
    "64:D4:DA": ("nic", "Hardware", "Intel"),
    "78:92:9C": ("nic", "Hardware", "Intel"),
    "8C:8D:28": ("nic", "Hardware", "Intel"),
    "AC:ED:5C": ("nic", "Hardware", "Intel"),
    "B4:96:91": ("nic", "Hardware", "Intel"),
}

INTEL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # NUC
    (r"Intel\s*NUC\s*\d+", "Intel NUC", "mini_pc", "BIOS"),
    (r"NUC\d+", "Intel NUC", "mini_pc", "BIOS"),
    # NICs
    (r"Intel.*I\d{3}", "Intel I-series NIC", "nic", "Driver"),
    (r"Intel.*X\d{3}", "Intel X-series NIC", "nic", "Driver"),
    (r"Intel.*E\d{3}", "Intel E-series NIC", "nic", "Driver"),
    (r"Intel\s*Ethernet", "Intel Ethernet Adapter", "nic", "Driver"),
    # Generic
    (r"Intel", "Intel Device", "nic", None),
]

# AMD
AMD_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:10:18": ("nic", "Hardware", "AMD"),
}

AMD_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"AMD\s*EPYC", "AMD EPYC Server", "server", "BIOS"),
    (r"AMD\s*Ryzen", "AMD Ryzen System", "computer", "BIOS"),
    (r"AMD\s*Radeon", "AMD Radeon GPU", "gpu", "Driver"),
    (r"AMD", "AMD Device", "nic", None),
]

# ASROCK
ASROCK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:25:22 - IEEE assigns to Unknown, not ASROCK
    "BC:5F:F4": ("computer", "Hardware", "ASRock"),
}

ASROCK_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"ASRock\s*X\d{3}", "ASRock X-Series", "motherboard", "UEFI"),
    (r"ASRock\s*B\d{3}", "ASRock B-Series", "motherboard", "UEFI"),
    (r"ASRock\s*Z\d{3}", "ASRock Z-Series", "motherboard", "UEFI"),
    (r"ASRock\s*Rack", "ASRock Rack Server", "server", "IPMI"),
    (r"ASRock", "ASRock Device", "computer", "UEFI"),
]

# GIGABYTE
GIGABYTE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0C:6E - IEEE assigns to Unknown, not GIGABYTE
    "18:C0:4D": ("computer", "Hardware", "Gigabyte"),
    "50:E5:49": ("computer", "Hardware", "Gigabyte"),
    "74:56:3C": ("computer", "Hardware", "Gigabyte"),
}

GIGABYTE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Gigabyte\s*X\d{3}", "Gigabyte X-Series", "motherboard", "UEFI"),
    (r"Gigabyte\s*B\d{3}", "Gigabyte B-Series", "motherboard", "UEFI"),
    (r"Gigabyte\s*Z\d{3}", "Gigabyte Z-Series", "motherboard", "UEFI"),
    (r"Gigabyte\s*AORUS", "Gigabyte AORUS", "motherboard", "UEFI"),
    (r"AORUS", "Gigabyte AORUS", "motherboard", "UEFI"),
    (r"Gigabyte\s*BRIX", "Gigabyte BRIX", "mini_pc", "UEFI"),
    (r"Gigabyte", "Gigabyte Device", "computer", "UEFI"),
]

# NVIDIA (Hardware)
NVIDIA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:04:4B - IEEE assigns to Unknown, not NVIDIA
    # REMOVED: 48:B0:2D - IEEE assigns to Unknown, not NVIDIA
    # REMOVED: 00:E0:4C - IEEE assigns to Realtek Semiconductor, not NVIDIA
}

NVIDIA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"NVIDIA\s*DGX", "NVIDIA DGX", "server", "DGX OS"),
    (r"NVIDIA\s*RTX\s*\d+", "NVIDIA RTX GPU", "gpu", "Driver"),
    (r"NVIDIA\s*GeForce\s*RTX", "NVIDIA GeForce RTX", "gpu", "Driver"),
    (r"NVIDIA\s*Quadro", "NVIDIA Quadro", "gpu", "Driver"),
    (r"NVIDIA\s*Tesla", "NVIDIA Tesla", "gpu", "Driver"),
    (r"NVIDIA\s*A\d+", "NVIDIA A-Series GPU", "gpu", "Driver"),
    (r"NVIDIA\s*H\d+", "NVIDIA H-Series GPU", "gpu", "Driver"),
    (r"NVIDIA\s*Shield", "NVIDIA Shield", "media_player", "Android TV"),
    (r"NVIDIA", "NVIDIA Device", "gpu", "Driver"),
]


# SERVER / HARDWARE VENDOR PATTERNS

# SUPERMICRO
SUPERMICRO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:25:90": ("server", "Server", "Supermicro Server"),
    "00:30:48": ("server", "Server", "Supermicro Server"),
    # REMOVED: 0C:C4:7A - IEEE assigns to Unknown, not SUPERMICRO
    "AC:1F:6B": ("server", "Server", "Supermicro Server"),
}

SUPERMICRO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # GPU Servers
    (r"SYS-\d+G", "Supermicro GPU Server", "server", "IPMI"),
    (r"AS-\d+G", "Supermicro GPU Server", "server", "IPMI"),

    # Storage Servers
    (r"SSG-\d+", "Supermicro Storage Server", "storage_server", "IPMI"),

    # Blade Servers
    (r"SBI-\d+", "Supermicro Blade Server", "blade_server", "IPMI"),

    # Rackmount
    (r"SYS-\d+", "Supermicro Rackmount Server", "server", "IPMI"),
    (r"AS-\d+", "Supermicro AMD Server", "server", "IPMI"),

    # MicroBlade
    (r"MBI-\d+", "Supermicro MicroBlade", "blade_server", "IPMI"),

    # Tower
    (r"SYS-\d+T", "Supermicro Tower Server", "server", "IPMI"),

    # IPMI/BMC
    (r"Supermicro.*IPMI", "Supermicro IPMI BMC", "bmc", "IPMI"),
    (r"X\d+\w+-\w+", "Supermicro Motherboard", "server", "IPMI"),

    # Generic
    (r"Supermicro", "Supermicro Server", "server", "IPMI"),
]

# INSPUR
INSPUR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 18:DB:F2 - IEEE assigns to Unknown, not INSPUR
    # REMOVED: 24:6E:96 - IEEE assigns to Unknown, not INSPUR
    # REMOVED: 50:9A:4C - IEEE assigns to Unknown, not INSPUR
}

INSPUR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # NF Series (2U Rack)
    (r"NF\d+M\d+", "Inspur NF Rack Server", "server", None),
    (r"NF8480M\d+", "Inspur NF8480 4U Server", "server", None),
    (r"NF5280M\d+", "Inspur NF5280 2U Server", "server", None),
    (r"NF5180M\d+", "Inspur NF5180 1U Server", "server", None),

    # SA Series (AMD)
    (r"SA\d+M\d+", "Inspur SA AMD Server", "server", None),
    (r"SA5248M\d+", "Inspur SA5248 2U AMD", "server", None),

    # NX Series (High Density)
    (r"NX\d+M\d+", "Inspur NX High-Density", "server", None),

    # Storage
    (r"AS\d+N\d+", "Inspur Storage Server", "storage_server", None),

    # Generic
    (r"Inspur", "Inspur Server", "server", None),
]

# LENOVO SERVERS (ThinkSystem)
LENOVO_SERVER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

LENOVO_SERVER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ThinkSystem SR (Rack)
    (r"ThinkSystem\s*SR950", "Lenovo ThinkSystem SR950", "server", "XCC"),
    (r"ThinkSystem\s*SR860", "Lenovo ThinkSystem SR860", "server", "XCC"),
    (r"ThinkSystem\s*SR850", "Lenovo ThinkSystem SR850", "server", "XCC"),
    (r"ThinkSystem\s*SR670", "Lenovo ThinkSystem SR670", "server", "XCC"),
    (r"ThinkSystem\s*SR650", "Lenovo ThinkSystem SR650", "server", "XCC"),
    (r"ThinkSystem\s*SR630", "Lenovo ThinkSystem SR630", "server", "XCC"),
    (r"ThinkSystem\s*SR550", "Lenovo ThinkSystem SR550", "server", "XCC"),
    (r"ThinkSystem\s*SR530", "Lenovo ThinkSystem SR530", "server", "XCC"),
    (r"ThinkSystem\s*SR\d+", "Lenovo ThinkSystem SR", "server", "XCC"),

    # ThinkSystem ST (Tower)
    (r"ThinkSystem\s*ST\d+", "Lenovo ThinkSystem Tower", "server", "XCC"),

    # ThinkSystem SD (High Density)
    (r"ThinkSystem\s*SD\d+", "Lenovo ThinkSystem SD", "server", "XCC"),

    # ThinkSystem SN (Blade)
    (r"ThinkSystem\s*SN\d+", "Lenovo ThinkSystem Blade", "blade_server", "XCC"),

    # ThinkAgile (HCI)
    (r"ThinkAgile.*VX", "Lenovo ThinkAgile VX", "hci_node", "XCC"),
    (r"ThinkAgile.*MX", "Lenovo ThinkAgile MX", "hci_node", "XCC"),
    (r"ThinkAgile.*HX", "Lenovo ThinkAgile HX", "hci_node", "XCC"),

    # XClarity
    (r"XClarity", "Lenovo XClarity Controller", "bmc", "XCC"),

    # Generic
    (r"ThinkSystem", "Lenovo ThinkSystem Server", "server", "XCC"),
]

# FUJITSU SERVERS
FUJITSU_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0B:5D": ("server", "Server", "Fujitsu Server"),
    "00:17:42": ("server", "Server", "Fujitsu Server"),
    "00:19:99": ("server", "Server", "Fujitsu Server"),
    "B0:99:28": ("server", "Server", "Fujitsu Server"),
}

FUJITSU_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # PRIMERGY RX (Rack)
    (r"PRIMERGY\s*RX4770", "Fujitsu PRIMERGY RX4770", "server", "iRMC"),
    (r"PRIMERGY\s*RX2540", "Fujitsu PRIMERGY RX2540", "server", "iRMC"),
    (r"PRIMERGY\s*RX2530", "Fujitsu PRIMERGY RX2530", "server", "iRMC"),
    (r"PRIMERGY\s*RX1330", "Fujitsu PRIMERGY RX1330", "server", "iRMC"),
    (r"PRIMERGY\s*RX\d+", "Fujitsu PRIMERGY RX", "server", "iRMC"),

    # PRIMERGY TX (Tower)
    (r"PRIMERGY\s*TX\d+", "Fujitsu PRIMERGY TX", "server", "iRMC"),

    # PRIMERGY CX (High Density)
    (r"PRIMERGY\s*CX\d+", "Fujitsu PRIMERGY CX", "server", "iRMC"),

    # PRIMERGY BX (Blade)
    (r"PRIMERGY\s*BX\d+", "Fujitsu PRIMERGY Blade", "blade_server", "iRMC"),

    # PRIMEQUEST (Mission Critical)
    (r"PRIMEQUEST\s*\d+", "Fujitsu PRIMEQUEST", "server", None),

    # iRMC
    (r"iRMC", "Fujitsu iRMC", "bmc", "iRMC"),

    # Generic
    (r"PRIMERGY", "Fujitsu PRIMERGY", "server", "iRMC"),
    (r"Fujitsu.*Server", "Fujitsu Server", "server", None),
]

# HUAWEI SERVERS/NETWORK
HUAWEI_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Huawei networking equipment
    "00:18:82": ("switch", "Network Equipment", "Huawei Switch"),
    "00:1E:10": ("router", "Network Equipment", "Huawei Router"),
    "00:25:9E": ("router", "Network Equipment", "Huawei Router"),
    "20:F3:A3": ("access_point", "Network Equipment", "Huawei AP"),
    "34:6B:D3": ("switch", "Network Equipment", "Huawei Switch"),
    "48:46:FB": ("router", "Network Equipment", "Huawei Router"),
    # REMOVED: 70:7B:E8 - IEEE assigns to Unknown, not HUAWEI
    "AC:E8:7B": ("router", "Network Equipment", "Huawei Router"),
    "E0:24:7F": ("access_point", "Network Equipment", "Huawei AP"),
    # Huawei mobile devices (phones, tablets)
    "00:46:4B": ("phone", "Mobile", "Huawei Phone"),
    "00:66:4B": ("phone", "Mobile", "Huawei Phone"),
    "00:9A:CD": ("phone", "Mobile", "Huawei Phone"),
    "04:B0:E7": ("phone", "Mobile", "Huawei Phone"),
    "04:C0:6F": ("phone", "Mobile", "Huawei Phone"),
    "08:19:A6": ("phone", "Mobile", "Huawei Phone"),
    "08:63:61": ("phone", "Mobile", "Huawei Phone"),
    "0C:37:DC": ("phone", "Mobile", "Huawei Phone"),
    "0C:45:BA": ("phone", "Mobile", "Huawei Phone"),
    "10:1B:54": ("phone", "Mobile", "Huawei Phone"),
    "10:44:00": ("phone", "Mobile", "Huawei Phone"),
    "10:47:80": ("phone", "Mobile", "Huawei Phone"),
    "10:C6:1F": ("phone", "Mobile", "Huawei Phone"),
    "14:30:04": ("phone", "Mobile", "Huawei Phone"),
    "14:9D:09": ("phone", "Mobile", "Huawei Phone"),
    "18:D2:76": ("phone", "Mobile", "Huawei Phone"),
    "1C:15:1F": ("phone", "Mobile", "Huawei Phone"),
    "24:09:95": ("phone", "Mobile", "Huawei Phone"),
    "24:4C:07": ("phone", "Mobile", "Huawei Phone"),
    "24:DB:AC": ("phone", "Mobile", "Huawei Phone"),
    "28:3C:E4": ("phone", "Mobile", "Huawei Phone"),
    "28:6E:D4": ("phone", "Mobile", "Huawei Phone"),
    "2C:AB:00": ("phone", "Mobile", "Huawei Phone"),
    "30:D1:7E": ("phone", "Mobile", "Huawei Phone"),
    "34:12:F9": ("phone", "Mobile", "Huawei Phone"),
    "38:F8:89": ("phone", "Mobile", "Huawei Phone"),
    "3C:FA:43": ("phone", "Mobile", "Huawei Phone"),
    "40:4D:8E": ("phone", "Mobile", "Huawei Phone"),
    "44:6A:2E": ("phone", "Mobile", "Huawei Phone"),
    "48:00:31": ("phone", "Mobile", "Huawei Phone"),
    "48:AD:08": ("phone", "Mobile", "Huawei Phone"),
    "4C:50:77": ("phone", "Mobile", "Huawei Phone"),
    "50:A7:2B": ("phone", "Mobile", "Huawei Phone"),
    "54:BA:D6": ("phone", "Mobile", "Huawei Phone"),
    "58:2A:F7": ("phone", "Mobile", "Huawei Phone"),
    "5C:4C:A9": ("phone", "Mobile", "Huawei Phone"),
    "5C:B4:3E": ("phone", "Mobile", "Huawei Phone"),
    "60:DE:44": ("phone", "Mobile", "Huawei Phone"),
    "64:A6:51": ("phone", "Mobile", "Huawei Phone"),
    "68:A0:F6": ("phone", "Mobile", "Huawei Phone"),
    "6C:B7:49": ("phone", "Mobile", "Huawei Phone"),
    "70:19:2F": ("phone", "Mobile", "Huawei Phone"),
    "70:8A:09": ("phone", "Mobile", "Huawei Phone"),
    "7C:60:97": ("phone", "Mobile", "Huawei Phone"),
    "7C:A1:77": ("phone", "Mobile", "Huawei Phone"),
    "80:D0:9B": ("phone", "Mobile", "Huawei Phone"),
    "84:A8:E4": ("phone", "Mobile", "Huawei Phone"),
    "84:DB:AC": ("phone", "Mobile", "Huawei Phone"),
    "88:28:B3": ("phone", "Mobile", "Huawei Phone"),
    "8C:34:FD": ("phone", "Mobile", "Huawei Phone"),
    "90:17:AC": ("phone", "Mobile", "Huawei Phone"),
    "94:04:9C": ("phone", "Mobile", "Huawei Phone"),
    "94:77:2B": ("phone", "Mobile", "Huawei Phone"),
    "98:E7:F5": ("phone", "Mobile", "Huawei Phone"),
    "9C:28:EF": ("phone", "Mobile", "Huawei Phone"),
    "9C:74:1A": ("phone", "Mobile", "Huawei Phone"),
    "A0:F4:79": ("phone", "Mobile", "Huawei Phone"),
    "A4:71:74": ("phone", "Mobile", "Huawei Phone"),
    "A4:93:3F": ("phone", "Mobile", "Huawei Phone"),
    "B4:CD:27": ("phone", "Mobile", "Huawei Phone"),
    "B8:BC:1B": ("phone", "Mobile", "Huawei Phone"),
    "BC:25:E0": ("phone", "Mobile", "Huawei Phone"),
    "BC:76:70": ("phone", "Mobile", "Huawei Phone"),
    "C0:70:09": ("phone", "Mobile", "Huawei Phone"),
    "C4:05:28": ("phone", "Mobile", "Huawei Phone"),
    "C4:86:E9": ("phone", "Mobile", "Huawei Phone"),
    "C8:D1:5E": ("phone", "Mobile", "Huawei Phone"),
    "CC:A2:23": ("phone", "Mobile", "Huawei Phone"),
    "D0:16:B4": ("phone", "Mobile", "Huawei Phone"),
    "D0:7A:B5": ("phone", "Mobile", "Huawei Phone"),
    "D4:6A:A8": ("phone", "Mobile", "Huawei Phone"),
    "D4:6E:5C": ("phone", "Mobile", "Huawei Phone"),
    "D8:C7:71": ("phone", "Mobile", "Huawei Phone"),
    "DC:D2:FC": ("phone", "Mobile", "Huawei Phone"),
    "E0:19:1D": ("phone", "Mobile", "Huawei Phone"),
    "E0:68:38": ("phone", "Mobile", "Huawei Phone"),
    "E4:72:E2": ("phone", "Mobile", "Huawei Phone"),
    "EC:23:3D": ("phone", "Mobile", "Huawei Phone"),
    "F0:43:47": ("phone", "Mobile", "Huawei Phone"),
    "F4:63:1F": ("phone", "Mobile", "Huawei Phone"),
    "F4:C7:14": ("phone", "Mobile", "Huawei Phone"),
    "F8:01:13": ("phone", "Mobile", "Huawei Phone"),
    "F8:4A:BF": ("phone", "Mobile", "Huawei Phone"),
    "FC:48:EF": ("phone", "Mobile", "Huawei Phone"),
    # Huawei additional networking OUIs
    "00:E0:FC": ("switch", "Network Equipment", "Huawei Switch"),
    "04:02:1F": ("router", "Network Equipment", "Huawei Router"),
    "04:BD:70": ("access_point", "Network Equipment", "Huawei AP"),
    "24:69:A5": ("switch", "Network Equipment", "Huawei Switch"),
    "28:31:52": ("router", "Network Equipment", "Huawei Router"),
    "40:CB:A8": ("router", "Network Equipment", "Huawei Router"),
    "4C:1F:CC": ("access_point", "Network Equipment", "Huawei AP"),
    "54:A5:1B": ("switch", "Network Equipment", "Huawei Switch"),
    "58:60:5F": ("router", "Network Equipment", "Huawei Router"),
    "60:DE:44": ("router", "Network Equipment", "Huawei Router"),
    "70:72:3C": ("switch", "Network Equipment", "Huawei Switch"),
    "78:6A:89": ("router", "Network Equipment", "Huawei Router"),
    "80:FB:06": ("access_point", "Network Equipment", "Huawei AP"),
    "84:BE:52": ("switch", "Network Equipment", "Huawei Switch"),
    "D0:D0:4B": ("switch", "Network Equipment", "Huawei Switch"),
    "D4:B1:10": ("router", "Network Equipment", "Huawei Router"),
    "E0:97:96": ("access_point", "Network Equipment", "Huawei AP"),
    "EC:38:8F": ("switch", "Network Equipment", "Huawei Switch"),
    "F4:4C:7F": ("router", "Network Equipment", "Huawei Router"),
}

HUAWEI_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Switches (CloudEngine)
    (r"CloudEngine\s*\d+", "Huawei CloudEngine Switch", "switch", "VRP"),
    (r"CE\d+-\d+", "Huawei CloudEngine", "switch", "VRP"),
    # S-Series switches use 4-digit model numbers like S5700, S6700, etc.
    # Using S\d{4} to avoid matching Siemens S7-1500 (which uses S7-xxxx format)
    (r"Huawei\s*S\d{4}", "Huawei S-Series Switch", "switch", "VRP"),
    (r"(?<!Siemens\s)S\d{4}-\d+", "Huawei S-Series Switch", "switch", "VRP"),

    # Routers (NetEngine) - require Huawei prefix for generic patterns
    (r"NetEngine\s*\d+", "Huawei NetEngine Router", "router", "VRP"),
    (r"Huawei\s*NE\d+-\d+", "Huawei NetEngine", "router", "VRP"),
    (r"Huawei\s*AR\d+", "Huawei AR Router", "router", "VRP"),

    # Firewalls (USG)
    (r"Huawei\s*USG\d+", "Huawei USG Firewall", "firewall", "VRP"),
    (r"HiSecEngine", "Huawei HiSecEngine", "firewall", "VRP"),

    # Wireless - require Huawei/AirEngine prefix, AP\d+ is too generic
    (r"AirEngine\s*\d+", "Huawei AirEngine AP", "access_point", None),
    (r"Huawei\s*AP\d+", "Huawei Access Point", "access_point", None),

    # Servers (FusionServer)
    (r"FusionServer\s*2288H", "Huawei FusionServer 2288H", "server", "iBMC"),
    (r"FusionServer\s*2488H", "Huawei FusionServer 2488H", "server", "iBMC"),
    (r"FusionServer\s*\d+", "Huawei FusionServer", "server", "iBMC"),
    (r"TaiShan\s*\d+", "Huawei TaiShan Server", "server", "iBMC"),

    # Storage
    (r"OceanStor\s*\d+", "Huawei OceanStor", "storage", None),
    (r"Dorado\s*\d+", "Huawei OceanStor Dorado", "storage", None),

    # Generic
    (r"Huawei.*VRP", "Huawei Network Device", "network_device", "VRP"),
    (r"Huawei", "Huawei Device", "network_device", None),
]

# ZTE NETWORK/SERVERS
ZTE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:15:EB": ("network_device", "Network Equipment", "ZTE"),
    "00:19:C6": ("network_device", "Network Equipment", "ZTE"),
    "00:1E:73": ("network_device", "Network Equipment", "ZTE"),
    "00:22:93": ("network_device", "Network Equipment", "ZTE"),
    "00:25:12": ("network_device", "Network Equipment", "ZTE"),
    "30:D3:86": ("network_device", "Network Equipment", "ZTE"),
    "D0:15:4A": ("network_device", "Network Equipment", "ZTE"),
}

ZTE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Switches
    (r"ZXR10\s*\d+", "ZTE ZXR10 Switch", "switch", "ZXROS"),
    (r"ZXR10", "ZTE ZXR10", "switch", "ZXROS"),

    # Routers
    (r"ZXR10.*Router", "ZTE Router", "router", "ZXROS"),
    (r"ZXHN", "ZTE Home Gateway", "router", None),

    # OLT/ONT
    (r"ZXA10\s*C\d+", "ZTE OLT", "olt", None),
    (r"ZXHN\s*F\d+", "ZTE ONT", "ont", None),

    # PON
    (r"GPON\s*OLT", "ZTE GPON OLT", "olt", None),

    # Wireless
    (r"ZXV10\s*W\d+", "ZTE Access Point", "access_point", None),

    # Generic
    (r"ZTE", "ZTE Device", "network_device", None),
]

# MELLANOX / NVIDIA NETWORKING
MELLANOX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:02:C9": ("switch", "Network Equipment", "Mellanox"),
    "24:8A:07": ("switch", "Network Equipment", "NVIDIA Networking"),
    "50:6B:4B": ("switch", "Network Equipment", "Mellanox"),
    "7C:FE:90": ("switch", "Network Equipment", "Mellanox"),
    "E4:1D:2D": ("switch", "Network Equipment", "Mellanox"),
    "E8:EB:D3": ("switch", "Network Equipment", "NVIDIA Networking"),
    "EC:0D:9A": ("switch", "Network Equipment", "Mellanox"),
}

MELLANOX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Spectrum (Ethernet)
    (r"Spectrum-\d+", "NVIDIA Spectrum Switch", "switch", "Cumulus"),
    (r"SN\d+-\d+", "NVIDIA SN Series Switch", "switch", "Cumulus"),
    (r"SN4\d+", "NVIDIA SN4000 400G Switch", "switch", "Cumulus"),
    (r"SN3\d+", "NVIDIA SN3000 100G Switch", "switch", "Cumulus"),
    (r"SN2\d+", "NVIDIA SN2000 Switch", "switch", "Cumulus"),

    # InfiniBand
    (r"QM\d+", "NVIDIA Quantum InfiniBand", "ib_switch", None),
    (r"HDR\s*Switch", "NVIDIA HDR InfiniBand", "ib_switch", None),
    (r"NDR\s*Switch", "NVIDIA NDR InfiniBand", "ib_switch", None),
    (r"EDR\s*Switch", "Mellanox EDR InfiniBand", "ib_switch", None),

    # DPU
    (r"BlueField-\d+", "NVIDIA BlueField DPU", "dpu", None),
    (r"BlueField", "NVIDIA BlueField DPU", "dpu", None),

    # Network Adapters
    (r"ConnectX-\d+", "NVIDIA ConnectX Adapter", "network_adapter", None),
    (r"ConnectX", "NVIDIA ConnectX", "network_adapter", None),

    # Generic
    (r"Cumulus\s*Linux", "NVIDIA Cumulus Linux", "switch", "Cumulus"),
    (r"Mellanox", "Mellanox Switch", "switch", None),
    (r"NVIDIA.*Networking", "NVIDIA Networking", "switch", None),
]


# GAMING CONSOLE PATTERNS

# Sony PlayStation
PLAYSTATION_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1D:0D - IEEE assigns to Unknown, not PLAYSTATION
    # REMOVED: 28:0D:FC - IEEE assigns to Unknown, not PLAYSTATION
    # REMOVED: 70:9E:29 - IEEE assigns to Unknown, not PLAYSTATION
    # REMOVED: BC:60:A7 - IEEE assigns to Unknown, not PLAYSTATION
    # REMOVED: FC:0F:E6 - IEEE assigns to Unknown, not PLAYSTATION
}

PLAYSTATION_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # PlayStation 5
    (r"PlayStation\s*5\s*Pro", "PlayStation 5 Pro", "gaming_console", "PS5 System Software"),
    (r"PlayStation\s*5|PS5", "PlayStation 5", "gaming_console", "PS5 System Software"),
    (r"CFI-1\d{3}", "PlayStation 5", "gaming_console", "PS5 System Software"),
    (r"CFI-2\d{3}", "PlayStation 5 Slim", "gaming_console", "PS5 System Software"),

    # PlayStation 4
    (r"PlayStation\s*4\s*Pro|PS4\s*Pro", "PlayStation 4 Pro", "gaming_console", "PS4 System Software"),
    (r"PlayStation\s*4|PS4", "PlayStation 4", "gaming_console", "PS4 System Software"),
    (r"CUH-7\d{3}", "PlayStation 4 Pro", "gaming_console", "PS4 System Software"),
    (r"CUH-2\d{3}", "PlayStation 4 Slim", "gaming_console", "PS4 System Software"),
    (r"CUH-1\d{3}", "PlayStation 4", "gaming_console", "PS4 System Software"),

    # PlayStation 3
    (r"PlayStation\s*3|PS3", "PlayStation 3", "gaming_console", "PS3 System Software"),
    (r"CECH-\d{4}", "PlayStation 3", "gaming_console", "PS3 System Software"),

    # PlayStation VR
    (r"PlayStation\s*VR\s*2|PSVR\s*2", "PlayStation VR2", "vr_headset", "PS VR2 Firmware"),
    (r"PlayStation\s*VR|PSVR", "PlayStation VR", "vr_headset", "PS VR Firmware"),

    # PlayStation Vita/Portable
    (r"PlayStation\s*Vita|PS\s*Vita", "PlayStation Vita", "handheld_console", "PS Vita Firmware"),
    (r"PlayStation\s*Portable|PSP", "PlayStation Portable", "handheld_console", "PSP Firmware"),

    # PlayStation Portal
    (r"PlayStation\s*Portal", "PlayStation Portal", "handheld_console", "Portal Firmware"),

    # Generic
    (r"PlayStation", "PlayStation", "gaming_console", None),
    (r"SONY.*SCEI", "PlayStation", "gaming_console", None),
]

# Microsoft Xbox
XBOX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:50:F2 - IEEE assigns to Unknown, not XBOX
    # REMOVED: 00:0D:3A - IEEE assigns to Unknown, not XBOX
    # REMOVED: 60:45:BD - IEEE assigns to Unknown, not XBOX
    # REMOVED: 98:5F:D3 - IEEE assigns to Unknown, not XBOX
    # REMOVED: 28:18:78 - IEEE assigns to Unknown, not XBOX
    # REMOVED: 7C:1E:52 - IEEE assigns to Unknown, not XBOX
}

XBOX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Xbox Series X|S
    (r"Xbox\s*Series\s*X", "Xbox Series X", "gaming_console", "Xbox OS"),
    (r"Xbox\s*Series\s*S", "Xbox Series S", "gaming_console", "Xbox OS"),

    # Xbox One
    (r"Xbox\s*One\s*X", "Xbox One X", "gaming_console", "Xbox OS"),
    (r"Xbox\s*One\s*S", "Xbox One S", "gaming_console", "Xbox OS"),
    (r"Xbox\s*One", "Xbox One", "gaming_console", "Xbox OS"),

    # Xbox 360
    (r"Xbox\s*360\s*S", "Xbox 360 S", "gaming_console", "Xbox 360 Dashboard"),
    (r"Xbox\s*360\s*E", "Xbox 360 E", "gaming_console", "Xbox 360 Dashboard"),
    (r"Xbox\s*360", "Xbox 360", "gaming_console", "Xbox 360 Dashboard"),

    # Original Xbox
    (r"Xbox(?!\s*(One|360|Series))", "Xbox", "gaming_console", "Xbox Dashboard"),

    # Xbox Cloud Gaming
    (r"Xbox\s*Cloud", "Xbox Cloud Gaming", "cloud_gaming", "Xbox OS"),
]

# Nintendo
NINTENDO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:09:BF": ("gaming_console", "Gaming", "Nintendo"),
    "00:16:56": ("gaming_console", "Gaming", "Nintendo"),
    "00:17:AB": ("gaming_console", "Gaming", "Nintendo"),
    "00:19:1D": ("gaming_console", "Gaming", "Nintendo"),
    "00:19:FD": ("gaming_console", "Gaming", "Nintendo"),
    "00:1A:E9": ("gaming_console", "Gaming", "Nintendo"),
    "00:1B:7A": ("gaming_console", "Gaming", "Nintendo"),
    "00:1B:EA": ("gaming_console", "Gaming", "Nintendo"),
    "00:1C:BE": ("gaming_console", "Gaming", "Nintendo"),
    "00:1D:BC": ("gaming_console", "Gaming", "Nintendo"),
    "00:1E:35": ("gaming_console", "Gaming", "Nintendo"),
    "00:1E:A9": ("gaming_console", "Gaming", "Nintendo"),
    "00:1F:32": ("gaming_console", "Gaming", "Nintendo"),
    "00:1F:C5": ("gaming_console", "Gaming", "Nintendo"),
    "00:21:47": ("gaming_console", "Gaming", "Nintendo"),
    "00:21:BD": ("gaming_console", "Gaming", "Nintendo"),
    "00:22:4C": ("gaming_console", "Gaming", "Nintendo"),
    "00:22:AA": ("gaming_console", "Gaming", "Nintendo"),
    "00:23:31": ("gaming_console", "Gaming", "Nintendo"),
    "00:23:CC": ("gaming_console", "Gaming", "Nintendo"),
    "00:24:1E": ("gaming_console", "Gaming", "Nintendo"),
    "00:24:F3": ("gaming_console", "Gaming", "Nintendo"),
    "00:25:A0": ("gaming_console", "Gaming", "Nintendo"),
    "00:26:59": ("gaming_console", "Gaming", "Nintendo"),
    "00:27:09": ("gaming_console", "Gaming", "Nintendo"),
    "2C:10:C1": ("gaming_console", "Gaming", "Nintendo"),
    # REMOVED: 34:AF:2C - IEEE assigns to Unknown, not NINTENDO
    "40:D2:8A": ("gaming_console", "Gaming", "Nintendo"),
    "40:F4:07": ("gaming_console", "Gaming", "Nintendo"),
    "58:2F:40": ("gaming_console", "Gaming", "Nintendo"),
    "58:BD:A3": ("gaming_console", "Gaming", "Nintendo"),
    "5C:52:1E": ("gaming_console", "Gaming", "Nintendo"),
    "78:A2:A0": ("gaming_console", "Gaming", "Nintendo"),
    "7C:BB:8A": ("gaming_console", "Gaming", "Nintendo"),
    "8C:56:C5": ("gaming_console", "Gaming", "Nintendo"),
    "8C:CD:E8": ("gaming_console", "Gaming", "Nintendo"),
    "98:41:5C": ("gaming_console", "Gaming", "Nintendo"),
    "98:B6:E9": ("gaming_console", "Gaming", "Nintendo"),
    "9C:E6:35": ("gaming_console", "Gaming", "Nintendo"),
    "A4:38:CC": ("gaming_console", "Gaming", "Nintendo"),
    "A4:5C:27": ("gaming_console", "Gaming", "Nintendo"),
    "A4:C0:E1": ("gaming_console", "Gaming", "Nintendo"),
    "B8:AE:6E": ("gaming_console", "Gaming", "Nintendo"),
    "CC:9E:00": ("gaming_console", "Gaming", "Nintendo"),
    "D8:6B:F7": ("gaming_console", "Gaming", "Nintendo"),
    "DC:68:EB": ("gaming_console", "Gaming", "Nintendo"),
    "E0:0C:7F": ("gaming_console", "Gaming", "Nintendo"),
    "E0:E7:51": ("gaming_console", "Gaming", "Nintendo"),
    "E8:4E:CE": ("gaming_console", "Gaming", "Nintendo"),
    "E8:6B:F7": ("gaming_console", "Gaming", "Nintendo"),
}

NINTENDO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Nintendo Switch
    (r"Nintendo\s*Switch\s*OLED", "Nintendo Switch OLED", "gaming_console", "Switch OS"),
    (r"Nintendo\s*Switch\s*Lite", "Nintendo Switch Lite", "handheld_console", "Switch OS"),
    (r"Nintendo\s*Switch", "Nintendo Switch", "gaming_console", "Switch OS"),
    (r"HAC-001", "Nintendo Switch", "gaming_console", "Switch OS"),
    (r"HDH-001", "Nintendo Switch Lite", "handheld_console", "Switch OS"),
    (r"HEG-001", "Nintendo Switch OLED", "gaming_console", "Switch OS"),

    # Wii U
    (r"Wii\s*U\s*GamePad", "Wii U GamePad", "gaming_controller", "Wii U System"),
    (r"Wii\s*U", "Wii U", "gaming_console", "Wii U System"),
    (r"WUP-\d{3}", "Wii U", "gaming_console", "Wii U System"),

    # Wii
    (r"Wii(?!\s*U)", "Wii", "gaming_console", "Wii System"),
    (r"RVL-\d{3}", "Wii", "gaming_console", "Wii System"),

    # 3DS family
    (r"New\s*Nintendo\s*3DS\s*XL", "New Nintendo 3DS XL", "handheld_console", "3DS System"),
    (r"New\s*Nintendo\s*3DS", "New Nintendo 3DS", "handheld_console", "3DS System"),
    (r"Nintendo\s*3DS\s*XL", "Nintendo 3DS XL", "handheld_console", "3DS System"),
    (r"Nintendo\s*3DS", "Nintendo 3DS", "handheld_console", "3DS System"),
    (r"Nintendo\s*2DS\s*XL", "Nintendo 2DS XL", "handheld_console", "3DS System"),
    (r"Nintendo\s*2DS", "Nintendo 2DS", "handheld_console", "3DS System"),
    (r"CTR-\d{3}", "Nintendo 3DS", "handheld_console", "3DS System"),
    (r"KTR-\d{3}", "New Nintendo 3DS", "handheld_console", "3DS System"),

    # DS family
    (r"Nintendo\s*DSi\s*XL", "Nintendo DSi XL", "handheld_console", "DSi System"),
    (r"Nintendo\s*DSi", "Nintendo DSi", "handheld_console", "DSi System"),
    (r"Nintendo\s*DS\s*Lite", "Nintendo DS Lite", "handheld_console", "DS System"),
    (r"Nintendo\s*DS", "Nintendo DS", "handheld_console", "DS System"),

    # Generic
    (r"Nintendo", "Nintendo Device", "gaming_console", None),
]

# Valve/Steam
VALVE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

VALVE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Steam Deck
    (r"Steam\s*Deck\s*OLED", "Steam Deck OLED", "handheld_console", "SteamOS"),
    (r"Steam\s*Deck", "Steam Deck", "handheld_console", "SteamOS"),
    (r"Jupiter", "Steam Deck", "handheld_console", "SteamOS"),

    # Steam Link
    (r"Steam\s*Link", "Steam Link", "streaming_device", "Steam Link OS"),

    # Steam Controller
    (r"Steam\s*Controller", "Steam Controller", "gaming_controller", None),

    # Steam Machine
    (r"Steam\s*Machine", "Steam Machine", "gaming_pc", "SteamOS"),

    # Valve Index
    (r"Valve\s*Index", "Valve Index", "vr_headset", "SteamVR"),
    (r"Index\s*VR", "Valve Index", "vr_headset", "SteamVR"),

    # SteamOS detection
    (r"SteamOS", "SteamOS Device", "gaming_device", "SteamOS"),
]


# POINT OF SALE (POS) PATTERNS

# Verifone
VERIFONE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

VERIFONE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Carbon series
    (r"Verifone\s*Carbon\s*10", "Verifone Carbon 10", "pos_terminal", "Verifone OS"),
    (r"Verifone\s*Carbon\s*8", "Verifone Carbon 8", "pos_terminal", "Verifone OS"),
    (r"Carbon\s*Mobile\s*5", "Verifone Carbon Mobile 5", "pos_terminal", "Verifone OS"),

    # Engage series
    (r"Verifone\s*Engage\s*V400c", "Verifone Engage V400c", "pos_terminal", "Verifone OS"),
    (r"Verifone\s*Engage\s*V400m", "Verifone Engage V400m", "pos_terminal", "Verifone OS"),
    (r"Verifone\s*Engage\s*P400", "Verifone Engage P400", "pos_terminal", "Verifone OS"),
    (r"Engage\s*V\d{3}", "Verifone Engage", "pos_terminal", "Verifone OS"),

    # VX series
    (r"VX\s*820", "Verifone VX 820", "pos_terminal", "Verifone OS"),
    (r"VX\s*805", "Verifone VX 805", "pos_terminal", "Verifone OS"),
    (r"VX\s*680", "Verifone VX 680", "pos_terminal", "Verifone OS"),
    (r"VX\s*520", "Verifone VX 520", "pos_terminal", "Verifone OS"),
    (r"VX\s*\d{3}", "Verifone VX Terminal", "pos_terminal", "Verifone OS"),

    # e-series
    (r"e355", "Verifone e355", "pos_terminal", "Verifone OS"),
    (r"e285", "Verifone e285", "pos_terminal", "Verifone OS"),

    # Generic
    (r"Verifone", "Verifone Terminal", "pos_terminal", "Verifone OS"),
]

# Ingenico
INGENICO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 28:3F:69 - IEEE assigns to Unknown, not INGENICO
    # REMOVED: 48:D6:D5 - IEEE assigns to Unknown, not INGENICO
    "64:C9:4A": ("pos_terminal", "Point of Sale", "Ingenico"),
}

INGENICO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Axium series
    (r"Axium\s*DX8000", "Ingenico Axium DX8000", "pos_terminal", "Axium OS"),
    (r"Axium\s*D7", "Ingenico Axium D7", "pos_terminal", "Axium OS"),
    (r"Axium", "Ingenico Axium", "pos_terminal", "Axium OS"),

    # Move series
    (r"Move\s*5000", "Ingenico Move 5000", "pos_terminal", "Tetra OS"),
    (r"Move\s*3500", "Ingenico Move 3500", "pos_terminal", "Tetra OS"),
    (r"Move\s*2500", "Ingenico Move 2500", "pos_terminal", "Tetra OS"),
    (r"Move\s*\d{4}", "Ingenico Move", "pos_terminal", "Tetra OS"),

    # Desk series
    (r"Desk\s*5000", "Ingenico Desk 5000", "pos_terminal", "Tetra OS"),
    (r"Desk\s*3500", "Ingenico Desk 3500", "pos_terminal", "Tetra OS"),
    (r"Desk\s*3200", "Ingenico Desk 3200", "pos_terminal", "Tetra OS"),
    (r"Desk\s*\d{4}", "Ingenico Desk", "pos_terminal", "Tetra OS"),

    # Lane series
    (r"Lane\s*8000", "Ingenico Lane 8000", "pos_terminal", "Tetra OS"),
    (r"Lane\s*7000", "Ingenico Lane 7000", "pos_terminal", "Tetra OS"),
    (r"Lane\s*5000", "Ingenico Lane 5000", "pos_terminal", "Tetra OS"),
    (r"Lane\s*3000", "Ingenico Lane 3000", "pos_terminal", "Tetra OS"),
    (r"Lane\s*\d{4}", "Ingenico Lane", "pos_terminal", "Tetra OS"),

    # iWL/iCT/iPP legacy
    (r"iWL\s*\d{3}", "Ingenico iWL", "pos_terminal", "Telium OS"),
    (r"iCT\s*\d{3}", "Ingenico iCT", "pos_terminal", "Telium OS"),
    (r"iPP\s*\d{3}", "Ingenico iPP", "pos_terminal", "Telium OS"),

    # Generic
    (r"Ingenico", "Ingenico Terminal", "pos_terminal", None),
]

# Square
SQUARE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "CC:5F:E1": ("pos_terminal", "Point of Sale", "Square"),
}

SQUARE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Square Terminal
    (r"Square\s*Terminal", "Square Terminal", "pos_terminal", "Square OS"),
    (r"Square\s*Stand", "Square Stand", "pos_terminal", "Square OS"),
    (r"Square\s*Register", "Square Register", "pos_terminal", "Square OS"),

    # Square Reader
    (r"Square\s*Reader", "Square Reader", "card_reader", "Square OS"),
    (r"Square\s*Contactless", "Square Contactless Reader", "card_reader", "Square OS"),
    (r"Chip\s*Reader", "Square Chip Reader", "card_reader", "Square OS"),

    # Square Kitchen Display
    (r"Square\s*KDS", "Square Kitchen Display", "kitchen_display", "Square OS"),

    # Generic
    (r"Square(?!\s*(Root|Enix))", "Square Device", "pos_terminal", "Square OS"),
]

# NCR (also ATM/Kiosk)
NCR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 54:4B:8C - IEEE assigns to Unknown, not NCR
}

NCR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ATMs
    (r"NCR\s*SelfServ\s*\d+", "NCR SelfServ ATM", "atm", "NCR ATM OS"),
    (r"NCR\s*ATM", "NCR ATM", "atm", "NCR ATM OS"),

    # POS Systems
    (r"NCR\s*Aloha", "NCR Aloha", "pos_terminal", "NCR Aloha"),
    (r"NCR\s*Silver", "NCR Silver", "pos_terminal", "NCR Silver"),
    (r"NCR\s*Counterpoint", "NCR Counterpoint", "pos_terminal", "NCR Counterpoint"),

    # Self-Checkout
    (r"NCR\s*FastLane", "NCR FastLane", "self_checkout", "NCR OS"),
    (r"NCR\s*Self\s*Checkout", "NCR Self-Checkout", "self_checkout", "NCR OS"),
    (r"Self\s*Serv\s*Checkout", "NCR SelfServ Checkout", "self_checkout", "NCR OS"),

    # Kiosks
    (r"NCR\s*Kiosk", "NCR Kiosk", "kiosk", "NCR OS"),
    (r"NCR\s*Interactive", "NCR Interactive Kiosk", "kiosk", "NCR OS"),

    # Terminals
    (r"NCR\s*RealPOS", "NCR RealPOS", "pos_terminal", "NCR OS"),
    (r"NCR\s*XR\d+", "NCR XR Terminal", "pos_terminal", "NCR OS"),

    # Generic
    (r"NCR\s*Corporation", "NCR Device", "pos_terminal", None),
    (r"NCR(?!/32)", "NCR Device", "pos_terminal", None),
]

# Clover
CLOVER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1E:4F - IEEE assigns to Unknown, not CLOVER
    # REMOVED: 44:07:0B - IEEE assigns to Unknown, not CLOVER
}

CLOVER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Clover Stations
    (r"Clover\s*Station\s*Duo", "Clover Station Duo", "pos_terminal", "Clover OS"),
    (r"Clover\s*Station\s*Solo", "Clover Station Solo", "pos_terminal", "Clover OS"),
    (r"Clover\s*Station\s*Pro", "Clover Station Pro", "pos_terminal", "Clover OS"),
    (r"Clover\s*Station", "Clover Station", "pos_terminal", "Clover OS"),

    # Clover Terminals
    (r"Clover\s*Flex", "Clover Flex", "pos_terminal", "Clover OS"),
    (r"Clover\s*Mini", "Clover Mini", "pos_terminal", "Clover OS"),

    # Clover Go
    (r"Clover\s*Go", "Clover Go", "card_reader", "Clover OS"),

    # Clover Kitchen Display
    (r"Clover\s*Kitchen\s*Display", "Clover Kitchen Display", "kitchen_display", "Clover OS"),
    (r"Clover\s*KDS", "Clover KDS", "kitchen_display", "Clover OS"),

    # Generic
    (r"Clover(?!\s*Field)", "Clover Device", "pos_terminal", "Clover OS"),
]

# PAX Technology
PAX_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 84:CC:A8 - IEEE assigns to Unknown, not PAX
}

PAX_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # A-series (Android)
    (r"PAX\s*A920\s*Pro", "PAX A920 Pro", "pos_terminal", "PayDroid"),
    (r"PAX\s*A920", "PAX A920", "pos_terminal", "PayDroid"),
    (r"PAX\s*A910", "PAX A910", "pos_terminal", "PayDroid"),
    (r"PAX\s*A80", "PAX A80", "pos_terminal", "PayDroid"),
    (r"PAX\s*A77", "PAX A77", "pos_terminal", "PayDroid"),
    (r"PAX\s*A60", "PAX A60", "pos_terminal", "PayDroid"),
    (r"PAX\s*A35", "PAX A35", "pos_terminal", "PayDroid"),
    (r"PAX\s*IM30", "PAX IM30", "pos_terminal", "PayDroid"),
    (r"PAX\s*IM20", "PAX IM20", "pos_terminal", "PayDroid"),

    # E-series
    (r"PAX\s*E800", "PAX E800", "pos_terminal", "Prolin OS"),
    (r"PAX\s*E700", "PAX E700", "pos_terminal", "Prolin OS"),
    (r"PAX\s*E600", "PAX E600", "pos_terminal", "Prolin OS"),
    (r"PAX\s*E500", "PAX E500", "pos_terminal", "Prolin OS"),

    # S-series
    (r"PAX\s*S920", "PAX S920", "pos_terminal", "Prolin OS"),
    (r"PAX\s*S900", "PAX S900", "pos_terminal", "Prolin OS"),
    (r"PAX\s*S800", "PAX S800", "pos_terminal", "Prolin OS"),
    (r"PAX\s*S300", "PAX S300", "pos_terminal", "Prolin OS"),

    # Q-series
    (r"PAX\s*Q92", "PAX Q92", "pos_terminal", "PayDroid"),
    (r"PAX\s*Q80", "PAX Q80", "pos_terminal", "PayDroid"),
    (r"PAX\s*Q30", "PAX Q30", "pos_terminal", "PayDroid"),

    # Generic
    (r"PAX\s*Technology", "PAX Terminal", "pos_terminal", None),
    (r"PAX(?!\s*(vax|wax))", "PAX Terminal", "pos_terminal", None),
]


# MEDICAL/HEALTHCARE PATTERNS

# GE Healthcare
GE_HEALTHCARE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0C:29 - IEEE assigns to Unknown, not GE_HEALTHCARE
    # REMOVED: 00:A0:45 - IEEE assigns to Unknown, not GE_HEALTHCARE
    "14:C9:15": ("medical_device", "Healthcare", "GE Healthcare"),
    "3C:8B:59": ("medical_device", "Healthcare", "GE Healthcare"),
    "54:52:FE": ("medical_device", "Healthcare", "GE Healthcare"),
}

GE_HEALTHCARE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Patient Monitors
    (r"CARESCAPE\s*B850", "GE CARESCAPE B850", "patient_monitor", "GE Healthcare OS"),
    (r"CARESCAPE\s*B650", "GE CARESCAPE B650", "patient_monitor", "GE Healthcare OS"),
    (r"CARESCAPE\s*B450", "GE CARESCAPE B450", "patient_monitor", "GE Healthcare OS"),
    (r"CARESCAPE", "GE CARESCAPE Monitor", "patient_monitor", "GE Healthcare OS"),
    (r"Dash\s*[3-5]000", "GE Dash Monitor", "patient_monitor", "GE Healthcare OS"),
    (r"Solar\s*\d+", "GE Solar Monitor", "patient_monitor", "GE Healthcare OS"),

    # Ultrasound
    (r"LOGIQ\s*E\d+", "GE LOGIQ Ultrasound", "ultrasound", "GE Healthcare OS"),
    (r"Voluson\s*E\d+", "GE Voluson Ultrasound", "ultrasound", "GE Healthcare OS"),
    (r"Venue\s*(Go|Fit|R\d+)", "GE Venue Ultrasound", "ultrasound", "GE Healthcare OS"),
    (r"Vivid\s*(E\d+|S\d+|T\d+|iq)", "GE Vivid Ultrasound", "ultrasound", "GE Healthcare OS"),

    # CT/MRI
    (r"Revolution\s*CT", "GE Revolution CT", "ct_scanner", "GE Healthcare OS"),
    (r"LightSpeed", "GE LightSpeed CT", "ct_scanner", "GE Healthcare OS"),
    (r"Optima\s*CT", "GE Optima CT", "ct_scanner", "GE Healthcare OS"),
    (r"Discovery\s*MR", "GE Discovery MR", "mri_scanner", "GE Healthcare OS"),
    (r"SIGNA", "GE SIGNA MRI", "mri_scanner", "GE Healthcare OS"),

    # X-ray
    (r"Revolution\s*XR", "GE Revolution XR", "xray", "GE Healthcare OS"),
    (r"Optima\s*XR", "GE Optima XR", "xray", "GE Healthcare OS"),
    (r"AMX", "GE AMX Portable X-ray", "xray", "GE Healthcare OS"),

    # Anesthesia/Ventilator
    (r"Aisys\s*CS2", "GE Aisys CS2", "anesthesia_machine", "GE Healthcare OS"),
    (r"Avance\s*CS2", "GE Avance CS2", "anesthesia_machine", "GE Healthcare OS"),
    (r"CARESTATION", "GE CARESTATION", "anesthesia_machine", "GE Healthcare OS"),
    (r"Engstrom", "GE Engstrom Ventilator", "ventilator", "GE Healthcare OS"),

    # Generic
    (r"GE\s*Healthcare", "GE Healthcare Device", "medical_device", "GE Healthcare OS"),
]

# Philips Healthcare (Medical, not Hue)
PHILIPS_HEALTHCARE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0F:B5 - IEEE assigns to Unknown, not PHILIPS_HEALTHCARE
    # REMOVED: 00:17:A4 - IEEE assigns to Unknown, not PHILIPS_HEALTHCARE
    # REMOVED: 00:1A:11 - IEEE assigns to Unknown, not PHILIPS_HEALTHCARE
    # REMOVED: 00:1C:C4 - IEEE assigns to Unknown, not PHILIPS_HEALTHCARE
    # REMOVED: 00:1D:AA - IEEE assigns to Unknown, not PHILIPS_HEALTHCARE
    # REMOVED: 00:26:AB - IEEE assigns to Unknown, not PHILIPS_HEALTHCARE
    "78:20:94": ("medical_device", "Healthcare", "Philips Healthcare"),
    "D0:22:AB": ("medical_device", "Healthcare", "Philips Healthcare"),
}

PHILIPS_HEALTHCARE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Patient Monitoring
    (r"IntelliVue\s*MX\d+", "Philips IntelliVue Monitor", "patient_monitor", "Philips Healthcare OS"),
    (r"IntelliVue\s*MP\d+", "Philips IntelliVue Monitor", "patient_monitor", "Philips Healthcare OS"),
    (r"IntelliVue\s*X\d+", "Philips IntelliVue Monitor", "patient_monitor", "Philips Healthcare OS"),
    (r"IntelliVue", "Philips IntelliVue", "patient_monitor", "Philips Healthcare OS"),
    (r"SureSigns", "Philips SureSigns Monitor", "patient_monitor", "Philips Healthcare OS"),

    # Ultrasound
    (r"EPIQ\s*\d+", "Philips EPIQ Ultrasound", "ultrasound", "Philips Healthcare OS"),
    (r"Affiniti\s*\d+", "Philips Affiniti Ultrasound", "ultrasound", "Philips Healthcare OS"),
    (r"ClearVue", "Philips ClearVue Ultrasound", "ultrasound", "Philips Healthcare OS"),
    (r"Lumify", "Philips Lumify Ultrasound", "ultrasound", "Philips Healthcare OS"),

    # CT/MRI
    (r"Ingenia\s*(Ambition|Elition)?", "Philips Ingenia MRI", "mri_scanner", "Philips Healthcare OS"),
    (r"Achieva", "Philips Achieva MRI", "mri_scanner", "Philips Healthcare OS"),
    (r"Ingenuity\s*CT", "Philips Ingenuity CT", "ct_scanner", "Philips Healthcare OS"),
    (r"IQon\s*CT", "Philips IQon Spectral CT", "ct_scanner", "Philips Healthcare OS"),
    (r"Incisive\s*CT", "Philips Incisive CT", "ct_scanner", "Philips Healthcare OS"),

    # X-ray
    (r"DigitalDiagnost", "Philips DigitalDiagnost", "xray", "Philips Healthcare OS"),
    (r"MobileDiagnost", "Philips MobileDiagnost", "xray", "Philips Healthcare OS"),
    (r"Azurion", "Philips Azurion", "interventional_xray", "Philips Healthcare OS"),

    # Defibrillator/AED
    (r"HeartStart\s*MRx", "Philips HeartStart MRx", "defibrillator", "Philips Healthcare OS"),
    (r"HeartStart\s*FRx", "Philips HeartStart FRx", "aed", "Philips Healthcare OS"),
    (r"HeartStart\s*FR3", "Philips HeartStart FR3", "aed", "Philips Healthcare OS"),
    (r"HeartStart", "Philips HeartStart", "defibrillator", "Philips Healthcare OS"),

    # Ventilator
    (r"Trilogy\s*(Evo|EV\d+|\d+)", "Philips Trilogy Ventilator", "ventilator", "Philips Healthcare OS"),
    (r"V680?\s*Ventilator", "Philips V Ventilator", "ventilator", "Philips Healthcare OS"),

    # Generic
    (r"Philips\s*Healthcare", "Philips Healthcare Device", "medical_device", "Philips Healthcare OS"),
    (r"Philips\s*Medical", "Philips Medical Device", "medical_device", "Philips Healthcare OS"),
]

# Medtronic
MEDTRONIC_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:17:EB - IEEE assigns to Unknown, not MEDTRONIC
    # REMOVED: 00:24:B2 - IEEE assigns to Unknown, not MEDTRONIC
    # REMOVED: 28:28:5D - IEEE assigns to Unknown, not MEDTRONIC
    "44:50:C3": ("medical_device", "Healthcare", "Medtronic"),
    "9C:B0:0D": ("medical_device", "Healthcare", "Medtronic"),
    # REMOVED: AC:22:0B - IEEE assigns to Unknown, not MEDTRONIC
    # REMOVED: D0:13:FD - IEEE assigns to Unknown, not MEDTRONIC
}

MEDTRONIC_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Surgical Navigation
    (r"StealthStation\s*S\d+", "Medtronic StealthStation", "surgical_navigation", "Medtronic OS"),
    (r"StealthStation", "Medtronic StealthStation", "surgical_navigation", "Medtronic OS"),
    (r"O-arm", "Medtronic O-arm", "surgical_imaging", "Medtronic OS"),

    # Ventilators
    (r"Puritan\s*Bennett\s*\d+", "Medtronic Puritan Bennett", "ventilator", "Medtronic OS"),
    (r"PB\s*980", "Medtronic PB 980 Ventilator", "ventilator", "Medtronic OS"),
    (r"PB\s*840", "Medtronic PB 840 Ventilator", "ventilator", "Medtronic OS"),

    # Diabetes
    (r"MiniMed\s*\d+G", "Medtronic MiniMed Pump", "insulin_pump", "Medtronic OS"),
    (r"Guardian\s*Connect", "Medtronic Guardian Connect CGM", "cgm", "Medtronic OS"),
    (r"Enlite", "Medtronic Enlite Sensor", "cgm", "Medtronic OS"),
    (r"InPen", "Medtronic InPen", "smart_insulin_pen", "Medtronic OS"),

    # Cardiac
    (r"CareLink", "Medtronic CareLink", "cardiac_monitor", "Medtronic OS"),
    (r"Reveal\s*LINQ", "Medtronic Reveal LINQ", "cardiac_monitor", "Medtronic OS"),

    # Spine/Neuro
    (r"Mazor\s*X", "Medtronic Mazor X", "surgical_robot", "Medtronic OS"),
    (r"Hugo", "Medtronic Hugo Surgical Robot", "surgical_robot", "Medtronic OS"),

    # Generic
    (r"Medtronic", "Medtronic Device", "medical_device", "Medtronic OS"),
]

# Draeger (Anesthesia/Patient Monitoring)
DRAEGER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:09:0F - IEEE assigns to Unknown, not DRAEGER
    # REMOVED: 00:19:99 - IEEE assigns to Unknown, not DRAEGER
    # REMOVED: 00:1D:60 - IEEE assigns to Unknown, not DRAEGER
}

DRAEGER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Anesthesia Machines
    (r"Perseus\s*A500", "Draeger Perseus A500", "anesthesia_machine", "Draeger OS"),
    (r"Primus", "Draeger Primus", "anesthesia_machine", "Draeger OS"),
    (r"Fabius\s*(GS|Plus|Tiro)", "Draeger Fabius", "anesthesia_machine", "Draeger OS"),
    (r"Apollo", "Draeger Apollo", "anesthesia_machine", "Draeger OS"),

    # Ventilators
    (r"Evita\s*(Infinity|V\d+|\d+)", "Draeger Evita Ventilator", "ventilator", "Draeger OS"),
    (r"Savina\s*\d+", "Draeger Savina Ventilator", "ventilator", "Draeger OS"),
    (r"Babylog\s*(VN\d+|\d+)", "Draeger Babylog Ventilator", "ventilator", "Draeger OS"),

    # Patient Monitoring
    (r"Infinity\s*Delta", "Draeger Infinity Delta", "patient_monitor", "Draeger OS"),
    (r"Infinity\s*Vista", "Draeger Infinity Vista", "patient_monitor", "Draeger OS"),
    (r"Infinity\s*Gamma", "Draeger Infinity Gamma", "patient_monitor", "Draeger OS"),
    (r"Infinity\s*Kappa", "Draeger Infinity Kappa", "patient_monitor", "Draeger OS"),
    (r"Infinity\s*Omega", "Draeger Infinity Omega", "patient_monitor", "Draeger OS"),
    (r"Vista\s*120", "Draeger Vista 120", "patient_monitor", "Draeger OS"),

    # Incubators
    (r"Isolette", "Draeger Isolette Incubator", "incubator", "Draeger OS"),
    (r"Caleo", "Draeger Caleo Incubator", "incubator", "Draeger OS"),
    (r"Giraffe", "Draeger Giraffe Warmer", "infant_warmer", "Draeger OS"),

    # Generic
    (r"Dr.ger|Draeger|Dräger", "Draeger Device", "medical_device", "Draeger OS"),
]

# Baxter (Infusion/Dialysis)
BAXTER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "60:53:D4": ("medical_device", "Healthcare", "Baxter"),
}

BAXTER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Infusion Pumps
    (r"Sigma\s*Spectrum", "Baxter Sigma Spectrum", "infusion_pump", "Baxter OS"),
    (r"Colleague", "Baxter Colleague Pump", "infusion_pump", "Baxter OS"),
    (r"Flo-Gard", "Baxter Flo-Gard", "infusion_pump", "Baxter OS"),

    # Dialysis
    (r"PrisMax", "Baxter PrisMax", "dialysis_machine", "Baxter OS"),
    (r"Prismaflex", "Baxter Prismaflex", "dialysis_machine", "Baxter OS"),
    (r"HomeChoice", "Baxter HomeChoice", "dialysis_machine", "Baxter OS"),
    (r"Amia", "Baxter Amia", "dialysis_machine", "Baxter OS"),

    # Generic
    (r"Baxter\s*Healthcare", "Baxter Device", "medical_device", "Baxter OS"),
    (r"Baxter(?!\s*International)", "Baxter Device", "medical_device", "Baxter OS"),
]


# BUILDING AUTOMATION/HVAC PATTERNS

# Johnson Controls
JOHNSON_CONTROLS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0A:E4 - IEEE assigns to Unknown, not JOHNSON_CONTROLS
    "00:40:AE": ("building_controller", "Building Automation", "Johnson Controls"),
    "24:CE:B7": ("building_controller", "Building Automation", "Johnson Controls"),
}

JOHNSON_CONTROLS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Metasys
    (r"Metasys\s*(NAE|NIE|NCE)\d+", "JCI Metasys Controller", "building_controller", "Metasys OS"),
    (r"Metasys\s*ADS", "JCI Metasys ADS", "building_controller", "Metasys OS"),
    (r"Metasys", "JCI Metasys", "building_controller", "Metasys OS"),

    # Facility Explorer
    (r"Facility\s*Explorer", "JCI Facility Explorer", "building_controller", "FX OS"),
    (r"FX\s*(Supervisory|PC)", "JCI Facility Explorer", "building_controller", "FX OS"),

    # OpenBlue
    (r"OpenBlue", "JCI OpenBlue", "building_controller", "OpenBlue"),

    # YORK Chillers
    (r"YORK\s*YK", "YORK Centrifugal Chiller", "chiller", "Johnson Controls"),
    (r"YORK\s*YZ", "YORK Screw Chiller", "chiller", "Johnson Controls"),
    (r"YORK\s*YMC2", "YORK Magnetic Chiller", "chiller", "Johnson Controls"),
    (r"YORK", "YORK HVAC", "hvac", "Johnson Controls"),

    # Simplex Fire (JCI owns)
    (r"Simplex\s*4100", "Simplex 4100 Fire Panel", "fire_panel", "Johnson Controls"),
    (r"Simplex\s*4020", "Simplex 4020 Fire Panel", "fire_panel", "Johnson Controls"),
    (r"Simplex", "Simplex Fire System", "fire_panel", "Johnson Controls"),

    # Tyco (JCI owns)
    (r"Tyco\s*Kantech", "Tyco Kantech Access", "access_controller", "Johnson Controls"),
    (r"Tyco\s*Security", "Tyco Security", "security_panel", "Johnson Controls"),

    # Generic
    (r"Johnson\s*Controls", "Johnson Controls Device", "building_controller", None),
    (r"JCI\s*Building", "JCI Building Controller", "building_controller", None),
]

# Trane Technologies (HVAC)
TRANE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:0E:8F - IEEE assigns to Unknown, not TRANE
}

TRANE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Tracer Controllers
    (r"Tracer\s*SC\+?", "Trane Tracer SC+", "building_controller", "Tracer OS"),
    (r"Tracer\s*ES", "Trane Tracer ES", "building_controller", "Tracer OS"),
    (r"Tracer\s*TU", "Trane Tracer TU", "unit_controller", "Tracer OS"),
    (r"Tracer", "Trane Tracer", "building_controller", "Tracer OS"),

    # Symbio
    (r"Symbio\s*\d+", "Trane Symbio Controller", "unit_controller", "Symbio"),

    # Chillers
    (r"CenTraVac", "Trane CenTraVac Chiller", "chiller", "Trane"),
    (r"RTAC", "Trane RTAC Chiller", "chiller", "Trane"),
    (r"RTAE", "Trane RTAE Chiller", "chiller", "Trane"),
    (r"CGAM", "Trane CGAM Chiller", "chiller", "Trane"),

    # Air Handlers
    (r"IntelliPak", "Trane IntelliPak Rooftop", "rooftop_unit", "Trane"),
    (r"Voyager", "Trane Voyager Rooftop", "rooftop_unit", "Trane"),

    # Residential (Nexia)
    (r"Nexia\s*Bridge", "Trane Nexia Bridge", "smart_thermostat", "Nexia"),
    (r"XL\d+i", "Trane XL Thermostat", "smart_thermostat", "Trane"),
    (r"ComfortLink", "Trane ComfortLink", "smart_thermostat", "Trane"),

    # Generic
    (r"Trane\s*Technologies", "Trane Device", "hvac_controller", None),
    (r"Trane(?!\s*Technologies)", "Trane HVAC", "hvac", None),
]

# Carrier Global (HVAC)
CARRIER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:18:AE - IEEE assigns to Unknown, not CARRIER
    # REMOVED: 18:64:72 - IEEE assigns to Unknown, not CARRIER
    # REMOVED: 44:61:32 - IEEE assigns to Unknown, not CARRIER
    # REMOVED: 98:F4:AB - IEEE assigns to Unknown, not CARRIER
}

CARRIER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # i-Vu Building Automation
    (r"i-Vu\s*(Pro|Plus|Open)?", "Carrier i-Vu", "building_controller", "i-Vu"),
    (r"i-Vu\s*CCN", "Carrier i-Vu CCN", "building_controller", "i-Vu"),

    # Comfort Network
    (r"CCN\s*Router", "Carrier CCN Router", "building_controller", "CCN"),
    (r"Comfort\s*Network", "Carrier Comfort Network", "building_controller", "CCN"),

    # Chillers
    (r"AquaEdge\s*\d+", "Carrier AquaEdge Chiller", "chiller", "Carrier"),
    (r"AquaForce\s*\d+", "Carrier AquaForce Chiller", "chiller", "Carrier"),
    (r"30XA", "Carrier 30XA Chiller", "chiller", "Carrier"),
    (r"30HX", "Carrier 30HX Chiller", "chiller", "Carrier"),

    # Air Handlers
    (r"WeatherMaker", "Carrier WeatherMaker", "rooftop_unit", "Carrier"),
    (r"WeatherExpert", "Carrier WeatherExpert", "rooftop_unit", "Carrier"),
    (r"48HC", "Carrier 48 Series Rooftop", "rooftop_unit", "Carrier"),

    # Residential (Côr)
    (r"Côr\s*Thermostat", "Carrier Côr Thermostat", "smart_thermostat", "Carrier"),
    (r"Infinity\s*System", "Carrier Infinity", "smart_thermostat", "Carrier"),

    # Generic
    (r"Carrier\s*Global", "Carrier Device", "hvac_controller", None),
    (r"Carrier\s*HVAC", "Carrier HVAC", "hvac", None),
]

# Honeywell Building Solutions
HONEYWELL_BUILDING_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:17:CB - IEEE assigns to Unknown, not HONEYWELL_BUILDING
    # REMOVED: 00:1B:B1 - IEEE assigns to Unknown, not HONEYWELL_BUILDING
    "40:C4:36": ("building_controller", "Building Automation", "Honeywell Building"),
    # REMOVED: 60:A4:4C - IEEE assigns to Unknown, not HONEYWELL_BUILDING
}

HONEYWELL_BUILDING_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # WEBs-AX (Niagara)
    (r"WEBs-AX", "Honeywell WEBs-AX", "building_controller", "Niagara AX"),
    (r"WEBs-N4", "Honeywell WEBs-N4", "building_controller", "Niagara 4"),
    (r"Niagara\s*4", "Niagara 4 Controller", "building_controller", "Niagara 4"),
    (r"JACE\s*\d+", "Niagara JACE", "building_controller", "Niagara"),

    # EBI (Enterprise Buildings Integrator)
    (r"EBI", "Honeywell EBI", "building_controller", "EBI"),
    (r"Enterprise\s*Buildings\s*Integrator", "Honeywell EBI", "building_controller", "EBI"),

    # Spyder
    (r"Spyder", "Honeywell Spyder", "unit_controller", "Spyder"),
    (r"PVL", "Honeywell PVL Controller", "unit_controller", "Sylk"),

    # Forge
    (r"Honeywell\s*Forge", "Honeywell Forge", "building_controller", "Forge"),

    # Generic
    (r"Honeywell\s*Building", "Honeywell Building Device", "building_controller", None),
]


# ENTERPRISE NETWORKING PATTERNS

# F5 Networks
F5_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:01:D7": ("load_balancer", "Network Equipment", "F5 Networks"),
    "00:23:E9": ("load_balancer", "Network Equipment", "F5 Networks"),
    "00:94:A1": ("load_balancer", "Network Equipment", "F5 Networks"),
    "54:4B:1E": ("load_balancer", "Network Equipment", "F5 Networks"),
    "84:12:4C": ("load_balancer", "Network Equipment", "F5 Networks"),
}

F5_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # BIG-IP
    (r"BIG-IP\s*i\d{4,5}", "F5 BIG-IP iSeries", "load_balancer", "TMOS"),
    (r"BIG-IP\s*VE", "F5 BIG-IP Virtual Edition", "load_balancer", "TMOS"),
    (r"BIG-IP\s*LTM", "F5 BIG-IP LTM", "load_balancer", "TMOS"),
    (r"BIG-IP\s*GTM", "F5 BIG-IP GTM", "dns_load_balancer", "TMOS"),
    (r"BIG-IP\s*ASM", "F5 BIG-IP ASM", "waf", "TMOS"),
    (r"BIG-IP\s*APM", "F5 BIG-IP APM", "access_manager", "TMOS"),
    (r"BIG-IP\s*AFM", "F5 BIG-IP AFM", "firewall", "TMOS"),
    (r"BIG-IP", "F5 BIG-IP", "load_balancer", "TMOS"),

    # BIG-IQ
    (r"BIG-IQ", "F5 BIG-IQ", "management_platform", "BIG-IQ"),

    # NGINX Plus (F5 owns)
    (r"NGINX\s*Plus", "F5 NGINX Plus", "load_balancer", "NGINX Plus"),

    # Generic
    (r"F5\s*Networks", "F5 Networks Device", "load_balancer", None),
    (r"TMOS", "F5 TMOS Device", "load_balancer", "TMOS"),
]

# A10 Networks
A10_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:11:92 - IEEE assigns to Unknown, not A10
    "00:1F:A0": ("load_balancer", "Network Equipment", "A10 Networks"),
    # REMOVED: 78:24:AF - IEEE assigns to Unknown, not A10
    # REMOVED: B4:B0:17 - IEEE assigns to Unknown, not A10
}

A10_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Thunder Series
    (r"Thunder\s*\d{4,5}S?", "A10 Thunder ADC", "load_balancer", "ACOS"),
    (r"Thunder\s*CFW", "A10 Thunder CFW", "firewall", "ACOS"),
    (r"Thunder\s*CGN", "A10 Thunder CGN", "cgnat", "ACOS"),
    (r"Thunder\s*SSLi", "A10 Thunder SSLi", "ssl_inspection", "ACOS"),
    (r"Thunder\s*TPS", "A10 Thunder TPS", "ddos_protection", "ACOS"),

    # vThunder
    (r"vThunder", "A10 vThunder", "load_balancer", "ACOS"),

    # AX Series (legacy)
    (r"AX\s*\d{4}", "A10 AX Series", "load_balancer", "ACOS"),

    # Generic
    (r"A10\s*Networks", "A10 Networks Device", "load_balancer", "ACOS"),
    (r"ACOS", "A10 ACOS Device", "load_balancer", "ACOS"),
]

# Barracuda Networks
BARRACUDA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 18:66:DA - IEEE assigns to Unknown, not BARRACUDA
}

BARRACUDA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # CloudGen Firewall
    (r"CloudGen\s*Firewall", "Barracuda CloudGen Firewall", "firewall", "Barracuda OS"),
    (r"Barracuda\s*NG\s*Firewall", "Barracuda NG Firewall", "firewall", "Barracuda OS"),

    # Web Application Firewall
    (r"Barracuda\s*WAF", "Barracuda WAF", "waf", "Barracuda OS"),
    (r"Web\s*Application\s*Firewall", "Barracuda WAF", "waf", "Barracuda OS"),

    # Email Security
    (r"Barracuda\s*Email\s*Security", "Barracuda Email Security", "email_gateway", "Barracuda OS"),
    (r"Barracuda\s*Spam\s*Firewall", "Barracuda Spam Firewall", "email_gateway", "Barracuda OS"),

    # Load Balancer
    (r"Barracuda\s*Load\s*Balancer", "Barracuda Load Balancer", "load_balancer", "Barracuda OS"),
    (r"Barracuda\s*ADC", "Barracuda ADC", "load_balancer", "Barracuda OS"),

    # Backup
    (r"Barracuda\s*Backup", "Barracuda Backup", "backup_appliance", "Barracuda OS"),

    # SSL VPN
    (r"Barracuda\s*SSL\s*VPN", "Barracuda SSL VPN", "vpn_gateway", "Barracuda OS"),
    (r"Barracuda\s*CloudGen\s*Access", "Barracuda CloudGen Access", "vpn_gateway", "Barracuda OS"),

    # Generic
    (r"Barracuda\s*Networks", "Barracuda Device", "security_appliance", "Barracuda OS"),
    (r"Barracuda", "Barracuda Device", "security_appliance", "Barracuda OS"),
]

# Alcatel-Lucent Enterprise
ALE_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:80:9F": ("switch", "Network Equipment", "Alcatel-Lucent Enterprise"),
    # REMOVED: 28:6E:D4 - IEEE assigns to Unknown, not ALE
    # REMOVED: 3C:4A:92 - IEEE assigns to Unknown, not ALE
    # REMOVED: 44:D9:E7 - IEEE assigns to Unknown, not ALE
    "50:57:F7": ("switch", "Network Equipment", "Alcatel-Lucent Enterprise"),
    "70:87:A8": ("switch", "Network Equipment", "Alcatel-Lucent Enterprise"),
    "A0:D3:C1": ("switch", "Network Equipment", "Alcatel-Lucent Enterprise"),
    "CC:28:56": ("switch", "Network Equipment", "Alcatel-Lucent Enterprise"),
}

ALE_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # OmniSwitch
    (r"OmniSwitch\s*\d{4}", "Alcatel OmniSwitch", "switch", "AOS"),
    (r"OS\d{4}(-\w+)?", "Alcatel OmniSwitch", "switch", "AOS"),
    (r"OmniSwitch", "Alcatel OmniSwitch", "switch", "AOS"),

    # OmniAccess (WLAN)
    (r"OmniAccess\s*Stellar", "Alcatel OmniAccess Stellar", "access_point", "AOS-W"),
    (r"OmniAccess\s*\d+", "Alcatel OmniAccess", "wireless_controller", "AOS-W"),
    (r"OAW-\w+", "Alcatel OmniAccess AP", "access_point", "AOS-W"),

    # OXO/OXE (PBX)
    (r"OXO\s*Connect", "Alcatel OXO Connect", "pbx", "ALE Voice"),
    (r"OmniPCX\s*Enterprise", "Alcatel OmniPCX Enterprise", "pbx", "ALE Voice"),
    (r"OXE", "Alcatel OmniPCX Enterprise", "pbx", "ALE Voice"),

    # Rainbow (UCaaS)
    (r"Rainbow", "Alcatel Rainbow", "collaboration", "Rainbow"),

    # Generic
    (r"Alcatel-Lucent\s*Enterprise", "ALE Device", "network_device", "AOS"),
    (r"ALE\s*OmniSwitch", "ALE OmniSwitch", "switch", "AOS"),
]

# Riverbed
RIVERBED_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0E:B6": ("wan_optimizer", "Network Equipment", "Riverbed"),
    "00:25:50": ("wan_optimizer", "Network Equipment", "Riverbed"),
    # REMOVED: 2C:59:E5 - IEEE assigns to Unknown, not RIVERBED
    # REMOVED: 78:2B:CB - IEEE assigns to Unknown, not RIVERBED
    # REMOVED: 90:6C:AC - IEEE assigns to Unknown, not RIVERBED
}

RIVERBED_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # SteelHead
    (r"SteelHead\s*CX\s*\d+", "Riverbed SteelHead CX", "wan_optimizer", "RiOS"),
    (r"SteelHead\s*EX\s*\d+", "Riverbed SteelHead EX", "wan_optimizer", "RiOS"),
    (r"SteelHead\s*SD\s*\d+", "Riverbed SteelHead SD", "wan_optimizer", "RiOS"),
    (r"SteelHead", "Riverbed SteelHead", "wan_optimizer", "RiOS"),

    # SteelFusion
    (r"SteelFusion\s*(Core|Edge)", "Riverbed SteelFusion", "wan_optimizer", "RiOS"),

    # SteelCentral
    (r"SteelCentral\s*AppResponse", "Riverbed SteelCentral AppResponse", "apm", "SteelCentral"),
    (r"SteelCentral\s*NetProfiler", "Riverbed SteelCentral NetProfiler", "npm", "SteelCentral"),
    (r"SteelCentral\s*NetIM", "Riverbed SteelCentral NetIM", "npm", "SteelCentral"),
    (r"SteelCentral", "Riverbed SteelCentral", "monitoring", "SteelCentral"),

    # SteelConnect
    (r"SteelConnect\s*EX\s*\d+", "Riverbed SteelConnect EX", "sd_wan", "SteelConnect"),
    (r"SteelConnect", "Riverbed SteelConnect", "sd_wan", "SteelConnect"),

    # Client Accelerator
    (r"Client\s*Accelerator", "Riverbed Client Accelerator", "wan_optimizer", "RiOS"),

    # RiOS
    (r"RiOS\s*[\d\.]+", "Riverbed RiOS Device", "wan_optimizer", "RiOS"),

    # Generic
    (r"Riverbed\s*Technology", "Riverbed Device", "wan_optimizer", None),
    (r"Riverbed", "Riverbed Device", "wan_optimizer", None),
]


# ATM/KIOSK PATTERNS

# Diebold Nixdorf
DIEBOLD_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:08:83 - IEEE assigns to Unknown, not DIEBOLD
}

DIEBOLD_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ATMs
    (r"Diebold\s*Nixdorf\s*DN\s*Series", "Diebold Nixdorf DN ATM", "atm", "Diebold OS"),
    (r"DN\s*Series\s*\d+", "Diebold Nixdorf DN ATM", "atm", "Diebold OS"),
    (r"CS\s*\d{4}", "Diebold Nixdorf CS ATM", "atm", "Diebold OS"),
    (r"Opteva\s*\d+", "Diebold Opteva ATM", "atm", "Diebold OS"),
    (r"Diebold\s*ATM", "Diebold ATM", "atm", "Diebold OS"),

    # POS Systems
    (r"BEETLE\s*/(iSCAN|Fusion|S-II)", "Diebold Nixdorf BEETLE", "pos_terminal", "Diebold OS"),
    (r"BEETLE", "Diebold Nixdorf BEETLE POS", "pos_terminal", "Diebold OS"),

    # Self-Checkout
    (r"K-two", "Diebold Nixdorf K-two", "self_checkout", "Diebold OS"),
    (r"SCO\s*\w+", "Diebold Nixdorf Self-Checkout", "self_checkout", "Diebold OS"),

    # Kiosks
    (r"Nixdorf\s*Kiosk", "Diebold Nixdorf Kiosk", "kiosk", "Diebold OS"),
    (r"Interactive\s*Teller", "Diebold Interactive Teller", "atm", "Diebold OS"),

    # Cash Recyclers
    (r"ProCash\s*\d+", "Diebold ProCash Recycler", "cash_recycler", "Diebold OS"),
    (r"Cash\s*Recycler", "Diebold Cash Recycler", "cash_recycler", "Diebold OS"),

    # Generic
    (r"Diebold\s*Nixdorf", "Diebold Nixdorf Device", "atm", "Diebold OS"),
    (r"Nixdorf", "Nixdorf Device", "atm", "Diebold OS"),
    (r"Diebold(?!\s*Nixdorf)", "Diebold Device", "atm", "Diebold OS"),
]

# Wincor (now part of Diebold Nixdorf)
WINCOR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:21:4F - IEEE assigns to Unknown, not WINCOR
    # REMOVED: 28:C0:DA - IEEE assigns to Unknown, not WINCOR
    # REMOVED: 48:0F:CF - IEEE assigns to Unknown, not WINCOR
    # REMOVED: 64:D1:54 - IEEE assigns to Unknown, not WINCOR
}

WINCOR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # ATMs
    (r"ProCash\s*\d+", "Wincor ProCash ATM", "atm", "Wincor OS"),
    (r"CINEO\s*C\d+", "Wincor CINEO", "atm", "Wincor OS"),
    (r"CINEO", "Wincor CINEO", "atm", "Wincor OS"),

    # Cash Handling
    (r"CashCode", "Wincor CashCode", "cash_recycler", "Wincor OS"),

    # POS
    (r"BEETLE", "Wincor BEETLE POS", "pos_terminal", "Wincor OS"),
    (r"TP-net", "Wincor TP-net POS", "pos_terminal", "Wincor OS"),

    # Kiosks
    (r"Wincor\s*Kiosk", "Wincor Kiosk", "kiosk", "Wincor OS"),

    # Generic
    (r"Wincor\s*Nixdorf", "Wincor Nixdorf Device", "atm", "Wincor OS"),
    (r"Wincor", "Wincor Device", "atm", "Wincor OS"),
]

# Hyosung (ATM manufacturer)
HYOSUNG_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # REMOVED: 00:1F:6B - IEEE assigns to Unknown, not HYOSUNG
    "78:01:23": ("atm", "Financial", "Hyosung"),
    # REMOVED: 94:57:A5 - IEEE assigns to Unknown, not HYOSUNG
}

HYOSUNG_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # MoniMax Series
    (r"MoniMax\s*\d+", "Hyosung MoniMax ATM", "atm", "Hyosung OS"),
    (r"MX\s*\d{4}", "Hyosung MX Series ATM", "atm", "Hyosung OS"),

    # Nautilus
    (r"Nautilus\s*Hyosung", "Nautilus Hyosung ATM", "atm", "Hyosung OS"),
    (r"NH\s*\d+", "Nautilus Hyosung ATM", "atm", "Hyosung OS"),

    # Halo Series
    (r"Halo\s*II?", "Hyosung Halo ATM", "atm", "Hyosung OS"),

    # Force Series
    (r"Force\s*\d+", "Hyosung Force ATM", "atm", "Hyosung OS"),

    # Generic
    (r"Hyosung", "Hyosung ATM", "atm", "Hyosung OS"),
]


# AUDIO / CONSUMER ELECTRONICS PATTERNS

# JBL (Harman subsidiary)
# NOTE: JBL/Harman devices often use chipset vendor OUIs (Qualcomm, MediaTek, etc.)
# Primary identification should be via hostname (*.harman.com) or banners
# Only verified Harman International OUIs are listed here
JBL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Verified Harman International Industries OUIs from IEEE
    "90:A9:B7": ("smart_speaker", "Audio", "JBL/Harman"),
}

JBL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # JBL Soundbars
    (r"JBL[- ]?Bar\s*\d+", "JBL Bar Soundbar", "soundbar", "Linux"),
    (r"JBL[- ]?Bar\s*5\.1", "JBL Bar 5.1 Soundbar", "soundbar", "Linux"),
    (r"JBL[- ]?Bar\s*9\.1", "JBL Bar 9.1 Soundbar", "soundbar", "Linux"),
    (r"JBL[- ]?Bar\s*300", "JBL Bar 300 Soundbar", "soundbar", "Linux"),
    (r"JBL[- ]?Bar\s*500", "JBL Bar 500 Soundbar", "soundbar", "Linux"),
    (r"JBL[- ]?Bar\s*800", "JBL Bar 800 Soundbar", "soundbar", "Linux"),
    (r"JBL[- ]?Bar\s*1000", "JBL Bar 1000 Soundbar", "soundbar", "Linux"),

    # JBL Smart Speakers
    (r"JBL[- ]?Authentics\s*\d+", "JBL Authentics Speaker", "smart_speaker", "Linux"),
    (r"JBL[- ]?Authentics\s*200", "JBL Authentics 200", "smart_speaker", "Linux"),
    (r"JBL[- ]?Authentics\s*300", "JBL Authentics 300", "smart_speaker", "Linux"),
    (r"JBL[- ]?Authentics\s*500", "JBL Authentics 500", "smart_speaker", "Linux"),
    (r"JBL[- ]?Link\s*\d+", "JBL Link Speaker", "smart_speaker", "Linux"),
    (r"JBL[- ]?Link\s*Portable", "JBL Link Portable", "smart_speaker", "Linux"),
    (r"JBL[- ]?Link\s*Music", "JBL Link Music", "smart_speaker", "Linux"),
    (r"JBL[- ]?Link\s*View", "JBL Link View", "smart_display", "Linux"),

    # JBL Party Speakers
    (r"JBL[- ]?PartyBox\s*\d+", "JBL PartyBox", "speaker", "Linux"),
    (r"JBL[- ]?PartyBox\s*On-The-Go", "JBL PartyBox On-The-Go", "speaker", "Linux"),
    (r"JBL[- ]?PartyBox\s*Encore", "JBL PartyBox Encore", "speaker", "Linux"),
    (r"JBL[- ]?PartyBox\s*Ultimate", "JBL PartyBox Ultimate", "speaker", "Linux"),
    (r"JBL[- ]?Boombox\s*\d*", "JBL Boombox", "speaker", "Linux"),

    # JBL Portable Speakers
    (r"JBL[- ]?Flip\s*\d+", "JBL Flip", "speaker", None),
    (r"JBL[- ]?Charge\s*\d+", "JBL Charge", "speaker", None),
    (r"JBL[- ]?Pulse\s*\d+", "JBL Pulse", "speaker", None),
    (r"JBL[- ]?Xtreme\s*\d*", "JBL Xtreme", "speaker", None),
    (r"JBL[- ]?Go\s*\d*", "JBL Go", "speaker", None),
    (r"JBL[- ]?Clip\s*\d+", "JBL Clip", "speaker", None),

    # Generic JBL
    (r"JBL", "JBL Device", "speaker", None),
]

# Harman Kardon (Harman subsidiary)
HARMAN_KARDON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Uses Harman International OUI - see JBL prefixes above
    # Device-specific entries can be added here
}

HARMAN_KARDON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Soundbars
    (r"Harman[/ ]?Kardon\s*Citation\s*\d+", "Harman Kardon Citation", "soundbar", "Linux"),
    (r"Harman[/ ]?Kardon\s*Citation\s*MultiBeam", "Harman Kardon Citation MultiBeam", "soundbar", "Linux"),
    (r"Harman[/ ]?Kardon\s*Enchant\s*\d+", "Harman Kardon Enchant", "soundbar", "Linux"),
    (r"Harman[/ ]?Kardon\s*SB\s*\d+", "Harman Kardon Soundbar", "soundbar", "Linux"),

    # Smart Speakers
    (r"Harman[/ ]?Kardon\s*Citation\s*One", "Harman Kardon Citation One", "smart_speaker", "Linux"),
    (r"Harman[/ ]?Kardon\s*Citation\s*200", "Harman Kardon Citation 200", "smart_speaker", "Linux"),
    (r"Harman[/ ]?Kardon\s*Citation\s*300", "Harman Kardon Citation 300", "smart_speaker", "Linux"),
    (r"Harman[/ ]?Kardon\s*Citation\s*500", "Harman Kardon Citation 500", "smart_speaker", "Linux"),
    (r"Harman[/ ]?Kardon\s*Invoke", "Harman Kardon Invoke", "smart_speaker", "Linux"),
    (r"Harman[/ ]?Kardon\s*Allure", "Harman Kardon Allure", "smart_speaker", "Linux"),

    # Home Theater
    (r"Harman[/ ]?Kardon\s*AVR\s*\d+", "Harman Kardon AVR", "av_receiver", None),
    (r"Harman[/ ]?Kardon\s*BDS\s*\d+", "Harman Kardon BDS", "av_receiver", None),

    # Portable
    (r"Harman[/ ]?Kardon\s*Aura\s*Studio\s*\d*", "Harman Kardon Aura Studio", "speaker", None),
    (r"Harman[/ ]?Kardon\s*Onyx\s*Studio\s*\d*", "Harman Kardon Onyx Studio", "speaker", None),
    (r"Harman[/ ]?Kardon\s*Go\s*\+?\s*Play", "Harman Kardon Go + Play", "speaker", None),

    # Generic
    (r"Harman[/ ]?Kardon", "Harman Kardon Device", "speaker", None),
    (r"\.harman\.com$", "Harman Device", "smart_speaker", "Linux"),
    (r"devices\.harman\.com", "Harman Smart Device", "smart_speaker", "Linux"),
]

# NOTE: Sonos and Bose patterns are already defined earlier in this file
# See SONOS_MAC_PREFIXES / SONOS_BANNER_PATTERNS around line 5081
# See BOSE_MAC_PREFIXES / BOSE_BANNER_PATTERNS around line 8268

# Marshall
MARSHALL_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Marshall uses various chipset vendors - specific OUIs TBD
}

MARSHALL_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Marshall\s*Stanmore\s*\d*", "Marshall Stanmore", "smart_speaker", None),
    (r"Marshall\s*Woburn\s*\d*", "Marshall Woburn", "smart_speaker", None),
    (r"Marshall\s*Acton\s*\d*", "Marshall Acton", "smart_speaker", None),
    (r"Marshall\s*Uxbridge", "Marshall Uxbridge", "smart_speaker", None),
    (r"Marshall\s*Kilburn\s*\d*", "Marshall Kilburn", "speaker", None),
    (r"Marshall\s*Emberton\s*\d*", "Marshall Emberton", "speaker", None),
    (r"Marshall\s*Middleton", "Marshall Middleton", "speaker", None),
    (r"Marshall\s*Tufton", "Marshall Tufton", "speaker", None),
    (r"Marshall", "Marshall Speaker", "speaker", None),
]

# Bang & Olufsen
BANG_OLUFSEN_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

BANG_OLUFSEN_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Beoplay\s*[A-Z]\d+", "Bang & Olufsen Beoplay", "smart_speaker", None),
    (r"Beosound\s*\w+", "Bang & Olufsen Beosound", "smart_speaker", None),
    (r"Beolab\s*\d+", "Bang & Olufsen Beolab", "speaker", None),
    (r"Beovision\s*\w+", "Bang & Olufsen Beovision", "smart_tv", None),
    (r"B&O|Bang\s*[&+]\s*Olufsen", "Bang & Olufsen Device", "speaker", None),
]

# Denon
DENON_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
}

DENON_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Denon\s*AVR-[SX]\d+", "Denon AVR", "av_receiver", None),
    (r"Denon\s*HEOS\s*\w+", "Denon HEOS", "smart_speaker", None),
    (r"Denon\s*Home\s*\d+", "Denon Home", "smart_speaker", None),
    (r"Denon\s*DHT-S\d+", "Denon DHT Soundbar", "soundbar", None),
    (r"Denon", "Denon Device", "av_receiver", None),
]

# Yamaha (Audio products)
YAMAHA_AUDIO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:A0:DE": ("av_receiver", "Audio", "Yamaha"),
}

YAMAHA_AUDIO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Yamaha\s*RX-[VA]\d+", "Yamaha AV Receiver", "av_receiver", None),
    (r"Yamaha\s*MusicCast\s*\w+", "Yamaha MusicCast", "smart_speaker", None),
    (r"Yamaha\s*YAS-\d+", "Yamaha Soundbar", "soundbar", None),
    (r"Yamaha\s*SR-[BC]\d+", "Yamaha Soundbar", "soundbar", None),
    (r"Yamaha\s*WX-\d+", "Yamaha Wireless Speaker", "smart_speaker", None),
    (r"Yamaha.*(?:Audio|Sound)", "Yamaha Audio", "speaker", None),
]


# META / OCULUS (VR Headsets)
META_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "78:1A:EC": ("vr_headset", "VR", "Meta Quest"),
}

META_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Quest\s*3S", "Meta Quest 3S", "vr_headset", "Meta Horizon"),
    (r"Quest\s*3", "Meta Quest 3", "vr_headset", "Meta Horizon"),
    (r"Quest\s*Pro", "Meta Quest Pro", "vr_headset", "Meta Horizon"),
    (r"Quest\s*2", "Meta Quest 2", "vr_headset", "Android"),
    (r"Oculus\s*Quest", "Meta Quest", "vr_headset", "Android"),
    (r"Meta\s*Portal", "Meta Portal", "smart_display", "Linux"),
    (r"Meta\s*Quest", "Meta Quest", "vr_headset", "Meta Horizon"),
]


# HP CONSUMER (Laptops/Desktops - separate from HPE servers and HP Printers)
HP_CONSUMER_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:21:5A": ("laptop", "Computer", "HP Laptop"),
    "00:23:7D": ("laptop", "Computer", "HP Laptop"),
    "00:26:55": ("laptop", "Computer", "HP Laptop"),
    "10:1F:74": ("laptop", "Computer", "HP Laptop"),
    "18:60:24": ("laptop", "Computer", "HP Laptop"),
    "28:80:23": ("laptop", "Computer", "HP Laptop"),
    "2C:41:38": ("laptop", "Computer", "HP Laptop"),
    "34:64:A9": ("laptop", "Computer", "HP Laptop"),
    "38:63:BB": ("laptop", "Computer", "HP Laptop"),
    "3C:52:82": ("laptop", "Computer", "HP Laptop"),
    "40:B0:34": ("laptop", "Computer", "HP Laptop"),
    "44:31:92": ("laptop", "Computer", "HP Laptop"),
    "48:BA:4E": ("laptop", "Computer", "HP Laptop"),
    "50:65:F3": ("laptop", "Computer", "HP Laptop"),
    "58:20:B1": ("laptop", "Computer", "HP Laptop"),
    "5C:B9:01": ("desktop", "Computer", "HP Desktop"),
    # REMOVED: 64:51:06 - IEEE assigns to Hewlett Packard, keeping in Aruba (HP subsidiary)
    "68:B5:99": ("laptop", "Computer", "HP Laptop"),
    "70:5A:0F": ("laptop", "Computer", "HP Laptop"),
    "78:AC:C0": ("desktop", "Computer", "HP Desktop"),
    "80:CE:62": ("laptop", "Computer", "HP Laptop"),
    "98:E7:F4": ("laptop", "Computer", "HP Laptop"),
    "A0:D3:C1": ("laptop", "Computer", "HP Laptop"),
    "A4:5D:36": ("desktop", "Computer", "HP Desktop"),
    "B0:5C:DA": ("laptop", "Computer", "HP Laptop"),
    "B4:B6:86": ("laptop", "Computer", "HP Laptop"),
    "B8:AF:67": ("laptop", "Computer", "HP Laptop"),
    "C0:18:03": ("desktop", "Computer", "HP Desktop"),
    "C4:34:6B": ("laptop", "Computer", "HP Laptop"),
    "D0:BF:9C": ("laptop", "Computer", "HP Laptop"),
    "D8:D3:85": ("laptop", "Computer", "HP Laptop"),
    "EC:8E:B5": ("laptop", "Computer", "HP Laptop"),
    "F4:30:B9": ("laptop", "Computer", "HP Laptop"),
    "F8:B4:6A": ("laptop", "Computer", "HP Laptop"),
}

HP_CONSUMER_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"HP\s*Spectre", "HP Spectre", "laptop", "Windows"),
    (r"HP\s*Envy.*(?:x360|Laptop)", "HP Envy", "laptop", "Windows"),
    (r"HP\s*Pavilion.*(?:Laptop|Desktop)", "HP Pavilion", "computer", "Windows"),
    (r"HP\s*EliteBook", "HP EliteBook", "laptop", "Windows"),
    (r"HP\s*ProBook", "HP ProBook", "laptop", "Windows"),
    (r"HP\s*ZBook", "HP ZBook", "workstation", "Windows"),
    (r"HP\s*Omen", "HP Omen", "laptop", "Windows"),
    (r"HP\s*Chromebook", "HP Chromebook", "laptop", "Chrome OS"),
    (r"HP\s*EliteDesk", "HP EliteDesk", "desktop", "Windows"),
    (r"HP\s*ProDesk", "HP ProDesk", "desktop", "Windows"),
    (r"HP\s*Elite\s*Dragonfly", "HP Elite Dragonfly", "laptop", "Windows"),
    (r"HP\s*Victus", "HP Victus", "laptop", "Windows"),
]


# CHIPSET VENDORS (OUI registered to chipset makers, found in many devices)

# Realtek - IEEE verified OUIs (source: maclookup.app/vendors/realtek-semiconductor-corp)
REALTEK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:E0:4C": ("nic", "Hardware", "Realtek NIC"),
}

# Qualcomm / Atheros - IEEE verified OUIs
# Sources: maclookup.app/vendors/qualcomm-inc, atheros-communications-inc
QUALCOMM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Qualcomm Inc. OUIs
    "00:A0:C6": ("nic", "Hardware", "Qualcomm NIC"),
    "64:9C:81": ("nic", "Hardware", "Qualcomm NIC"),
    "88:12:4E": ("nic", "Hardware", "Qualcomm NIC"),
    "8C:FD:F0": ("nic", "Hardware", "Qualcomm NIC"),
    # Atheros Communications OUIs (Qualcomm subsidiary)
}

# MediaTek - IEEE verified OUIs (source: maclookup.app/vendors/mediatek-inc)
MEDIATEK_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0A:00": ("nic", "Hardware", "MediaTek NIC"),
    "00:0C:43": ("nic", "Hardware", "MediaTek NIC"),
    "00:0C:E7": ("nic", "Hardware", "MediaTek NIC"),
    "00:17:A5": ("nic", "Hardware", "MediaTek NIC"),
}

# Broadcom - IEEE verified OUIs (source: maclookup.app/vendors/broadcom)
BROADCOM_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0A:F7": ("nic", "Hardware", "Broadcom NIC"),
    "00:0D:B6": ("nic", "Hardware", "Broadcom NIC"),
    "00:10:18": ("nic", "Hardware", "Broadcom NIC"),
    "00:1B:E9": ("nic", "Hardware", "Broadcom NIC"),
    "18:C0:86": ("nic", "Hardware", "Broadcom NIC"),
    "38:BA:B0": ("nic", "Hardware", "Broadcom NIC"),
    "B8:CE:ED": ("nic", "Hardware", "Broadcom NIC"),
    "D4:01:29": ("nic", "Hardware", "Broadcom NIC"),
    "E0:3E:44": ("nic", "Hardware", "Broadcom NIC"),
}


# PANASONIC (Cameras, TVs, Appliances)
PANASONIC_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "04:20:9A": ("smart_tv", "Entertainment", "Panasonic TV"),
    "20:C6:EB": ("smart_tv", "Entertainment", "Panasonic TV"),
    "34:63:BC": ("smart_tv", "Entertainment", "Panasonic TV"),
    "3C:C2:2B": ("smart_tv", "Entertainment", "Panasonic TV"),
    "44:36:FC": ("smart_tv", "Entertainment", "Panasonic TV"),
    "78:CF:BF": ("smart_tv", "Entertainment", "Panasonic TV"),
    "80:BE:B6": ("smart_tv", "Entertainment", "Panasonic TV"),
}

PANASONIC_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Panasonic\s*(?:VIERA|TV)", "Panasonic TV", "smart_tv", None),
    (r"Panasonic\s*WV-", "Panasonic IP Camera", "camera", None),
    (r"Panasonic\s*Toughbook", "Panasonic Toughbook", "laptop", "Windows"),
    (r"Panasonic\s*Lumix", "Panasonic Lumix Camera", "camera", None),
]


# TOSHIBA (Laptops, TVs)
TOSHIBA_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "00:0E:7B": ("laptop", "Computer", "Toshiba"),
    "00:23:18": ("laptop", "Computer", "Toshiba"),
    "B8:6B:23": ("laptop", "Computer", "Toshiba"),
}

TOSHIBA_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Toshiba.*Satellite", "Toshiba Satellite", "laptop", "Windows"),
    (r"Toshiba.*Portege", "Toshiba Portege", "laptop", "Windows"),
    (r"Toshiba.*Tecra", "Toshiba Tecra", "laptop", "Windows"),
    (r"Toshiba.*TV", "Toshiba TV", "smart_tv", None),
    (r"Toshiba.*REGZA", "Toshiba REGZA TV", "smart_tv", None),
]


# SHARP (TVs, Displays)
SHARP_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    "44:A7:C3": ("smart_tv", "Entertainment", "Sharp TV"),
}

SHARP_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"Sharp\s*AQUOS", "Sharp AQUOS TV", "smart_tv", "Android TV"),
    (r"Sharp.*TV", "Sharp TV", "smart_tv", None),
]


# EERO (AMAZON) MESH ROUTER PATTERNS

EERO_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # eero inc. (IEEE MA-L) — Amazon mesh WiFi routers
    "00:AB:48": ("mesh_router", "Network Equipment", "eero"),
    "08:9B:F1": ("mesh_router", "Network Equipment", "eero"),
    "08:F0:1E": ("mesh_router", "Network Equipment", "eero"),
    "0C:1C:1A": ("mesh_router", "Network Equipment", "eero"),
    "0C:93:A5": ("mesh_router", "Network Equipment", "eero"),
    "0C:C7:63": ("mesh_router", "Network Equipment", "eero"),
    "14:22:DB": ("mesh_router", "Network Equipment", "eero"),
    "18:90:88": ("mesh_router", "Network Equipment", "eero"),
    "18:A9:ED": ("mesh_router", "Network Equipment", "eero"),
    "20:3A:0C": ("mesh_router", "Network Equipment", "eero"),
    "20:BE:CD": ("mesh_router", "Network Equipment", "eero"),
    "20:E6:DF": ("mesh_router", "Network Equipment", "eero"),
    "24:2D:6C": ("mesh_router", "Network Equipment", "eero"),
    "24:F3:E3": ("mesh_router", "Network Equipment", "eero"),
    "28:EC:22": ("mesh_router", "Network Equipment", "eero"),
    "2C:2B:DB": ("mesh_router", "Network Equipment", "eero"),
    "2C:2F:F4": ("mesh_router", "Network Equipment", "eero"),
    "30:29:2B": ("mesh_router", "Network Equipment", "eero"),
    "30:34:22": ("mesh_router", "Network Equipment", "eero"),
    "30:3A:4A": ("mesh_router", "Network Equipment", "eero"),
    "30:57:8E": ("mesh_router", "Network Equipment", "eero"),
    "34:BC:5E": ("mesh_router", "Network Equipment", "eero"),
    "3C:5C:F1": ("mesh_router", "Network Equipment", "eero"),
    "40:47:5E": ("mesh_router", "Network Equipment", "eero"),
    "40:49:7C": ("mesh_router", "Network Equipment", "eero"),
    "44:AC:85": ("mesh_router", "Network Equipment", "eero"),
    "48:B4:24": ("mesh_router", "Network Equipment", "eero"),
    "48:DD:0C": ("mesh_router", "Network Equipment", "eero"),
    "4C:01:43": ("mesh_router", "Network Equipment", "eero"),
    "50:27:A9": ("mesh_router", "Network Equipment", "eero"),
    "50:61:3F": ("mesh_router", "Network Equipment", "eero"),
    "5C:A5:BC": ("mesh_router", "Network Equipment", "eero"),
    "60:57:7D": ("mesh_router", "Network Equipment", "eero"),
    "60:5F:8D": ("mesh_router", "Network Equipment", "eero"),
    "60:F4:19": ("mesh_router", "Network Equipment", "eero"),
    "64:97:14": ("mesh_router", "Network Equipment", "eero"),
    "64:C2:69": ("mesh_router", "Network Equipment", "eero"),
    "64:D9:C2": ("mesh_router", "Network Equipment", "eero"),
    "64:DA:ED": ("mesh_router", "Network Equipment", "eero"),
    "68:4A:76": ("mesh_router", "Network Equipment", "eero"),
    "6C:AE:F6": ("mesh_router", "Network Equipment", "eero"),
    "6C:BF:2F": ("mesh_router", "Network Equipment", "eero"),
    "70:93:C1": ("mesh_router", "Network Equipment", "eero"),
    "74:B6:B6": ("mesh_router", "Network Equipment", "eero"),
    "78:68:29": ("mesh_router", "Network Equipment", "eero"),
    "78:76:89": ("mesh_router", "Network Equipment", "eero"),
    "78:D6:D6": ("mesh_router", "Network Equipment", "eero"),
    "7C:49:CF": ("mesh_router", "Network Equipment", "eero"),
    "7C:5E:98": ("mesh_router", "Network Equipment", "eero"),
    "7C:7E:F9": ("mesh_router", "Network Equipment", "eero"),
    "80:AF:9F": ("mesh_router", "Network Equipment", "eero"),
    "80:B9:7A": ("mesh_router", "Network Equipment", "eero"),
    "80:DA:13": ("mesh_router", "Network Equipment", "eero"),
    "84:70:D7": ("mesh_router", "Network Equipment", "eero"),
    "84:D9:E0": ("mesh_router", "Network Equipment", "eero"),
    "88:67:46": ("mesh_router", "Network Equipment", "eero"),
    "8C:DD:0B": ("mesh_router", "Network Equipment", "eero"),
    "90:0E:84": ("mesh_router", "Network Equipment", "eero"),
    "94:CD:FD": ("mesh_router", "Network Equipment", "eero"),
    "98:ED:7E": ("mesh_router", "Network Equipment", "eero"),
    "9C:0B:05": ("mesh_router", "Network Equipment", "eero"),
    "9C:57:BC": ("mesh_router", "Network Equipment", "eero"),
    "9C:A5:70": ("mesh_router", "Network Equipment", "eero"),
    "A0:8E:24": ("mesh_router", "Network Equipment", "eero"),
    "A4:0F:25": ("mesh_router", "Network Equipment", "eero"),
    "A4:6B:1F": ("mesh_router", "Network Equipment", "eero"),
    "A4:99:A8": ("mesh_router", "Network Equipment", "eero"),
    "A8:13:0B": ("mesh_router", "Network Equipment", "eero"),
    "A8:B0:88": ("mesh_router", "Network Equipment", "eero"),
    "AC:39:3D": ("mesh_router", "Network Equipment", "eero"),
    "AC:EC:85": ("mesh_router", "Network Equipment", "eero"),
    "B0:F1:AE": ("mesh_router", "Network Equipment", "eero"),
    "B4:20:46": ("mesh_router", "Network Equipment", "eero"),
    "B4:B9:E6": ("mesh_router", "Network Equipment", "eero"),
    "B8:32:8F": ("mesh_router", "Network Equipment", "eero"),
    "C0:36:53": ("mesh_router", "Network Equipment", "eero"),
    "C0:6F:98": ("mesh_router", "Network Equipment", "eero"),
    "C4:A8:16": ("mesh_router", "Network Equipment", "eero"),
    "C4:F1:74": ("mesh_router", "Network Equipment", "eero"),
    "C8:B8:2F": ("mesh_router", "Network Equipment", "eero"),
    "C8:C6:FE": ("mesh_router", "Network Equipment", "eero"),
    "C8:CC:21": ("mesh_router", "Network Equipment", "eero"),
    "C8:E3:06": ("mesh_router", "Network Equipment", "eero"),
    "D0:16:7C": ("mesh_router", "Network Equipment", "eero"),
    "D0:68:27": ("mesh_router", "Network Equipment", "eero"),
    "D0:CB:DD": ("mesh_router", "Network Equipment", "eero"),
    "D4:05:DE": ("mesh_router", "Network Equipment", "eero"),
    "D4:3F:32": ("mesh_router", "Network Equipment", "eero"),
    "D8:8E:D4": ("mesh_router", "Network Equipment", "eero"),
    "DC:69:B5": ("mesh_router", "Network Equipment", "eero"),
    "DC:B4:3F": ("mesh_router", "Network Equipment", "eero"),
    "E4:19:7F": ("mesh_router", "Network Equipment", "eero"),
    "E8:D3:EB": ("mesh_router", "Network Equipment", "eero"),
    "EC:30:DD": ("mesh_router", "Network Equipment", "eero"),
    "EC:74:27": ("mesh_router", "Network Equipment", "eero"),
    "F0:21:E0": ("mesh_router", "Network Equipment", "eero"),
    "F0:B6:61": ("mesh_router", "Network Equipment", "eero"),
    "F4:25:3C": ("mesh_router", "Network Equipment", "eero"),
    "F8:BB:BF": ("mesh_router", "Network Equipment", "eero"),
    "F8:BC:0E": ("mesh_router", "Network Equipment", "eero"),
    "FC:3D:73": ("mesh_router", "Network Equipment", "eero"),
    "FC:3F:A6": ("mesh_router", "Network Equipment", "eero"),
}

EERO_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    (r"eero\s*Pro\s*6E", "eero Pro 6E", "mesh_router", "eeroOS"),
    (r"eero\s*Pro\s*6", "eero Pro 6", "mesh_router", "eeroOS"),
    (r"eero\s*Pro", "eero Pro", "mesh_router", "eeroOS"),
    (r"eero\s*6\+", "eero 6+", "mesh_router", "eeroOS"),
    (r"eero\s*6E", "eero 6E", "mesh_router", "eeroOS"),
    (r"eero\s*6", "eero 6", "mesh_router", "eeroOS"),
    (r"eero\s*Max\s*7", "eero Max 7", "mesh_router", "eeroOS"),
    (r"eero\s*PoE\s*6", "eero PoE 6", "mesh_router", "eeroOS"),
    (r"eero\s*Beacon", "eero Beacon", "mesh_router", "eeroOS"),
    (r"eero", "eero Mesh Router", "mesh_router", "eeroOS"),
]


# ARRIS / COMMSCOPE CABLE MODEM AND GATEWAY PATTERNS

ARRIS_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # CommScope / ARRIS Group (IEEE MA-L) — cable modems and gateways
    # Subset of most commonly seen prefixes on ISP networks (Comcast/Xfinity, etc.)
    "00:00:CA": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:03:E0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:04:BD": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:08:0E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:0B:06": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:0C:E5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:0E:5C": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:0F:9F": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:11:1A": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:11:80": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:12:25": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:12:C9": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:13:11": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:13:71": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:14:9A": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:14:E8": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:96": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:9A": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:A2": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:A3": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:A4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:CE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:CF": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:D0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:15:D1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:16:26": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:16:75": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:16:B5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:17:00": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:17:EE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:18:A4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:19:5E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:19:A6": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1A:66": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1A:77": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1A:DB": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1A:DE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1B:DD": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1C:11": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1C:FB": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:BE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:CD": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:CE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:CF": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D2": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D3": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1D:D6": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1E:5A": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1E:8D": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:1F:C4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:21:1E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:21:80": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:22:10": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:74": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:75": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:95": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:A2": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:A3": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:ED": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:23:EE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:24:95": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:24:A0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:24:A1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:25:F1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:25:F2": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:26:36": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:26:42": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "00:26:D9": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "10:86:8C": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "10:E1:77": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "14:AB:F0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "14:CF:E2": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "14:D4:FE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "18:35:D1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "1C:1B:68": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "20:3D:66": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "20:E5:64": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "20:F3:75": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "2C:9E:5F": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "34:1F:E4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "38:6B:BB": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "38:70:0C": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "3C:36:E4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "3C:7A:8A": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "3C:DF:A9": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "40:B7:F3": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "44:AA:F5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "44:E1:37": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "54:E2:E0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "58:56:E8": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "5C:8F:E0": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "5C:E3:0E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "60:8C:E6": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "64:ED:57": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "6C:A6:04": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "6C:CA:08": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "70:54:25": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "70:76:30": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "70:DF:F7": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "74:56:12": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "74:E7:C6": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "78:71:9C": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "78:96:84": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "84:BB:69": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "84:E0:58": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "88:71:B1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "88:96:4E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "90:B1:34": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "90:C7:92": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "94:62:69": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "94:87:7C": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "94:CC:B9": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "94:E8:C5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "98:F7:81": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "9C:34:26": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "9C:C8:FC": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "A0:55:DE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "A0:68:7E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "A4:ED:4E": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "A8:97:CD": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "AC:B3:13": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "AC:EC:80": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "B0:77:AC": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "B0:93:5B": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "B0:DA:F9": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "BC:64:4B": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "BC:CA:B5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "C0:05:C2": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "C0:94:35": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "C0:A0:0D": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "C8:AA:21": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "CC:65:AD": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "D0:39:B3": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "D4:04:CD": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "D4:6C:6D": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "D4:AB:82": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "DC:45:17": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "E0:B7:B1": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "E4:64:49": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "E8:3E:FC": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "E8:ED:05": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "F0:AF:85": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "F8:0B:BE": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "F8:7B:7A": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "F8:8B:37": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "F8:ED:A5": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "FC:51:A4": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
    "FC:AE:34": ("cable_modem", "Network Equipment", "ARRIS/CommScope"),
}

ARRIS_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Surfboard cable modems
    (r"SB\d{4}", "ARRIS Surfboard", "cable_modem", "Firmware"),
    (r"SBG\d{4}", "ARRIS Surfboard Gateway", "cable_modem", "Firmware"),
    (r"Surfboard", "ARRIS Surfboard", "cable_modem", "Firmware"),
    # Touchstone cable modems
    (r"TG\d{4}", "ARRIS Touchstone Gateway", "cable_modem", "Firmware"),
    (r"TM\d{4}", "ARRIS Touchstone Modem", "cable_modem", "Firmware"),
    (r"Touchstone", "ARRIS Touchstone", "cable_modem", "Firmware"),
    # Xfinity gateways (ARRIS-built)
    (r"XB\d", "ARRIS Xfinity Gateway", "cable_modem", "Firmware"),
    # Generic
    (r"ARRIS", "ARRIS Device", "cable_modem", None),
    (r"CommScope", "CommScope Device", "network_device", None),
]


# TECHNICOLOR / VANTIVA CABLE MODEM AND GATEWAY PATTERNS

TECHNICOLOR_MAC_PREFIXES: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Vantiva USA LLC / Technicolor (IEEE MA-L) — ISP cable modems and gateways
    "00:CB:7A": ("cable_modem", "Network Equipment", "Technicolor"),
    "08:7E:64": ("cable_modem", "Network Equipment", "Technicolor"),
    "08:95:2A": ("cable_modem", "Network Equipment", "Technicolor"),
    "08:A7:C0": ("cable_modem", "Network Equipment", "Technicolor"),
    "0C:02:27": ("cable_modem", "Network Equipment", "Technicolor"),
    "0C:FE:7B": ("cable_modem", "Network Equipment", "Technicolor"),
    "10:33:BF": ("cable_modem", "Network Equipment", "Technicolor"),
    "10:62:D0": ("cable_modem", "Network Equipment", "Technicolor"),
    "10:A7:93": ("cable_modem", "Network Equipment", "Technicolor"),
    "10:C2:5A": ("cable_modem", "Network Equipment", "Technicolor"),
    "14:98:7D": ("cable_modem", "Network Equipment", "Technicolor"),
    "14:B7:F8": ("cable_modem", "Network Equipment", "Technicolor"),
    "1C:9D:72": ("cable_modem", "Network Equipment", "Technicolor"),
    "1C:9E:CC": ("cable_modem", "Network Equipment", "Technicolor"),
    "28:BE:9B": ("cable_modem", "Network Equipment", "Technicolor"),
    "38:17:E1": ("cable_modem", "Network Equipment", "Technicolor"),
    "38:3F:B3": ("cable_modem", "Network Equipment", "Technicolor"),
    "3C:82:C0": ("cable_modem", "Network Equipment", "Technicolor"),
    "3C:9A:77": ("cable_modem", "Network Equipment", "Technicolor"),
    "3C:B7:4B": ("cable_modem", "Network Equipment", "Technicolor"),
    "40:0F:C1": ("cable_modem", "Network Equipment", "Technicolor"),
    "40:75:C3": ("cable_modem", "Network Equipment", "Technicolor"),
    "44:1C:12": ("cable_modem", "Network Equipment", "Technicolor"),
    "44:32:C8": ("cable_modem", "Network Equipment", "Technicolor"),
    "48:00:33": ("cable_modem", "Network Equipment", "Technicolor"),
    "48:1B:40": ("cable_modem", "Network Equipment", "Technicolor"),
    "48:4B:D4": ("cable_modem", "Network Equipment", "Technicolor"),
    "48:BD:CE": ("cable_modem", "Network Equipment", "Technicolor"),
    "48:F7:C0": ("cable_modem", "Network Equipment", "Technicolor"),
    "4C:D7:4A": ("cable_modem", "Network Equipment", "Technicolor"),
    "50:09:59": ("cable_modem", "Network Equipment", "Technicolor"),
    "50:BB:9F": ("cable_modem", "Network Equipment", "Technicolor"),
    "54:A6:5C": ("cable_modem", "Network Equipment", "Technicolor"),
    "58:23:8C": ("cable_modem", "Network Equipment", "Technicolor"),
    "58:96:30": ("cable_modem", "Network Equipment", "Technicolor"),
    "5C:22:DA": ("cable_modem", "Network Equipment", "Technicolor"),
    "5C:76:95": ("cable_modem", "Network Equipment", "Technicolor"),
    "5C:7D:7D": ("cable_modem", "Network Equipment", "Technicolor"),
    "60:3D:26": ("cable_modem", "Network Equipment", "Technicolor"),
    "64:12:36": ("cable_modem", "Network Equipment", "Technicolor"),
    "64:1B:85": ("cable_modem", "Network Equipment", "Technicolor"),
    "6C:55:E8": ("cable_modem", "Network Equipment", "Technicolor"),
    "70:03:7E": ("cable_modem", "Network Equipment", "Technicolor"),
    "70:5A:9E": ("cable_modem", "Network Equipment", "Technicolor"),
    "7C:9A:54": ("cable_modem", "Network Equipment", "Technicolor"),
    "80:29:94": ("cable_modem", "Network Equipment", "Technicolor"),
    "80:B2:34": ("cable_modem", "Network Equipment", "Technicolor"),
    "80:C6:AB": ("cable_modem", "Network Equipment", "Technicolor"),
    "80:D0:4A": ("cable_modem", "Network Equipment", "Technicolor"),
    "80:DA:C2": ("cable_modem", "Network Equipment", "Technicolor"),
    "84:17:EF": ("cable_modem", "Network Equipment", "Technicolor"),
    "88:9E:68": ("cable_modem", "Network Equipment", "Technicolor"),
    "88:F7:C7": ("cable_modem", "Network Equipment", "Technicolor"),
    "8C:04:FF": ("cable_modem", "Network Equipment", "Technicolor"),
    "8C:5C:20": ("cable_modem", "Network Equipment", "Technicolor"),
    "8C:6A:8D": ("cable_modem", "Network Equipment", "Technicolor"),
    "90:58:51": ("cable_modem", "Network Equipment", "Technicolor"),
    "94:04:E3": ("cable_modem", "Network Equipment", "Technicolor"),
    "94:6A:77": ("cable_modem", "Network Equipment", "Technicolor"),
    "98:52:4A": ("cable_modem", "Network Equipment", "Technicolor"),
    "98:9D:5D": ("cable_modem", "Network Equipment", "Technicolor"),
    "A0:FF:70": ("cable_modem", "Network Equipment", "Technicolor"),
    "A4:56:CC": ("cable_modem", "Network Equipment", "Technicolor"),
    "AC:4C:A5": ("cable_modem", "Network Equipment", "Technicolor"),
    "AC:62:FF": ("cable_modem", "Network Equipment", "Technicolor"),
    "B0:C2:87": ("cable_modem", "Network Equipment", "Technicolor"),
    "B4:2A:0E": ("cable_modem", "Network Equipment", "Technicolor"),
    "B8:5E:71": ("cable_modem", "Network Equipment", "Technicolor"),
    "B8:A5:35": ("cable_modem", "Network Equipment", "Technicolor"),
    "BC:9B:68": ("cable_modem", "Network Equipment", "Technicolor"),
    "C4:27:95": ("cable_modem", "Network Equipment", "Technicolor"),
    "CC:03:FA": ("cable_modem", "Network Equipment", "Technicolor"),
    "CC:35:40": ("cable_modem", "Network Equipment", "Technicolor"),
    "CC:F3:C8": ("cable_modem", "Network Equipment", "Technicolor"),
    "D0:5A:00": ("cable_modem", "Network Equipment", "Technicolor"),
    "D0:8A:91": ("cable_modem", "Network Equipment", "Technicolor"),
    "D0:B2:C4": ("cable_modem", "Network Equipment", "Technicolor"),
    "D4:B9:2F": ("cable_modem", "Network Equipment", "Technicolor"),
    "D4:E2:CB": ("cable_modem", "Network Equipment", "Technicolor"),
    "DC:EB:69": ("cable_modem", "Network Equipment", "Technicolor"),
    "E0:37:17": ("cable_modem", "Network Equipment", "Technicolor"),
    "E0:88:5D": ("cable_modem", "Network Equipment", "Technicolor"),
    "E0:DB:D1": ("cable_modem", "Network Equipment", "Technicolor"),
    "E4:BF:FA": ("cable_modem", "Network Equipment", "Technicolor"),
    "E8:CD:15": ("cable_modem", "Network Equipment", "Technicolor"),
    "EC:93:7D": ("cable_modem", "Network Equipment", "Technicolor"),
    "EC:A8:1F": ("cable_modem", "Network Equipment", "Technicolor"),
    "F0:4B:8A": ("cable_modem", "Network Equipment", "Technicolor"),
    "F4:C1:14": ("cable_modem", "Network Equipment", "Technicolor"),
    "F8:20:D2": ("cable_modem", "Network Equipment", "Technicolor"),
    "F8:3B:1D": ("cable_modem", "Network Equipment", "Technicolor"),
    "F8:5E:42": ("cable_modem", "Network Equipment", "Technicolor"),
    "F8:D0:0E": ("cable_modem", "Network Equipment", "Technicolor"),
    "F8:D2:AC": ("cable_modem", "Network Equipment", "Technicolor"),
    "FC:52:8D": ("cable_modem", "Network Equipment", "Technicolor"),
    "FC:91:14": ("cable_modem", "Network Equipment", "Technicolor"),
    "FC:94:E3": ("cable_modem", "Network Equipment", "Technicolor"),
}

TECHNICOLOR_BANNER_PATTERNS: List[Tuple[str, str, str, Optional[str]]] = [
    # Cable gateways
    (r"CGA\d{4}", "Technicolor CGA Gateway", "cable_modem", "Firmware"),
    (r"TC\d{4}", "Technicolor TC Modem", "cable_modem", "Firmware"),
    (r"DGA\d{4}", "Technicolor DGA Gateway", "cable_modem", "Firmware"),
    (r"TG\d{3}", "Technicolor TG Gateway", "cable_modem", "Firmware"),
    (r"MediaAccess", "Technicolor MediaAccess", "cable_modem", "Firmware"),
    # Generic
    (r"Technicolor", "Technicolor Device", "cable_modem", None),
    (r"Vantiva", "Vantiva/Technicolor Device", "cable_modem", None),
]


# VENDOR ENRICHMENT FUNCTIONS

def enrich_ubiquiti_device(
    mac_address: Optional[str] = None,
    banners: Optional[List[str]] = None,
    hostname: Optional[str] = None,
    open_ports: Optional[List[int]] = None,
    kernel_version: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enrich Ubiquiti device identification with specific model and type.

    Args:
        mac_address: Device MAC address
        banners: List of service banners
        hostname: Device hostname
        open_ports: List of open ports
        kernel_version: Detected kernel version

    Returns:
        Dict with device_type, model, firmware_hint, confidence
    """
    result = {
        "device_type": None,
        "device_category": None,
        "model": None,
        "firmware_hint": None,
        "confidence": 0.0,
    }

    # 1. Check MAC OUI prefix
    if mac_address:
        mac_upper = mac_address.upper().replace("-", ":")
        prefix = mac_upper[:8]

        if prefix in UBIQUITI_MAC_PREFIXES:
            device_type, category, model_hint = UBIQUITI_MAC_PREFIXES[prefix]
            result["device_type"] = device_type
            result["device_category"] = category
            result["model"] = model_hint
            result["confidence"] = 0.70

    # 2. Check service banners for model detection
    if banners:
        banner_text = " ".join(banners)

        for pattern, model, device_type, firmware in UBIQUITI_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                result["model"] = model
                result["device_type"] = device_type
                result["firmware_hint"] = firmware
                result["confidence"] = max(result["confidence"], 0.90)
                break

    # 3. Check hostname for model hints
    if hostname:
        hostname_upper = hostname.upper()

        for pattern, model, device_type, firmware in UBIQUITI_BANNER_PATTERNS:
            if re.search(pattern, hostname_upper, re.IGNORECASE):
                result["model"] = model
                result["device_type"] = device_type
                result["firmware_hint"] = firmware
                result["confidence"] = max(result["confidence"], 0.85)
                break

    # 4. Check port signatures for device type hints
    if open_ports and not result["device_type"]:
        for port in open_ports:
            if port in UBIQUITI_PORT_SIGNATURES:
                service_hint, device_hint = UBIQUITI_PORT_SIGNATURES[port]
                if device_hint:
                    result["device_type"] = device_hint
                    result["confidence"] = max(result["confidence"], 0.60)

    # 5. Map kernel version to firmware if we have Ubiquiti manufacturer
    if kernel_version and not result["firmware_hint"]:
        kernel_major = kernel_version.split(".")[0] if kernel_version else ""
        kernel_minor = kernel_version.split(".")[1] if "." in kernel_version else ""
        kernel_prefix = f"{kernel_major}.{kernel_minor}" if kernel_minor else kernel_major

        kernel_to_firmware = {
            "2.6": "Legacy Firmware",
            "3.2": "EdgeOS 1.x / AirOS 5.x",
            "3.10": "EdgeOS 1.x / UniFi OS 1.x",
            "4.4": "EdgeOS 2.x / UniFi OS 2.x",
            "4.9": "UniFi OS 3.x",
            "4.14": "EdgeOS 2.x",
            "5.4": "UniFi OS 4.x",
            "5.10": "UniFi OS 4.x",
        }

        if kernel_prefix in kernel_to_firmware:
            result["firmware_hint"] = kernel_to_firmware[kernel_prefix]

    return result


def enrich_mikrotik_device(
    mac_address: Optional[str] = None,
    banners: Optional[List[str]] = None,
    hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enrich MikroTik device identification with specific model and type.

    Args:
        mac_address: Device MAC address
        banners: List of service banners
        hostname: Device hostname

    Returns:
        Dict with device_type, model, firmware_hint, confidence
    """
    result = {
        "device_type": None,
        "device_category": None,
        "model": None,
        "firmware_hint": None,
        "confidence": 0.0,
    }

    # 1. Check MAC OUI prefix
    if mac_address:
        mac_upper = mac_address.upper().replace("-", ":")
        prefix = mac_upper[:8]

        if prefix in MIKROTIK_MAC_PREFIXES:
            device_type, category, model_hint = MIKROTIK_MAC_PREFIXES[prefix]
            result["device_type"] = device_type
            result["device_category"] = category
            result["model"] = model_hint
            result["confidence"] = 0.70

    # 2. Check service banners for model detection
    if banners:
        banner_text = " ".join(banners)

        for pattern, model, device_type, firmware in MIKROTIK_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                result["model"] = model
                result["device_type"] = device_type
                result["firmware_hint"] = firmware
                result["confidence"] = max(result["confidence"], 0.90)
                break

    # 3. Check hostname
    if hostname:
        hostname_upper = hostname.upper()

        for pattern, model, device_type, firmware in MIKROTIK_BANNER_PATTERNS:
            if re.search(pattern, hostname_upper, re.IGNORECASE):
                result["model"] = model
                result["device_type"] = device_type
                result["firmware_hint"] = firmware
                result["confidence"] = max(result["confidence"], 0.85)
                break

    return result


def enrich_vendor_device(
    manufacturer: str,
    mac_address: Optional[str] = None,
    banners: Optional[List[str]] = None,
    hostname: Optional[str] = None,
    open_ports: Optional[List[int]] = None,
    kernel_version: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Main entry point for vendor-specific device enrichment.

    Routes to the appropriate vendor enrichment function based on manufacturer.

    Args:
        manufacturer: Device manufacturer name
        mac_address: Device MAC address
        banners: List of service banners
        hostname: Device hostname
        open_ports: List of open ports
        kernel_version: Detected kernel version

    Returns:
        Dict with enriched device info, or None if no enrichment available
    """
    if not manufacturer:
        return None

    manufacturer_lower = manufacturer.lower()

    # Ubiquiti
    if any(name in manufacturer_lower for name in ["ubiquiti", "ubnt", "unifi"]):
        return enrich_ubiquiti_device(
            mac_address=mac_address,
            banners=banners,
            hostname=hostname,
            open_ports=open_ports,
            kernel_version=kernel_version,
        )

    # MikroTik
    if "mikrotik" in manufacturer_lower:
        return enrich_mikrotik_device(
            mac_address=mac_address,
            banners=banners,
            hostname=hostname,
        )

    # Cisco
    if any(name in manufacturer_lower for name in ["cisco", "meraki"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            CISCO_MAC_PREFIXES, CISCO_BANNER_PATTERNS
        )

    # Aruba / HPE Networking
    if any(name in manufacturer_lower for name in ["aruba", "hpe aruba"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            ARUBA_MAC_PREFIXES, ARUBA_BANNER_PATTERNS
        )

    # Fortinet
    if any(name in manufacturer_lower for name in ["fortinet", "fortigate", "fortiap"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            FORTINET_MAC_PREFIXES, FORTINET_BANNER_PATTERNS
        )

    # Synology
    if "synology" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SYNOLOGY_MAC_PREFIXES, SYNOLOGY_BANNER_PATTERNS
        )

    # QNAP
    if "qnap" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            QNAP_MAC_PREFIXES, QNAP_BANNER_PATTERNS
        )

    # TP-Link
    if "tp-link" in manufacturer_lower or "tplink" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            TPLINK_MAC_PREFIXES, TPLINK_BANNER_PATTERNS
        )

    # Netgear
    if "netgear" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            NETGEAR_MAC_PREFIXES, NETGEAR_BANNER_PATTERNS
        )

    # Hikvision
    if "hikvision" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            HIKVISION_MAC_PREFIXES, HIKVISION_BANNER_PATTERNS
        )

    # Dahua
    if "dahua" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            DAHUA_MAC_PREFIXES, DAHUA_BANNER_PATTERNS
        )

    # Ruckus
    if any(name in manufacturer_lower for name in ["ruckus", "commscope"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            RUCKUS_MAC_PREFIXES, RUCKUS_BANNER_PATTERNS
        )

    # Juniper
    if "juniper" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            JUNIPER_MAC_PREFIXES, JUNIPER_BANNER_PATTERNS
        )

    # Dell
    if any(name in manufacturer_lower for name in ["dell", "dell emc"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            DELL_MAC_PREFIXES, DELL_BANNER_PATTERNS
        )

    # HPE (HP Enterprise)
    if any(name in manufacturer_lower for name in ["hewlett packard enterprise", "hpe", "hp enterprise"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            HPE_MAC_PREFIXES, HPE_BANNER_PATTERNS
        )

    # Axis Communications
    if "axis" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            AXIS_MAC_PREFIXES, AXIS_BANNER_PATTERNS
        )

    # Palo Alto Networks
    if any(name in manufacturer_lower for name in ["palo alto", "paloalto"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            PALOALTO_MAC_PREFIXES, PALOALTO_BANNER_PATTERNS
        )

    # Sophos
    if "sophos" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SOPHOS_MAC_PREFIXES, SOPHOS_BANNER_PATTERNS
        )

    # WatchGuard
    if "watchguard" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            WATCHGUARD_MAC_PREFIXES, WATCHGUARD_BANNER_PATTERNS
        )

    # Extreme Networks
    if any(name in manufacturer_lower for name in ["extreme", "aerohive"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            EXTREME_MAC_PREFIXES, EXTREME_BANNER_PATTERNS
        )

    # VMware
    if "vmware" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            VMWARE_MAC_PREFIXES, VMWARE_BANNER_PATTERNS
        )

    # Nutanix
    if "nutanix" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            NUTANIX_MAC_PREFIXES, NUTANIX_BANNER_PATTERNS
        )

    # XCP-ng / Xen (open-source Xen hypervisor)
    if any(name in manufacturer_lower for name in ["xcp-ng", "xcp ng", "xen project", "xen hypervisor"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            XCPNG_MAC_PREFIXES, XCPNG_BANNER_PATTERNS
        )

    # Citrix (XenServer, ADC/NetScaler, Virtual Apps & Desktops)
    if any(name in manufacturer_lower for name in ["citrix", "xenserver", "netscaler"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            CITRIX_MAC_PREFIXES, CITRIX_BANNER_PATTERNS
        )

    # Oracle VM / VirtualBox
    if any(name in manufacturer_lower for name in ["oracle vm", "virtualbox", "oracle linux virtualization", "oracle corporation", "oracle"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            ORACLE_VM_MAC_PREFIXES, ORACLE_VM_BANNER_PATTERNS
        )

    # Banner-only virtualization detection (no MAC prefixes)
    if banners:
        banner_text = " ".join(banners)

        # oVirt / Red Hat Virtualization
        for pattern, model, device_type, firmware in OVIRT_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Virtualization",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

        # OpenStack
        for pattern, model, device_type, firmware in OPENSTACK_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Cloud Platform",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

        # Microsoft Hyper-V
        for pattern, model, device_type, firmware in HYPERV_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Virtualization",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

        # KVM / QEMU / libvirt
        for pattern, model, device_type, firmware in KVM_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Virtualization",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

        # Microsoft Azure
        for pattern, model, device_type, firmware in AZURE_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Cloud Platform",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

        # Container orchestration (Kubernetes, Docker Swarm, EKS, GKE, etc.)
        for pattern, model, device_type, firmware in CONTAINER_ORCH_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Container Platform",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.88,
                }

    # Apple
    if "apple" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            APPLE_MAC_PREFIXES, APPLE_BANNER_PATTERNS
        )

    # Samsung
    if "samsung" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SAMSUNG_MAC_PREFIXES, SAMSUNG_BANNER_PATTERNS
        )

    # LG
    if any(name in manufacturer_lower for name in ["lg electronics", "lg "]):
        return _generic_enrich(
            mac_address, banners, hostname,
            LG_MAC_PREFIXES, LG_BANNER_PATTERNS
        )

    # Honeywell
    if "honeywell" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            HONEYWELL_MAC_PREFIXES, HONEYWELL_BANNER_PATTERNS
        )

    # Schneider Electric (includes APC)
    if any(name in manufacturer_lower for name in ["schneider", "apc"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            SCHNEIDER_MAC_PREFIXES, SCHNEIDER_BANNER_PATTERNS
        )

    # Siemens
    if "siemens" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SIEMENS_MAC_PREFIXES, SIEMENS_BANNER_PATTERNS
        )

    # Allen-Bradley / Rockwell
    if any(name in manufacturer_lower for name in ["allen-bradley", "rockwell"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            ALLEN_BRADLEY_MAC_PREFIXES, ALLEN_BRADLEY_BANNER_PATTERNS
        )

    # Amazon (Echo, Ring, Blink, eero)
    if any(name in manufacturer_lower for name in ["amazon", "ring", "blink", "eero"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            AMAZON_MAC_PREFIXES, AMAZON_BANNER_PATTERNS
        )

    # Google (Nest, Chromecast)
    if any(name in manufacturer_lower for name in ["google", "nest"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            GOOGLE_MAC_PREFIXES, GOOGLE_BANNER_PATTERNS
        )

    # Proxmox (check banners directly - no MAC prefix)
    if banners:
        banner_text = " ".join(banners)
        for pattern, model, device_type, firmware in PROXMOX_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Virtualization",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

    # pfSense (check banners directly)
    if banners:
        banner_text = " ".join(banners)
        for pattern, model, device_type, firmware in PFSENSE_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Network Equipment",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }
        for pattern, model, device_type, firmware in OPNSENSE_BANNER_PATTERNS:
            if re.search(pattern, banner_text, re.IGNORECASE):
                return {
                    "device_type": device_type,
                    "device_category": "Network Equipment",
                    "model": model,
                    "firmware_hint": firmware,
                    "confidence": 0.90,
                }

    # Sonos
    if "sonos" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SONOS_MAC_PREFIXES, SONOS_BANNER_PATTERNS
        )

    # Roku
    if "roku" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ROKU_MAC_PREFIXES, ROKU_BANNER_PATTERNS
        )

    # Philips Hue / Signify
    if any(name in manufacturer_lower for name in ["philips", "signify", "hue"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            PHILIPS_HUE_MAC_PREFIXES, PHILIPS_HUE_BANNER_PATTERNS
        )

    # Wyze
    if "wyze" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            WYZE_MAC_PREFIXES, WYZE_BANNER_PATTERNS
        )

    # Canon (printers/cameras)
    if "canon" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CANON_MAC_PREFIXES, CANON_BANNER_PATTERNS
        )

    # Epson
    if "epson" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            EPSON_MAC_PREFIXES, EPSON_BANNER_PATTERNS
        )

    # Brother
    if "brother" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            BROTHER_MAC_PREFIXES, BROTHER_BANNER_PATTERNS
        )

    # HP Printers (distinct from HPE enterprise)
    if any(name in manufacturer_lower for name in ["hewlett-packard", "hp inc"]) and "enterprise" not in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            HP_PRINTER_MAC_PREFIXES, HP_PRINTER_BANNER_PATTERNS
        )

    # Polycom (VoIP)
    if any(name in manufacturer_lower for name in ["polycom", "poly"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            POLYCOM_MAC_PREFIXES, POLYCOM_BANNER_PATTERNS
        )

    # Yealink (VoIP)
    if "yealink" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            YEALINK_MAC_PREFIXES, YEALINK_BANNER_PATTERNS
        )

    # Cisco VoIP phones (separate from network gear)
    # Note: This should come after main Cisco routing - use if specific VoIP patterns detected
    # The main Cisco routing handles most cases

    # Crestron (AV control)
    if "crestron" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CRESTRON_MAC_PREFIXES, CRESTRON_BANNER_PATTERNS
        )

    # Extron (AV control)
    if "extron" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            EXTRON_MAC_PREFIXES, EXTRON_BANNER_PATTERNS
        )

    # Raspberry Pi Foundation
    if any(name in manufacturer_lower for name in ["raspberry", "raspberry pi"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            RASPBERRY_PI_MAC_PREFIXES, RASPBERRY_PI_BANNER_PATTERNS
        )

    # Espressif (ESP32/ESP8266 IoT modules)
    if "espressif" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ESPRESSIF_MAC_PREFIXES, ESPRESSIF_BANNER_PATTERNS
        )

    # Tesla (vehicles and wall connectors)
    if "tesla" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            TESLA_MAC_PREFIXES, TESLA_BANNER_PATTERNS
        )

    # ChargePoint (EV chargers)
    if "chargepoint" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CHARGEPOINT_MAC_PREFIXES, CHARGEPOINT_BANNER_PATTERNS
        )

    # Zebra Technologies (barcode scanners, mobile computers)
    if any(name in manufacturer_lower for name in ["zebra", "symbol"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            ZEBRA_MAC_PREFIXES, ZEBRA_BANNER_PATTERNS
        )

    # Lenovo
    if "lenovo" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            LENOVO_MAC_PREFIXES, LENOVO_BANNER_PATTERNS
        )

    # ASUS
    if "asus" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ASUS_MAC_PREFIXES, ASUS_BANNER_PATTERNS
        )

    # Security Camera Vendors

    # Reolink
    if "reolink" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            REOLINK_MAC_PREFIXES, REOLINK_BANNER_PATTERNS
        )

    # Amcrest
    if "amcrest" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            AMCREST_MAC_PREFIXES, AMCREST_BANNER_PATTERNS
        )

    # Lorex
    if "lorex" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            LOREX_MAC_PREFIXES, LOREX_BANNER_PATTERNS
        )

    # VIVOTEK
    if "vivotek" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            VIVOTEK_MAC_PREFIXES, VIVOTEK_BANNER_PATTERNS
        )

    # Hanwha / Samsung Wisenet
    if any(name in manufacturer_lower for name in ["hanwha", "wisenet", "samsung techwin"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            HANWHA_MAC_PREFIXES, HANWHA_BANNER_PATTERNS
        )

    # Foscam
    if "foscam" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            FOSCAM_MAC_PREFIXES, FOSCAM_BANNER_PATTERNS
        )

    # Arlo
    if "arlo" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ARLO_MAC_PREFIXES, ARLO_BANNER_PATTERNS
        )

    # eufy (Anker)
    if any(name in manufacturer_lower for name in ["eufy", "anker"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            EUFY_MAC_PREFIXES, EUFY_BANNER_PATTERNS
        )

    # Bosch Security
    if "bosch" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            BOSCH_MAC_PREFIXES, BOSCH_BANNER_PATTERNS
        )

    # Uniview
    if any(name in manufacturer_lower for name in ["uniview", "unv"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            UNIVIEW_MAC_PREFIXES, UNIVIEW_BANNER_PATTERNS
        )

    # Pelco
    if "pelco" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            PELCO_MAC_PREFIXES, PELCO_BANNER_PATTERNS
        )

    # GeoVision
    if "geovision" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            GEOVISION_MAC_PREFIXES, GEOVISION_BANNER_PATTERNS
        )

    # MOBOTIX
    if "mobotix" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            MOBOTIX_MAC_PREFIXES, MOBOTIX_BANNER_PATTERNS
        )

    # Avigilon
    if "avigilon" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            AVIGILON_MAC_PREFIXES, AVIGILON_BANNER_PATTERNS
        )

    # Verkada
    if "verkada" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            VERKADA_MAC_PREFIXES, VERKADA_BANNER_PATTERNS
        )

    # TV Vendors

    # Sony (TV/PlayStation)
    if "sony" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SONY_TV_MAC_PREFIXES, SONY_TV_BANNER_PATTERNS
        )

    # Vizio
    if "vizio" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            VIZIO_MAC_PREFIXES, VIZIO_BANNER_PATTERNS
        )

    # TCL
    if "tcl" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            TCL_MAC_PREFIXES, TCL_BANNER_PATTERNS
        )

    # Hisense
    if "hisense" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            HISENSE_MAC_PREFIXES, HISENSE_BANNER_PATTERNS
        )

    # IoT / Smart Home Vendors

    # ecobee
    if "ecobee" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ECOBEE_MAC_PREFIXES, ECOBEE_BANNER_PATTERNS
        )

    # Nest (Google Nest) - separate from main Google
    if "nest" in manufacturer_lower and "google" not in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            NEST_MAC_PREFIXES, NEST_BANNER_PATTERNS
        )

    # Ring
    if "ring" in manufacturer_lower and "amazon" not in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            RING_MAC_PREFIXES, RING_BANNER_PATTERNS
        )

    # Lutron
    if "lutron" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            LUTRON_MAC_PREFIXES, LUTRON_BANNER_PATTERNS
        )

    # Control4
    if "control4" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CONTROL4_MAC_PREFIXES, CONTROL4_BANNER_PATTERNS
        )

    # Savant
    if "savant" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SAVANT_MAC_PREFIXES, SAVANT_BANNER_PATTERNS
        )

    # Wemo (Belkin)
    if any(name in manufacturer_lower for name in ["wemo", "belkin"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            WEMO_MAC_PREFIXES, WEMO_BANNER_PATTERNS
        )

    # Tuya
    if "tuya" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            TUYA_MAC_PREFIXES, TUYA_BANNER_PATTERNS
        )

    # Kasa (TP-Link Smart Home)
    if "kasa" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            KASA_MAC_PREFIXES, KASA_BANNER_PATTERNS
        )

    # Network Equipment Vendors

    # Arista Networks
    if "arista" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ARISTA_MAC_PREFIXES, ARISTA_BANNER_PATTERNS
        )

    # Brocade
    if "brocade" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            BROCADE_MAC_PREFIXES, BROCADE_BANNER_PATTERNS
        )

    # Allied Telesis
    if "allied telesis" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ALLIED_TELESIS_MAC_PREFIXES, ALLIED_TELESIS_BANNER_PATTERNS
        )

    # DrayTek
    if "draytek" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            DRAYTEK_MAC_PREFIXES, DRAYTEK_BANNER_PATTERNS
        )

    # Peplink/Pepwave
    if any(name in manufacturer_lower for name in ["peplink", "pepwave"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            PEPLINK_MAC_PREFIXES, PEPLINK_BANNER_PATTERNS
        )

    # Cambium Networks
    if "cambium" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CAMBIUM_MAC_PREFIXES, CAMBIUM_BANNER_PATTERNS
        )

    # Server / Hardware Vendors

    # Supermicro
    if "supermicro" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SUPERMICRO_MAC_PREFIXES, SUPERMICRO_BANNER_PATTERNS
        )

    # Inspur
    if "inspur" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            INSPUR_MAC_PREFIXES, INSPUR_BANNER_PATTERNS
        )

    # Lenovo Servers (ThinkSystem) - check before regular Lenovo
    if "lenovo" in manufacturer_lower:
        # Check for server-specific terms
        if banners:
            banner_text = " ".join(banners).lower()
            if any(term in banner_text for term in ["thinksystem", "thinkagile", "xclarity"]):
                return _generic_enrich(
                    mac_address, banners, hostname,
                    LENOVO_SERVER_MAC_PREFIXES, LENOVO_SERVER_BANNER_PATTERNS
                )
        # Fall through to regular Lenovo (already handled above)

    # Fujitsu Servers
    if "fujitsu" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            FUJITSU_MAC_PREFIXES, FUJITSU_BANNER_PATTERNS
        )

    # Huawei
    if "huawei" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            HUAWEI_MAC_PREFIXES, HUAWEI_BANNER_PATTERNS
        )

    # ZTE
    if "zte" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            ZTE_MAC_PREFIXES, ZTE_BANNER_PATTERNS
        )

    # Mellanox / NVIDIA Networking
    if any(name in manufacturer_lower for name in ["mellanox", "nvidia"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            MELLANOX_MAC_PREFIXES, MELLANOX_BANNER_PATTERNS
        )

    # GAMING CONSOLES

    # Sony PlayStation
    if any(name in manufacturer_lower for name in ["sony", "playstation", "scei"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            PLAYSTATION_MAC_PREFIXES, PLAYSTATION_BANNER_PATTERNS
        )

    # Microsoft Xbox
    if any(name in manufacturer_lower for name in ["xbox"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            XBOX_MAC_PREFIXES, XBOX_BANNER_PATTERNS
        )

    # Nintendo
    if "nintendo" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            NINTENDO_MAC_PREFIXES, NINTENDO_BANNER_PATTERNS
        )

    # Valve / Steam
    if any(name in manufacturer_lower for name in ["valve", "steam"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            VALVE_MAC_PREFIXES, VALVE_BANNER_PATTERNS
        )

    # POINT OF SALE (POS)

    # Verifone
    if "verifone" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            VERIFONE_MAC_PREFIXES, VERIFONE_BANNER_PATTERNS
        )

    # Ingenico
    if "ingenico" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            INGENICO_MAC_PREFIXES, INGENICO_BANNER_PATTERNS
        )

    # Square
    if "square" in manufacturer_lower and "enix" not in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SQUARE_MAC_PREFIXES, SQUARE_BANNER_PATTERNS
        )

    # NCR
    if "ncr" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            NCR_MAC_PREFIXES, NCR_BANNER_PATTERNS
        )

    # Clover
    if "clover" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CLOVER_MAC_PREFIXES, CLOVER_BANNER_PATTERNS
        )

    # PAX Technology
    if "pax" in manufacturer_lower and "technology" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            PAX_MAC_PREFIXES, PAX_BANNER_PATTERNS
        )

    # MEDICAL / HEALTHCARE

    # GE Healthcare
    if any(name in manufacturer_lower for name in ["ge healthcare", "general electric healthcare"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            GE_HEALTHCARE_MAC_PREFIXES, GE_HEALTHCARE_BANNER_PATTERNS
        )

    # Philips Healthcare (not Hue)
    if "philips" in manufacturer_lower and any(term in manufacturer_lower for term in ["healthcare", "medical"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            PHILIPS_HEALTHCARE_MAC_PREFIXES, PHILIPS_HEALTHCARE_BANNER_PATTERNS
        )

    # Medtronic
    if "medtronic" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            MEDTRONIC_MAC_PREFIXES, MEDTRONIC_BANNER_PATTERNS
        )

    # Draeger
    if any(name in manufacturer_lower for name in ["draeger", "dräger", "drager"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            DRAEGER_MAC_PREFIXES, DRAEGER_BANNER_PATTERNS
        )

    # Baxter
    if "baxter" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            BAXTER_MAC_PREFIXES, BAXTER_BANNER_PATTERNS
        )

    # BUILDING AUTOMATION / HVAC

    # Johnson Controls
    if any(name in manufacturer_lower for name in ["johnson controls", "jci", "metasys"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            JOHNSON_CONTROLS_MAC_PREFIXES, JOHNSON_CONTROLS_BANNER_PATTERNS
        )

    # Trane
    if "trane" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            TRANE_MAC_PREFIXES, TRANE_BANNER_PATTERNS
        )

    # Carrier
    if "carrier" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            CARRIER_MAC_PREFIXES, CARRIER_BANNER_PATTERNS
        )

    # Honeywell Building (separate from consumer Honeywell)
    if "honeywell" in manufacturer_lower:
        # Check for building automation terms
        if banners:
            banner_text = " ".join(banners).lower()
            if any(term in banner_text for term in ["webs", "niagara", "jace", "ebi", "spyder"]):
                return _generic_enrich(
                    mac_address, banners, hostname,
                    HONEYWELL_BUILDING_MAC_PREFIXES, HONEYWELL_BUILDING_BANNER_PATTERNS
                )
        # Fall through to regular Honeywell if already defined

    # ENTERPRISE NETWORKING

    # F5 Networks
    if any(name in manufacturer_lower for name in ["f5", "big-ip", "bigip"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            F5_MAC_PREFIXES, F5_BANNER_PATTERNS
        )

    # A10 Networks
    if "a10" in manufacturer_lower and "network" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            A10_MAC_PREFIXES, A10_BANNER_PATTERNS
        )

    # Barracuda Networks
    if "barracuda" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            BARRACUDA_MAC_PREFIXES, BARRACUDA_BANNER_PATTERNS
        )

    # Alcatel-Lucent Enterprise
    if any(name in manufacturer_lower for name in ["alcatel", "ale", "omniswitch"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            ALE_MAC_PREFIXES, ALE_BANNER_PATTERNS
        )

    # Riverbed
    if any(name in manufacturer_lower for name in ["riverbed", "steelhead"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            RIVERBED_MAC_PREFIXES, RIVERBED_BANNER_PATTERNS
        )

    # ATM / KIOSK / FINANCIAL

    # Diebold Nixdorf
    if any(name in manufacturer_lower for name in ["diebold", "nixdorf"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            DIEBOLD_MAC_PREFIXES, DIEBOLD_BANNER_PATTERNS
        )

    # Wincor
    if "wincor" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            WINCOR_MAC_PREFIXES, WINCOR_BANNER_PATTERNS
        )

    # Hyosung
    if any(name in manufacturer_lower for name in ["hyosung", "nautilus"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            HYOSUNG_MAC_PREFIXES, HYOSUNG_BANNER_PATTERNS
        )

    # AUDIO / CONSUMER ELECTRONICS

    # JBL / Harman (check hostname for .harman.com domain as well)
    if any(name in manufacturer_lower for name in ["jbl", "harman"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            JBL_MAC_PREFIXES, JBL_BANNER_PATTERNS
        )

    # Check hostname for Harman domain (high-priority override)
    if hostname and "harman.com" in hostname.lower():
        return _generic_enrich(
            mac_address, banners, hostname,
            JBL_MAC_PREFIXES, JBL_BANNER_PATTERNS
        )

    # Harman Kardon
    if "harman kardon" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            HARMAN_KARDON_MAC_PREFIXES, HARMAN_KARDON_BANNER_PATTERNS
        )

    # Sonos
    if "sonos" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            SONOS_MAC_PREFIXES, SONOS_BANNER_PATTERNS
        )

    # Bose
    if "bose" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            BOSE_MAC_PREFIXES, BOSE_BANNER_PATTERNS
        )

    # Marshall
    if "marshall" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            MARSHALL_MAC_PREFIXES, MARSHALL_BANNER_PATTERNS
        )

    # Bang & Olufsen
    if any(name in manufacturer_lower for name in ["bang", "olufsen", "b&o", "beoplay", "beosound"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            BANG_OLUFSEN_MAC_PREFIXES, BANG_OLUFSEN_BANNER_PATTERNS
        )

    # Denon
    if any(name in manufacturer_lower for name in ["denon", "heos"]):
        return _generic_enrich(
            mac_address, banners, hostname,
            DENON_MAC_PREFIXES, DENON_BANNER_PATTERNS
        )

    # Yamaha Audio
    if "yamaha" in manufacturer_lower:
        return _generic_enrich(
            mac_address, banners, hostname,
            YAMAHA_AUDIO_MAC_PREFIXES, YAMAHA_AUDIO_BANNER_PATTERNS
        )

    return None


def _generic_enrich(
    mac_address: Optional[str],
    banners: Optional[List[str]],
    hostname: Optional[str],
    mac_prefixes: Dict[str, Tuple[str, str, Optional[str]]],
    banner_patterns: List[Tuple[str, str, str, Optional[str]]],
) -> Dict[str, Any]:
    """
    Generic enrichment function for vendors that follow the standard pattern.

    Args:
        mac_address: Device MAC address
        banners: List of service banners
        hostname: Device hostname
        mac_prefixes: Dict mapping MAC prefixes to (device_type, category, model_hint)
        banner_patterns: List of (pattern, model, device_type, firmware) tuples

    Returns:
        Dict with device_type, model, firmware_hint, confidence
    """
    result = {
        "device_type": None,
        "device_category": None,
        "model": None,
        "firmware_hint": None,
        "confidence": 0.0,
    }

    # 1. Check MAC OUI prefix
    if mac_address:
        mac_upper = mac_address.upper().replace("-", ":")
        prefix = mac_upper[:8]

        if prefix in mac_prefixes:
            device_type, category, model_hint = mac_prefixes[prefix]
            result["device_type"] = device_type
            result["device_category"] = category
            result["model"] = model_hint
            result["confidence"] = 0.70

    # 2. Check service banners for model detection
    if banners:
        banner_text = " ".join(banners)

        for pattern, model, device_type, firmware in banner_patterns:
            if re.search(pattern, banner_text, re.IGNORECASE):
                result["model"] = model
                result["device_type"] = device_type
                result["firmware_hint"] = firmware
                result["confidence"] = max(result["confidence"], 0.90)
                break

    # 3. Check hostname for model hints
    if hostname and result["confidence"] < 0.90:
        for pattern, model, device_type, firmware in banner_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                result["model"] = model
                result["device_type"] = device_type
                result["firmware_hint"] = firmware
                result["confidence"] = max(result["confidence"], 0.85)
                break

    return result

def load_oui_data(cache_dir=None) -> Dict[str, Dict]:
    """
    Load all OUI/MAC prefix data into a unified dict.

    Merges two sources:
    1. Built-in vendor patterns (higher priority — richer metadata with
       device_type, category, and model hints).
    2. IEEE OUI cache from ``cache_dir/ieee_oui.json`` (86K+ entries
       providing broad manufacturer coverage as a fallback).

    Args:
        cache_dir: Optional path to JSON cache directory (``~/.cache/leetha/``).

    Returns:
        Dict mapping MAC prefix -> {"manufacturer": str, "device_type": str, ...}
    """
    # Aggregate all vendor MAC prefix dicts
    all_vendors = [
        ("ZyXEL", ZYXEL_MAC_PREFIXES),
        ("D-Link", DLINK_MAC_PREFIXES),
        ("Linksys", LINKSYS_MAC_PREFIXES),
        ("Meraki", MERAKI_MAC_PREFIXES),
        ("Buffalo", BUFFALO_MAC_PREFIXES),
        ("Mimosa", MIMOSA_MAC_PREFIXES),
        ("Cradlepoint", CRADLEPOINT_MAC_PREFIXES),
        ("EnGenius", ENGENIUS_MAC_PREFIXES),
        ("Aerohive", AEROHIVE_MAC_PREFIXES),
        ("Ubiquiti", UBIQUITI_MAC_PREFIXES),
        ("MikroTik", MIKROTIK_MAC_PREFIXES),
        ("Cisco", CISCO_MAC_PREFIXES),
        ("Aruba", ARUBA_MAC_PREFIXES),
        ("Fortinet", FORTINET_MAC_PREFIXES),
        ("Synology", SYNOLOGY_MAC_PREFIXES),
        ("QNAP", QNAP_MAC_PREFIXES),
        ("TP-Link", TPLINK_MAC_PREFIXES),
        ("Netgear", NETGEAR_MAC_PREFIXES),
        ("Hikvision", HIKVISION_MAC_PREFIXES),
        ("Dahua", DAHUA_MAC_PREFIXES),
        ("Ruckus", RUCKUS_MAC_PREFIXES),
        ("Juniper", JUNIPER_MAC_PREFIXES),
        ("Dell", DELL_MAC_PREFIXES),
        ("HPE", HPE_MAC_PREFIXES),
        ("Axis", AXIS_MAC_PREFIXES),
        ("Palo Alto", PALOALTO_MAC_PREFIXES),
        ("Sophos", SOPHOS_MAC_PREFIXES),
        ("WatchGuard", WATCHGUARD_MAC_PREFIXES),
        ("Extreme", EXTREME_MAC_PREFIXES),
        ("Check Point", CHECKPOINT_MAC_PREFIXES),
        ("SonicWall", SONICWALL_MAC_PREFIXES),
        ("VMware", VMWARE_MAC_PREFIXES),
        ("QEMU/KVM", QEMU_KVM_MAC_PREFIXES),
        ("Docker", DOCKER_MAC_PREFIXES),
        ("LXC", LXC_MAC_PREFIXES),
        ("Parallels", PARALLELS_MAC_PREFIXES),
        ("bhyve", BHYVE_MAC_PREFIXES),
        ("Firecracker", FIRECRACKER_MAC_PREFIXES),
        ("XCP-ng", XCPNG_MAC_PREFIXES),
        ("Citrix", CITRIX_MAC_PREFIXES),
        ("Nutanix", NUTANIX_MAC_PREFIXES),
        ("Oracle VM", ORACLE_VM_MAC_PREFIXES),
        ("NetApp", NETAPP_MAC_PREFIXES),
        ("EMC", EMC_MAC_PREFIXES),
        ("Pure Storage", PURE_MAC_PREFIXES),
        ("Asustor", ASUSTOR_MAC_PREFIXES),
        ("TerraMaster", TERRAMASTER_MAC_PREFIXES),
        ("Apple", APPLE_MAC_PREFIXES),
        ("Samsung", SAMSUNG_MAC_PREFIXES),
        ("LG", LG_MAC_PREFIXES),
        ("Honeywell", HONEYWELL_MAC_PREFIXES),
        ("Schneider Electric", SCHNEIDER_MAC_PREFIXES),
        ("Siemens", SIEMENS_MAC_PREFIXES),
        ("Allen-Bradley", ALLEN_BRADLEY_MAC_PREFIXES),
        ("ABB", ABB_MAC_PREFIXES),
        ("Omron", OMRON_MAC_PREFIXES),
        ("Mitsubishi", MITSUBISHI_MAC_PREFIXES),
        ("Beckhoff", BECKHOFF_MAC_PREFIXES),
        ("Phoenix Contact", PHOENIX_CONTACT_MAC_PREFIXES),
        ("AMX", AMX_MAC_PREFIXES),
        ("Biamp", BIAMP_MAC_PREFIXES),
        ("Barco", BARCO_MAC_PREFIXES),
        ("Christie", CHRISTIE_MAC_PREFIXES),
        ("NEC Display", NEC_DISPLAY_MAC_PREFIXES),
        ("Crestron", CRESTRON_MAC_PREFIXES),
        ("Extron", EXTRON_MAC_PREFIXES),
        ("QSC", QSYS_MAC_PREFIXES),
        ("NVIDIA Jetson", NVIDIA_JETSON_MAC_PREFIXES),
        ("Arduino", ARDUINO_MAC_PREFIXES),
        ("BeagleBone", BEAGLEBONE_MAC_PREFIXES),
        ("Espressif", ESPRESSIF_MAC_PREFIXES),
        ("MSI", MSI_MAC_PREFIXES),
        ("Acer", ACER_MAC_PREFIXES),
        ("Microsoft", MICROSOFT_MAC_PREFIXES),
        ("ChargePoint", CHARGEPOINT_MAC_PREFIXES),
        ("Tesla Wall Connector", TESLA_WALL_MAC_PREFIXES),
        ("JuiceBox", JUICEBOX_MAC_PREFIXES),
        ("Wallbox", WALLBOX_MAC_PREFIXES),
        ("Clipper Creek", CLIPPER_CREEK_MAC_PREFIXES),
        ("Datalogic", DATALOGIC_MAC_PREFIXES),
        ("Honeywell Scanner", HONEYWELL_SCANNER_MAC_PREFIXES),
        ("Zebra Scanner", ZEBRA_SCANNER_MAC_PREFIXES),
        ("Symbol", SYMBOL_MAC_PREFIXES),
        ("Amazon", AMAZON_MAC_PREFIXES),
        ("Google", GOOGLE_MAC_PREFIXES),
        ("Sonos", SONOS_MAC_PREFIXES),
        ("Roku", ROKU_MAC_PREFIXES),
        ("Philips Hue", PHILIPS_HUE_MAC_PREFIXES),
        ("Wyze", WYZE_MAC_PREFIXES),
        ("Canon", CANON_MAC_PREFIXES),
        ("Epson", EPSON_MAC_PREFIXES),
        ("Brother", BROTHER_MAC_PREFIXES),
        ("HP Printer", HP_PRINTER_MAC_PREFIXES),
        ("Xerox", XEROX_MAC_PREFIXES),
        ("Lexmark", LEXMARK_MAC_PREFIXES),
        ("Kyocera", KYOCERA_MAC_PREFIXES),
        ("Ricoh", RICOH_MAC_PREFIXES),
        ("Konica Minolta", KONICA_MAC_PREFIXES),
        ("Polycom", POLYCOM_MAC_PREFIXES),
        ("Yealink", YEALINK_MAC_PREFIXES),
        ("Cisco VoIP", CISCO_VOIP_MAC_PREFIXES),
        ("Grandstream", GRANDSTREAM_MAC_PREFIXES),
        ("Avaya", AVAYA_MAC_PREFIXES),
        ("Mitel", MITEL_MAC_PREFIXES),
        ("Raspberry Pi", RASPBERRY_PI_MAC_PREFIXES),
        ("Tesla", TESLA_MAC_PREFIXES),
        ("Zebra", ZEBRA_MAC_PREFIXES),
        ("Lenovo", LENOVO_MAC_PREFIXES),
        ("ASUS", ASUS_MAC_PREFIXES),
        ("Reolink", REOLINK_MAC_PREFIXES),
        ("Amcrest", AMCREST_MAC_PREFIXES),
        ("Lorex", LOREX_MAC_PREFIXES),
        ("Vivotek", VIVOTEK_MAC_PREFIXES),
        ("Hanwha", HANWHA_MAC_PREFIXES),
        ("Foscam", FOSCAM_MAC_PREFIXES),
        ("Arlo", ARLO_MAC_PREFIXES),
        ("Eufy", EUFY_MAC_PREFIXES),
        ("Bosch", BOSCH_MAC_PREFIXES),
        ("Uniview", UNIVIEW_MAC_PREFIXES),
        ("Pelco", PELCO_MAC_PREFIXES),
        ("GeoVision", GEOVISION_MAC_PREFIXES),
        ("Mobotix", MOBOTIX_MAC_PREFIXES),
        ("Avigilon", AVIGILON_MAC_PREFIXES),
        ("Verkada", VERKADA_MAC_PREFIXES),
        ("Sony TV", SONY_TV_MAC_PREFIXES),
        ("Vizio", VIZIO_MAC_PREFIXES),
        ("TCL", TCL_MAC_PREFIXES),
        ("Hisense", HISENSE_MAC_PREFIXES),
        ("Shelly", SHELLY_MAC_PREFIXES),
        ("Sonoff", SONOFF_MAC_PREFIXES),
        ("Nanoleaf", NANOLEAF_MAC_PREFIXES),
        ("Govee", GOVEE_MAC_PREFIXES),
        ("Insteon", INSTEON_MAC_PREFIXES),
        ("Ecovacs", ECOVACS_MAC_PREFIXES),
        ("iRobot", IROBOT_MAC_PREFIXES),
        ("Roborock", ROBOROCK_MAC_PREFIXES),
        ("Dyson", DYSON_MAC_PREFIXES),
        ("Xiaomi", XIAOMI_MAC_PREFIXES),
        ("OnePlus", ONEPLUS_MAC_PREFIXES),
        ("Oppo", OPPO_MAC_PREFIXES),
        ("Vivo", VIVO_MAC_PREFIXES),
        ("Realme", REALME_MAC_PREFIXES),
        ("Honor", HONOR_MAC_PREFIXES),
        ("Nothing", NOTHING_MAC_PREFIXES),
        ("Pixel", PIXEL_MAC_PREFIXES),
        ("Sony Mobile", SONY_MOBILE_MAC_PREFIXES),
        ("LG Mobile", LG_MOBILE_MAC_PREFIXES),
        ("HTC", HTC_MAC_PREFIXES),
        ("Infinix", INFINIX_MAC_PREFIXES),
        ("Tecno", TECNO_MAC_PREFIXES),
        ("Meizu", MEIZU_MAC_PREFIXES),
        ("ASUS Mobile", ASUS_MOBILE_MAC_PREFIXES),
        ("Lenovo Mobile", LENOVO_MOBILE_MAC_PREFIXES),
        ("Bose", BOSE_MAC_PREFIXES),
        ("Logitech", LOGITECH_MAC_PREFIXES),
        ("Chromecast", CHROMECAST_MAC_PREFIXES),
        ("Ecobee", ECOBEE_MAC_PREFIXES),
        ("Nest", NEST_MAC_PREFIXES),
        ("Ring", RING_MAC_PREFIXES),
        ("Lutron", LUTRON_MAC_PREFIXES),
        ("Control4", CONTROL4_MAC_PREFIXES),
        ("Savant", SAVANT_MAC_PREFIXES),
        ("Wemo", WEMO_MAC_PREFIXES),
        ("Tuya", TUYA_MAC_PREFIXES),
        ("Kasa", KASA_MAC_PREFIXES),
        ("Arista", ARISTA_MAC_PREFIXES),
        ("Brocade", BROCADE_MAC_PREFIXES),
        ("Allied Telesis", ALLIED_TELESIS_MAC_PREFIXES),
        ("DrayTek", DRAYTEK_MAC_PREFIXES),
        ("Peplink", PEPLINK_MAC_PREFIXES),
        ("Cambium", CAMBIUM_MAC_PREFIXES),
        ("Dell Wyse", DELL_WYSE_MAC_PREFIXES),
        ("IGEL", IGEL_MAC_PREFIXES),
        ("Fitbit", FITBIT_MAC_PREFIXES),
        ("Garmin", GARMIN_MAC_PREFIXES),
        ("Withings", WITHINGS_MAC_PREFIXES),
        ("Oura", OURA_MAC_PREFIXES),
        ("Peloton", PELOTON_MAC_PREFIXES),
        ("Motorola", MOTOROLA_MAC_PREFIXES),
        ("Nokia", NOKIA_MAC_PREFIXES),
        ("Ericsson", ERICSSON_MAC_PREFIXES),
        ("Intel", INTEL_MAC_PREFIXES),
        ("AMD", AMD_MAC_PREFIXES),
        ("ASRock", ASROCK_MAC_PREFIXES),
        ("Gigabyte", GIGABYTE_MAC_PREFIXES),
        ("NVIDIA", NVIDIA_MAC_PREFIXES),
        ("Supermicro", SUPERMICRO_MAC_PREFIXES),
        ("Inspur", INSPUR_MAC_PREFIXES),
        ("Lenovo Server", LENOVO_SERVER_MAC_PREFIXES),
        ("Fujitsu", FUJITSU_MAC_PREFIXES),
        ("Huawei", HUAWEI_MAC_PREFIXES),
        ("ZTE", ZTE_MAC_PREFIXES),
        ("Mellanox", MELLANOX_MAC_PREFIXES),
        ("PlayStation", PLAYSTATION_MAC_PREFIXES),
        ("Xbox", XBOX_MAC_PREFIXES),
        ("Nintendo", NINTENDO_MAC_PREFIXES),
        ("Valve", VALVE_MAC_PREFIXES),
        ("VeriFone", VERIFONE_MAC_PREFIXES),
        ("Ingenico", INGENICO_MAC_PREFIXES),
        ("Square", SQUARE_MAC_PREFIXES),
        ("NCR", NCR_MAC_PREFIXES),
        ("Clover", CLOVER_MAC_PREFIXES),
        ("PAX", PAX_MAC_PREFIXES),
        ("GE Healthcare", GE_HEALTHCARE_MAC_PREFIXES),
        ("Philips Healthcare", PHILIPS_HEALTHCARE_MAC_PREFIXES),
        ("Medtronic", MEDTRONIC_MAC_PREFIXES),
        ("Draeger", DRAEGER_MAC_PREFIXES),
        ("Baxter", BAXTER_MAC_PREFIXES),
        ("Johnson Controls", JOHNSON_CONTROLS_MAC_PREFIXES),
        ("Trane", TRANE_MAC_PREFIXES),
        ("Carrier", CARRIER_MAC_PREFIXES),
        ("Honeywell Building", HONEYWELL_BUILDING_MAC_PREFIXES),
        ("F5", F5_MAC_PREFIXES),
        ("A10", A10_MAC_PREFIXES),
        ("Barracuda", BARRACUDA_MAC_PREFIXES),
        ("ALE", ALE_MAC_PREFIXES),
        ("Riverbed", RIVERBED_MAC_PREFIXES),
        ("Diebold", DIEBOLD_MAC_PREFIXES),
        ("Wincor Nixdorf", WINCOR_MAC_PREFIXES),
        ("Hyosung", HYOSUNG_MAC_PREFIXES),
        ("JBL", JBL_MAC_PREFIXES),
        ("Harman Kardon", HARMAN_KARDON_MAC_PREFIXES),
        ("Marshall", MARSHALL_MAC_PREFIXES),
        ("Bang & Olufsen", BANG_OLUFSEN_MAC_PREFIXES),
        ("Denon", DENON_MAC_PREFIXES),
        ("Yamaha Audio", YAMAHA_AUDIO_MAC_PREFIXES),
        ("Meta", META_MAC_PREFIXES),
        ("HP", HP_CONSUMER_MAC_PREFIXES),
        ("Realtek", REALTEK_MAC_PREFIXES),
        ("Qualcomm", QUALCOMM_MAC_PREFIXES),
        ("MediaTek", MEDIATEK_MAC_PREFIXES),
        ("Broadcom", BROADCOM_MAC_PREFIXES),
        ("Panasonic", PANASONIC_MAC_PREFIXES),
        ("Toshiba", TOSHIBA_MAC_PREFIXES),
        ("Sharp", SHARP_MAC_PREFIXES),
        ("eero", EERO_MAC_PREFIXES),
        ("ARRIS/CommScope", ARRIS_MAC_PREFIXES),
        ("Technicolor", TECHNICOLOR_MAC_PREFIXES),
    ]

    oui_dict = {}

    # Layer 1: Load IEEE OUI cache as broad fallback (86K+ entries)
    if cache_dir is not None:
        import json
        import logging
        from pathlib import Path

        logger = logging.getLogger(__name__)
        ieee_path = Path(cache_dir) / "ieee_oui.json"
        if ieee_path.is_file():
            try:
                with open(ieee_path, "r", encoding="utf-8") as fh:
                    ieee_data = json.load(fh)
                entries = ieee_data.get("entries", {})
                for prefix, info in entries.items():
                    if isinstance(info, dict) and info.get("vendor"):
                        oui_dict[prefix] = {
                            "manufacturer": info.get("vendor") or info.get("vendor_short"),
                            "device_type": info.get("device_type", "unknown"),
                            "category": "Unknown",
                            "model": None,
                        }
                logger.info(f"Loaded {len(oui_dict)} IEEE OUI entries from cache")
            except Exception as exc:
                logger.warning(f"Failed to load IEEE OUI cache: {exc}")

    # Layer 2: Built-in vendor patterns override IEEE data (richer metadata)
    for vendor_name, prefix_dict in all_vendors:
        for prefix, (device_type, category, model_hint) in prefix_dict.items():
            oui_dict[prefix] = {
                "manufacturer": vendor_name,
                "device_type": device_type,
                "category": category,
                "model": model_hint,
            }

    return oui_dict
