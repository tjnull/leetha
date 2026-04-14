"""WS-Discovery (Web Services Dynamic Discovery) parser.

Captures Hello and ProbeMatch messages on UDP 3702 (multicast 239.255.255.250).
Extracts device type, manufacturer, model, and firmware from XML payloads.
"""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ImportError:
    from xml.etree.ElementTree import fromstring as _xml_fromstring
import xml.etree.ElementTree as ET

MAX_WSD_PAYLOAD = 65536

# WSD type URIs mapped to normalized device types
_TYPE_MAP = {
    "wprt:PrinterServiceType": "printer",
    "wscn:ScannerServiceType": "scanner",
    "wsdp:Device": "computer",
    "pub:Computer": "computer",
    "netdisco:NetworkDevice": "network_device",
}

# WSD XML namespaces
_NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "pnp": "http://schemas.microsoft.com/windows/pnpx/2005/10",
    "df": "http://schemas.microsoft.com/windows/2008/09/devicefoundation",
}


def _extract_action(root: ET.Element) -> str | None:
    """Extract the WSD action (Hello, ProbeMatches, etc.)."""
    action_el = root.find(".//a:Action", _NS)
    if action_el is None or not action_el.text:
        return None
    text = action_el.text.lower()
    if "hello" in text:
        return "hello"
    if "probematches" in text or "probematch" in text:
        return "probe_match"
    return None


def _extract_types(root: ET.Element) -> list[str]:
    """Extract and normalize device types from d:Types element."""
    types_el = root.find(".//d:Types", _NS)
    if types_el is None or not types_el.text:
        return []
    normalized = []
    for raw_type in types_el.text.strip().split():
        for key, val in _TYPE_MAP.items():
            if key.split(":")[-1].lower() in raw_type.lower():
                if val not in normalized:
                    normalized.append(val)
                break
    return normalized


def _extract_pnp_metadata(root: ET.Element) -> dict[str, str | None]:
    """Extract PnP-X metadata (manufacturer, model, firmware)."""
    result: dict[str, str | None] = {"manufacturer": None, "model": None, "firmware": None}
    # Try direct PnP-X elements
    for tag, key in [("Manufacturer", "manufacturer"), ("ModelName", "model"),
                     ("FirmwareVersion", "firmware")]:
        for ns_prefix in ("pnp", "df"):
            el = root.find(f".//{ns_prefix}:{tag}", _NS)
            if el is not None and el.text:
                result[key] = el.text.strip()
                break
    # Fallback: extract from Scopes URI
    if not result["manufacturer"]:
        scopes_el = root.find(".//d:Scopes", _NS)
        if scopes_el is not None and scopes_el.text:
            for scope in scopes_el.text.strip().split():
                if "manufacturer" in scope.lower():
                    # URI like http://schemas.../manufacturer/HP
                    parts = scope.rstrip("/").split("/")
                    if parts:
                        result["manufacturer"] = parts[-1]
    return result


def _extract_xaddrs(root: ET.Element) -> list[str]:
    """Extract service endpoint addresses."""
    el = root.find(".//d:XAddrs", _NS)
    if el is None or not el.text:
        return []
    return el.text.strip().split()


def _extract_scopes(root: ET.Element) -> list[str]:
    """Extract scope URIs."""
    el = root.find(".//d:Scopes", _NS)
    if el is None or not el.text:
        return []
    return el.text.strip().split()


def parse_ws_discovery(packet) -> CapturedPacket | None:
    """Extract WS-Discovery fields from UDP port 3702 packets."""
    try:
        from scapy.layers.inet import IP, UDP
    except ImportError:
        return None

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    if udp.dport != 3702 and udp.sport != 3702:
        return None

    try:
        payload = bytes(udp.payload).decode("utf-8", errors="ignore")
    except Exception:
        return None

    if not payload or not payload.strip().startswith("<"):
        return None

    if len(payload) > MAX_WSD_PAYLOAD:
        return None

    try:
        root = _xml_fromstring(payload)
    except ET.ParseError:
        return None

    action = _extract_action(root)
    if action is None:
        return None

    device_types = _extract_types(root)
    metadata = _extract_pnp_metadata(root)
    xaddrs = _extract_xaddrs(root)
    scopes = _extract_scopes(root)

    # Must have at least one useful field
    if not device_types and not metadata["manufacturer"] and not metadata["model"]:
        return None

    return CapturedPacket(
        protocol="ws_discovery",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "action": action,
            "device_types": device_types,
            "manufacturer": metadata["manufacturer"],
            "model": metadata["model"],
            "firmware": metadata["firmware"],
            "scopes": scopes,
            "xaddrs": xaddrs,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
