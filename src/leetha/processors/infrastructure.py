"""Infrastructure processor -- LLDP, CDP, STP, SNMP."""
from __future__ import annotations

import re

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


_LLDP_CAP_MAP = {
    "router": "router",
    "bridge": "switch",
    "wlan_ap": "access_point",
    "station": "endpoint",
    "telephone": "voip_phone",
    "docsis": "cable_modem",
    "repeater": "switch",
}

# Priority for LLDP capabilities: lower number = higher priority.
# When multiple capabilities are present, pick the highest priority one.
_CAP_PRIORITY = {"router": 1, "switch": 2, "access_point": 3, "voip_phone": 4,
                 "cable_modem": 5, "endpoint": 6}

_CDP_CAP_MAP = {
    "router": "router",
    "switch": "switch",
    "host": "workstation",
    "phone": "voip_phone",
    "igmp": "router",
}


@register_processor("lldp", "cdp", "stp", "snmp")
class InfrastructureProcessor(Processor):
    """Handles infrastructure discovery protocols."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "lldp":
            return self._analyze_lldp(packet)
        elif protocol == "cdp":
            return self._analyze_cdp(packet)
        elif protocol == "stp":
            return self._analyze_stp(packet)
        elif protocol == "snmp":
            return self._analyze_snmp(packet)
        return []

    def _analyze_lldp(self, packet: CapturedPacket) -> list[Evidence]:
        system_name = packet.get("system_name", "")
        system_description = packet.get("system_description", "")
        capabilities = packet.get("capabilities") or []
        management_ip = packet.get("management_ip")

        # Collect all matching capabilities and pick the highest priority one
        device_type = None
        best_priority = 999
        for cap in capabilities:
            if cap in _LLDP_CAP_MAP:
                mapped = _LLDP_CAP_MAP[cap]
                priority = _CAP_PRIORITY.get(mapped, 99)
                if priority < best_priority:
                    best_priority = priority
                    device_type = mapped

        platform = None
        vendor = None
        model = None
        desc_lower = system_description.lower() if system_description else ""
        if "cisco ios" in desc_lower or "cisco nx-os" in desc_lower:
            vendor = "Cisco"
            platform = "NX-OS" if "nx-os" in desc_lower else "IOS"
        elif "junos" in desc_lower:
            vendor = "Juniper"
            platform = "Junos"
        elif "linux" in desc_lower:
            platform = "Linux"
        elif "windows" in desc_lower:
            platform = "Windows"
        elif "aruba" in desc_lower:
            vendor = "Aruba"
            platform = "ArubaOS"
        elif "extreme" in desc_lower:
            vendor = "Extreme"
        elif "fortinet" in desc_lower or "fortigate" in desc_lower:
            vendor = "Fortinet"
            platform = "FortiOS"
        elif "mikrotik" in desc_lower or "routeros" in desc_lower:
            vendor = "MikroTik"
            platform = "RouterOS"

        # Extract UniFi model from system_description (e.g. "US-8-150W, 7.2.123, Linux 3.6.5")
        if system_description:
            model_str = system_description.split(",")[0].strip()
            model_lower = model_str.lower()
            if re.match(r'^(us[w]?-|us8|us16|us24|us48)', model_lower):
                model = model_str
                vendor = "Ubiquiti"
                device_type = "switch"
            elif re.match(r'^(uap|u6|u7|nanohd|flexhd|beaconhd)', model_lower):
                model = model_str
                vendor = "Ubiquiti"
                device_type = "access_point"
            elif re.match(r'^(udm|ucg|udr|usg|edgerouter)', model_lower):
                model = model_str
                vendor = "Ubiquiti"
                device_type = "router"

        # Fall back to system_name as model if no model extracted from description
        if not model:
            model = system_name or None

        # Use system_name as hostname evidence
        hostname = system_name if system_name else None

        # Reduce certainty for ambiguous "endpoint" (was "station")
        certainty = 0.60 if device_type == "endpoint" else 0.90

        return [Evidence(
            source="lldp", method="exact", certainty=certainty,
            category=device_type,
            vendor=vendor,
            platform=platform,
            model=model,
            hostname=hostname,
            raw={
                "system_name": system_name,
                "system_description": system_description,
                "capabilities": capabilities,
                "management_ip": management_ip,
            },
        )]

    def _analyze_cdp(self, packet: CapturedPacket) -> list[Evidence]:
        device_id = packet.get("device_id", "")
        cdp_platform = packet.get("platform", "")
        software_version = packet.get("software_version", "")
        capabilities = packet.get("capabilities") or []
        management_ip = packet.get("management_ip")

        device_type = None
        for cap in capabilities:
            cap_lower = cap.lower()
            if cap_lower in _CDP_CAP_MAP:
                device_type = _CDP_CAP_MAP[cap_lower]
                break

        vendor = None
        model = None
        if cdp_platform:
            platform_lower = cdp_platform.lower()
            if "cisco" in platform_lower:
                vendor = "Cisco"
                for prefix in ("cisco ", "Cisco "):
                    if cdp_platform.startswith(prefix):
                        model = cdp_platform[len(prefix):].strip()
                        break
                if not model:
                    model = cdp_platform
            else:
                model = cdp_platform

        os_family = None
        os_version = None
        ver_lower = software_version.lower() if software_version else ""
        if "ios-xe" in ver_lower:
            os_family = "IOS-XE"
        elif "ios" in ver_lower and "cisco" in ver_lower:
            os_family = "IOS"
        elif "nx-os" in ver_lower:
            os_family = "NX-OS"
        elif "adaptive security" in ver_lower or "asa" in ver_lower:
            os_family = "ASA"

        ver_match = re.search(r'Version\s+([\d.()A-Za-z]+)', software_version)
        if ver_match:
            os_version = ver_match.group(1)

        return [Evidence(
            source="cdp", method="exact", certainty=0.92,
            category=device_type,
            vendor=vendor,
            platform=os_family,
            platform_version=os_version,
            model=model,
            raw={
                "device_id": device_id,
                "platform": cdp_platform,
                "software_version": software_version,
                "capabilities": capabilities,
                "management_ip": management_ip,
            },
        )]

    def _analyze_stp(self, packet: CapturedPacket) -> list[Evidence]:
        """STP classification.

        Docker bridges and VMware virtual switches also emit STP BPDUs,
        so keep certainty low. Only non-default bridge priorities suggest
        intentional switch configuration.
        """
        bridge_priority = packet.get("bridge_priority", 32768)
        bridge_mac = packet.get("bridge_mac", "")
        is_root = packet.get("is_root", False)

        if bridge_priority < 8192:
            confidence = 0.45
        elif bridge_priority < 32768:
            confidence = 0.35
        else:
            # Default bridge priority (32768) — likely Docker/VMware host
            confidence = 0.20

        if is_root:
            confidence = min(confidence + 0.05, 0.45)

        return [Evidence(
            source="stp", method="heuristic", certainty=confidence,
            category="switch",
            raw={
                "bridge_priority": bridge_priority,
                "bridge_mac": bridge_mac,
                "is_root": is_root,
            },
        )]

    def _analyze_snmp(self, packet: CapturedPacket) -> list[Evidence]:
        version = packet.get("version", "")
        community = packet.get("community", "")
        pdu_type = packet.get("pdu_type", "")
        sys_descr = packet.get("sys_descr", "")
        sys_name = packet.get("sys_name", "")
        sys_object_id = packet.get("sys_object_id", "")

        platform = None
        platform_version = None
        vendor = None
        device_type = None

        if sys_descr:
            descr_lower = sys_descr.lower()
            if "cisco ios" in descr_lower or "cisco nx-os" in descr_lower or "cisco adaptive" in descr_lower or "asa" in descr_lower or "pix" in descr_lower:
                vendor = "Cisco"
                # Distinguish Cisco device types from sys_descr (similar to CDP analyzer)
                if "asa" in descr_lower or "adaptive security" in descr_lower or "pix" in descr_lower:
                    platform = "ASA"
                    device_type = "firewall"
                elif "nx-os" in descr_lower:
                    platform = "NX-OS"
                    device_type = "switch"
                elif "ios-xe" in descr_lower:
                    platform = "IOS-XE"
                    device_type = "router" if "router" in descr_lower else "network_device"
                elif "wireless" in descr_lower or "air-" in descr_lower or "wlc" in descr_lower:
                    platform = "IOS"
                    device_type = "wireless_controller"
                elif "ios" in descr_lower and "router" in descr_lower:
                    platform = "IOS"
                    device_type = "router"
                elif "ios" in descr_lower:
                    platform = "IOS"
                    device_type = "network_device"
                else:
                    platform = "IOS"
                    device_type = "network_device"
            elif "junos" in descr_lower:
                vendor = "Juniper"
                platform = "Junos"
            elif "linux" in descr_lower:
                platform = "Linux"
                ver_match = re.search(r'Linux\s+\S+\s+([\d.]+)', sys_descr)
                if ver_match:
                    platform_version = ver_match.group(1)
            elif "windows" in descr_lower:
                platform = "Windows"
            elif "freebsd" in descr_lower:
                platform = "FreeBSD"
            elif "net-snmp" in descr_lower:
                platform = "Linux"
            elif "arista" in descr_lower:
                vendor = "Arista"
                platform = "EOS"
            elif "hp" in descr_lower or "procurve" in descr_lower:
                vendor = "HP"
                device_type = "switch"
            elif "ubiquiti" in descr_lower or "unifi" in descr_lower:
                vendor = "Ubiquiti"
            elif "fortinet" in descr_lower:
                vendor = "Fortinet"
                platform = "FortiOS"

        confidence = 0.85 if sys_descr else 0.30
        method = "exact" if sys_descr else "heuristic"

        return [Evidence(
            source="snmp", method=method, certainty=confidence,
            category=device_type,
            vendor=vendor,
            platform=platform,
            platform_version=platform_version,
            raw={
                "version": version,
                "community": community,
                "pdu_type": pdu_type,
                "sys_descr": sys_descr,
                "sys_name": sys_name,
                "sys_object_id": sys_object_id,
            },
        )]
