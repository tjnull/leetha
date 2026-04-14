"""Enhanced discovery processor -- WS-Discovery, NTP, DHCP server, DNS server."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


@register_processor("ws_discovery", "ntp", "dhcp_server", "dns_server")
class EnhancedDiscoveryProcessor(Processor):
    """Handles WS-Discovery, NTP, DHCP server, and DNS server protocols."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        if packet.protocol == "ws_discovery":
            return self._analyze_ws_discovery(packet)
        elif packet.protocol == "ntp":
            return self._analyze_ntp(packet)
        elif packet.protocol == "dhcp_server":
            return self._analyze_dhcp_server(packet)
        elif packet.protocol == "dns_server":
            return self._analyze_dns_server(packet)
        return []

    def _analyze_dhcp_server(self, packet: CapturedPacket) -> list[Evidence]:
        """DHCP OFFER/ACK → device serves DHCP.

        Running a DHCP server is a network role, not a device type. Many
        non-routers serve DHCP: NAS boxes (OpenMediaVault, TrueNAS),
        Pi-hole, Linux servers, domain controllers. We record the role
        as infrastructure evidence but do NOT assert category=router —
        that requires stronger proof (LLDP/CDP, actual routing protocols,
        or ICMPv6 Router Advertisements from a device with router OUI).
        """
        return [Evidence(
            source="dhcp_server",
            method="heuristic",
            certainty=0.55,
            category="infrastructure",
            raw={
                "role": "dhcp_server",
                "message_type": packet.get("message_type"),
                "client_mac": packet.get("client_mac"),
                "offered_ip": packet.get("offered_ip"),
            },
        )]

    def _analyze_dns_server(self, packet: CapturedPacket) -> list[Evidence]:
        """DNS response → device resolves DNS.

        Serving DNS is extremely common for non-routers: Pi-hole, AD
        domain controllers, NAS appliances, any Linux box running
        dnsmasq/unbound. Do NOT classify as router — record the service
        role only.
        """
        return [Evidence(
            source="dns_server",
            method="heuristic",
            certainty=0.40,
            raw={
                "role": "dns_server",
                "answer_count": packet.get("answer_count", 0),
            },
        )]

    def _analyze_ws_discovery(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        manufacturer = packet.get("manufacturer")
        model = packet.get("model")
        firmware = packet.get("firmware")
        device_types = packet.get("device_types") or []

        # Primary identification from PnP-X metadata
        if manufacturer or model:
            device_type = device_types[0] if device_types else None
            evidence.append(Evidence(
                source="ws_discovery",
                method="exact",
                certainty=0.85,
                vendor=manufacturer,
                model=model,
                category=device_type,
                raw={
                    "device_types": device_types,
                    "firmware": firmware,
                    "action": packet.get("action"),
                },
            ))
        elif device_types:
            # Type only (no manufacturer/model)
            evidence.append(Evidence(
                source="ws_discovery",
                method="heuristic",
                certainty=0.65,
                category=device_types[0],
                raw={"device_types": device_types, "action": packet.get("action")},
            ))

        return evidence

    def _analyze_ntp(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        mode = packet.get("mode")
        stratum = packet.get("stratum", 0)

        if mode == "server" or mode == "broadcast":
            # NTP server mode does not reliably indicate device type;
            # many Linux boxes, NAS devices, and DCs serve NTP.
            evidence.append(Evidence(
                source="ntp",
                method="heuristic",
                certainty=0.30,
                category=None,
                raw={
                    "ntp_role": mode,
                    "stratum": stratum,
                    "reference_id": packet.get("reference_id"),
                },
            ))
        elif mode == "client":
            # NTP clients -- stratum info is a weak supporting signal
            evidence.append(Evidence(
                source="ntp",
                method="heuristic",
                certainty=0.30,
                raw={
                    "ntp_role": "client",
                    "stratum": stratum,
                    "reference_id": packet.get("reference_id"),
                },
            ))

        return evidence
