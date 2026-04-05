"""Network discovery processor -- ARP, DHCPv4, DHCPv6, ICMPv6."""
from __future__ import annotations

import re

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


@register_processor("arp", "dhcpv4", "dhcpv6", "icmpv6")
class NetworkDiscoveryProcessor(Processor):
    """Handles protocols that reveal host presence and basic identity."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "arp":
            return self._analyze_arp(packet)
        elif protocol == "dhcpv4":
            return self._analyze_dhcpv4(packet)
        elif protocol == "dhcpv6":
            return self._analyze_dhcpv6(packet)
        elif protocol == "icmpv6":
            return self._analyze_icmpv6(packet)
        return []

    def _analyze_arp(self, packet: CapturedPacket) -> list[Evidence]:
        # ARP itself doesn't reveal much about device type,
        # but the MAC OUI lookup happens separately in the lookup layer
        return [Evidence(
            source="arp", method="heuristic", certainty=0.3,
            raw={"op": packet.get("op"), "ip": packet.ip_addr},
        )]

    def _analyze_dhcpv4(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        hostname = packet.get("hostname")
        opt55 = packet.get("opt55")
        opt60 = packet.get("opt60")

        if hostname:
            evidence.append(Evidence(
                source="dhcpv4", method="exact", certainty=0.75,
                hostname=hostname,
                raw={"hostname": hostname},
            ))
            # Hostname pattern matching
            from leetha.patterns.matching import match_hostname
            host_match = match_hostname(hostname)
            if host_match:
                raw_conf = host_match.get("confidence", 75)
                cert = raw_conf / 100.0 if raw_conf > 1 else raw_conf
                evidence.append(Evidence(
                    source="hostname", method="pattern",
                    certainty=cert,
                    vendor=host_match.get("manufacturer"),
                    category=host_match.get("device_type"),
                    platform=host_match.get("os_family"),
                    model=host_match.get("model"),
                    hostname=hostname,
                    raw={"hostname": hostname, "match": host_match},
                ))

        if opt60:
            evidence.append(Evidence(
                source="dhcpv4_vendor", method="pattern", certainty=0.80,
                raw={"opt60": opt60},
            ))
            # DHCP Option 60 (Vendor Class) pattern matching
            from leetha.patterns.matching import match_dhcp_opt60
            opt60_match = match_dhcp_opt60(opt60)
            if opt60_match:
                raw_conf = opt60_match.get("confidence", 80)
                cert = raw_conf / 100.0 if raw_conf > 1 else raw_conf
                evidence.append(Evidence(
                    source="dhcpv4_vendor", method="pattern",
                    certainty=cert,
                    vendor=opt60_match.get("manufacturer"),
                    category=opt60_match.get("device_type"),
                    platform=opt60_match.get("os_family"),
                    raw={"opt60": opt60, "match": opt60_match},
                ))

        if opt55:
            evidence.append(Evidence(
                source="dhcpv4_fingerprint", method="pattern", certainty=0.70,
                raw={"opt55": opt55},
            ))

        client_id = packet.get("client_id")
        if client_id:
            ev = Evidence(
                source="dhcpv4",
                method="exact",
                certainty=0.70,
                raw={"client_id": client_id},
            )
            if _MAC_RE.match(client_id):
                ev.raw["possible_real_mac"] = True
            else:
                # Check for vendor-like substring in non-MAC client IDs
                cid_lower = client_id.lower()
                for keyword in ("dell", "hp", "lenovo", "apple", "cisco",
                                "huawei", "samsung", "intel", "broadcom"):
                    if keyword in cid_lower:
                        ev.vendor = client_id
                        break
            evidence.append(ev)

        return evidence

    def _analyze_dhcpv6(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        oro = packet.get("oro")
        vendor_class = packet.get("vendor_class")
        fqdn = packet.get("fqdn")

        if vendor_class:
            evidence.append(Evidence(
                source="dhcpv6_vendor", method="pattern", certainty=0.80,
                raw={"vendor_class": vendor_class},
            ))
        if oro:
            evidence.append(Evidence(
                source="dhcpv6_oro", method="pattern", certainty=0.65,
                raw={"oro": oro},
            ))
        if fqdn:
            evidence.append(Evidence(
                source="dhcpv6", method="exact", certainty=0.75,
                hostname=fqdn,
                raw={"fqdn": fqdn},
            ))

        enterprise_id = packet.get("enterprise_id")
        if enterprise_id:
            evidence.append(Evidence(
                source="dhcpv6",
                method="exact",
                certainty=0.70,
                raw={"enterprise_id": enterprise_id},
            ))

        duid = packet.get("duid")
        if duid:
            evidence.append(Evidence(
                source="dhcpv6",
                method="exact",
                certainty=0.65,
                raw={"duid": duid},
            ))

        return evidence

    def _analyze_icmpv6(self, packet: CapturedPacket) -> list[Evidence]:
        icmp_type = packet.get("icmpv6_type", "")
        evidence = []
        if icmp_type == "router_advertisement":
            evidence.append(Evidence(
                source="icmpv6_ra", method="heuristic", certainty=0.60,
                category="router",
                raw={"hop_limit": packet.get("hop_limit"), "managed": packet.get("managed")},
            ))
        return evidence
