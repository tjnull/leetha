"""Passive observer processor -- IP observed events."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


@register_processor("ip_observed")
class PassiveObserverProcessor(Processor):
    """Handles passively observed IP traffic for OS and service hints."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        ttl = packet.get("ttl")
        port = packet.get("dst_port")
        ttl_os_hint = packet.get("ttl_os_hint")

        if ttl is not None:
            # Use our own TTL analysis, not the parser's overly-broad hint.
            # TTL 64 is shared by Linux, macOS, iOS, Android, FreeBSD —
            # too ambiguous to label as any specific OS.
            os_hint = self._ttl_os_hint(ttl)
            if os_hint:
                evidence.append(Evidence(
                    source="ip_observed_ttl", method="heuristic",
                    certainty=0.40,
                    platform=os_hint,
                    raw={"ttl": ttl, "os_hint": os_hint},
                ))

        if port is not None:
            service_hint = self._port_service_hint(port)
            if service_hint:
                evidence.append(Evidence(
                    source="ip_observed_port", method="heuristic", certainty=0.30,
                    raw={"port": port, "service_hint": service_hint},
                ))

        return evidence

    @staticmethod
    def _ttl_os_hint(ttl: int) -> str | None:
        """TTL is not reliable for OS identification in passive monitoring.

        Many device categories share TTL ranges:
        - TTL 64: Linux, macOS, iOS, Android, FreeBSD, embedded, most IoT
        - TTL 128: Windows, UniFi OS, many routers/switches
        - TTL 255: Network infrastructure

        Platform should come from DHCP options, mDNS, DNS patterns, user-agent.
        """
        return None

    @staticmethod
    def _port_service_hint(port: int) -> str | None:
        """Map well-known ports to service hints."""
        common = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
            3389: "rdp", 5060: "sip", 5432: "postgresql", 6379: "redis",
            8080: "http-proxy", 8443: "https-alt", 8883: "mqtt-tls",
        }
        return common.get(port)
