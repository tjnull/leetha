"""Service fingerprint processor -- TCP SYN, TLS, HTTP User-Agent."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence
from leetha.patterns.tls import lookup_ja3


@register_processor("tcp_syn", "tls", "http_useragent", "stun", "quic", "radius")
class ServiceFingerprintProcessor(Processor):
    """Handles protocols that reveal services, applications, and OS hints."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "tcp_syn":
            return self._analyze_tcp_syn(packet)
        elif protocol == "tls":
            return self._analyze_tls(packet)
        elif protocol == "http_useragent":
            return self._analyze_http_useragent(packet)
        elif protocol == "stun":
            return self._analyze_stun(packet)
        elif protocol == "quic":
            return self._analyze_quic(packet)
        elif protocol == "radius":
            return self._analyze_radius(packet)
        return []

    def _analyze_tcp_syn(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        ttl = packet.get("ttl")
        window_size = packet.get("window_size")
        mss = packet.get("mss")
        tcp_options = packet.get("tcp_options", "")

        # TTL-based OS heuristic
        if ttl is not None:
            os_hint = self._ttl_os_hint(ttl)
            if os_hint:
                evidence.append(Evidence(
                    source="tcp_syn_ttl", method="heuristic", certainty=0.50,
                    platform=os_hint,
                    raw={"ttl": ttl, "os_hint": os_hint},
                ))

        # TCP signature (window + MSS + options) -- stored as raw evidence
        # but NOT used for platform inference.  Embedded devices, routers,
        # and smart speakers share identical TCP stacks with Linux/Windows.
        if window_size is not None:
            mss_str = str(mss) if mss else "*"
            sig = f"{ttl}:{window_size}:{mss_str}:{tcp_options}"
            evidence.append(Evidence(
                source="tcp_syn_sig", method="pattern",
                certainty=0.40,
                raw={"signature": sig, "window_size": window_size,
                     "mss": mss, "tcp_options": tcp_options},
            ))

        return evidence

    def _analyze_tls(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        ja3 = packet.get("ja3_hash")
        ja4 = packet.get("ja4")
        sni = packet.get("sni")

        if ja3:
            evidence.append(Evidence(
                source="tls_ja3", method="pattern", certainty=0.75,
                raw={"ja3_hash": ja3},
            ))
            match = lookup_ja3(ja3)
            if match:
                evidence[-1].vendor = match.get("app")
                evidence[-1].platform = match.get("os_family")

        if ja4:
            evidence.append(Evidence(
                source="tls_ja4", method="pattern", certainty=0.75,
                raw={"ja4": ja4},
            ))

        if sni:
            evidence.append(Evidence(
                source="tls_sni", method="exact", certainty=0.70,
                raw={"sni": sni},
            ))

        return evidence

    def _analyze_http_useragent(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        user_agent = packet.get("user_agent")
        host = packet.get("host")

        if user_agent:
            platform, vendor = self._parse_user_agent(user_agent)
            evidence.append(Evidence(
                source="http_useragent", method="pattern", certainty=0.80,
                platform=platform,
                vendor=vendor,
                raw={"user_agent": user_agent},
            ))

        if host:
            evidence.append(Evidence(
                source="http_host", method="pattern", certainty=0.40,
                raw={"host": host},
            ))

        return evidence

    def _analyze_stun(self, packet: CapturedPacket) -> list[Evidence]:
        """STUN/TURN — reveals WebRTC usage (video conferencing, streaming)."""
        type_name = packet.get("type_name", "")
        return [Evidence(
            source="stun", method="heuristic", certainty=0.50,
            raw={"type": type_name, "dst_port": packet.get("dst_port")},
        )]

    def _analyze_quic(self, packet: CapturedPacket) -> list[Evidence]:
        """QUIC HTTP/3 — extract SNI like TLS."""
        sni = packet.get("sni")
        evidence = [Evidence(
            source="quic_sni", method="exact", certainty=0.65,
            raw={"sni": sni},
        )]
        return evidence

    def _analyze_radius(self, packet: CapturedPacket) -> list[Evidence]:
        """RADIUS — enterprise authentication."""
        code_name = packet.get("code_name", "")
        is_server = packet.get("is_server", False)
        evidence = [Evidence(
            source="radius", method="exact", certainty=0.70,
            raw={"code": code_name},
        )]
        if is_server:
            evidence[0].category = "server"
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
    def _parse_user_agent(ua: str) -> tuple[str | None, str | None]:
        """Extract platform and vendor hints from a User-Agent string."""
        ua_lower = ua.lower()
        platform = None
        vendor = None

        if "windows" in ua_lower:
            platform = "Windows"
            vendor = "Microsoft"
        elif "macintosh" in ua_lower or "mac os" in ua_lower:
            platform = "macOS"
            vendor = "Apple"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            platform = "iOS"
            vendor = "Apple"
        elif "android" in ua_lower:
            platform = "Android"
            # Extract actual vendor from common Android UA patterns
            if "pixel" in ua_lower or "nexus" in ua_lower:
                vendor = "Google"
            elif "sm-" in ua_lower or "samsung" in ua_lower:
                vendor = "Samsung"
            elif "xiaomi" in ua_lower or "redmi" in ua_lower or "poco" in ua_lower:
                vendor = "Xiaomi"
            elif "oneplus" in ua_lower:
                vendor = "OnePlus"
            elif "motorola" in ua_lower or "moto " in ua_lower or "moto/" in ua_lower:
                vendor = "Motorola"
            elif "huawei" in ua_lower or "honor" in ua_lower:
                vendor = "Huawei"
            elif "oppo" in ua_lower:
                vendor = "OPPO"
            elif "vivo" in ua_lower:
                vendor = "Vivo"
            # Otherwise vendor stays None for generic Android
        elif "linux" in ua_lower:
            platform = "Linux"
        elif "cros" in ua_lower:
            platform = "ChromeOS"
            vendor = "Google"

        return platform, vendor
