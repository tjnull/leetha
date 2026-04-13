"""Verdict computation engine.

Fuses multiple Evidence objects into a single Verdict per host. Uses
weighted certainty based on source reliability and agreement boosting
when independent sources agree on the same value.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from leetha.evidence.models import Evidence, Verdict

logger = logging.getLogger(__name__)

# Source reliability weights — how much we trust each evidence source
_SOURCE_WEIGHTS: dict[str, float] = {
    # MAC OUI identification — highest reliability
    "oui": 0.90,
    "huginn_mac": 0.85,
    # Infrastructure protocols
    "lldp": 0.95,
    "cdp": 0.95,
    "snmp": 0.90,
    "dhcpv4": 0.85,
    "dhcpv4_vendor": 0.85,
    "dhcpv4_fingerprint": 0.80,
    "dhcpv6_vendor": 0.85,
    "dhcpv6_oro": 0.75,
    "dhcpv6": 0.75,
    "probe": 0.85,
    "tcp_syn": 0.70,
    "tls": 0.70,
    "http_useragent": 0.75,
    "ssdp": 0.65,
    "mdns": 0.70,
    "mdns_exclusive": 0.80,  # vendor-exclusive services — below OUI (0.90) because
                              # routers/gateways forward mDNS, rewriting source MAC
    "mdns_txt": 0.75,
    "tls_sni": 0.50,
    "dns": 0.50,
    "dns_vendor": 0.55,
    "dns_behavioral": 0.60,
    "netbios": 0.60,
    "icmpv6_ra": 0.60,
    "stp": 0.50,
    "arp": 0.30,
    "ip_observed": 0.30,
    "hostname": 0.65,
    # TCP/TLS sources
    "tcp_syn_ttl": 0.50,
    "tcp_syn_sig": 0.65,
    "tls_ja3": 0.75,
    "tls_ja4": 0.75,
    "http_host": 0.40,
    # DNS sources
    "dns_query": 0.45,
    "dns_ntp_hint": 0.55,
    # mDNS sources
    "mdns_service": 0.65,
    "mdns_srv": 0.85,    # SRV target = device's actual .local hostname
    "mdns_name": 0.60,
    # Banner source
    "passive_banner": 0.85,
    # IoT/SCADA sources
    "modbus": 0.60,
    "bacnet": 0.65,
    "coap": 0.50,
    "mqtt": 0.55,
    "enip": 0.65,
    "dnp3": 0.75,
    "s7comm": 0.80,
    "opcua": 0.75,
    "goose": 0.85,
    "profinet": 0.80,
    "umas": 0.85,
    # Other
    "ip_observed_ttl": 0.35,
    "ip_observed_port": 0.30,
    "dns_answer": 0.50,
    "ws_discovery": 0.85,
    # Discovery-enhanced sources
    "dhcp_server": 0.85,
    "dns_server": 0.50,
    "ntp": 0.55,
    "ssdp_server": 0.65,
    # Fingerprint lookup sources (from fingerprint/lookup.py)
    "banner": 0.75,
    "banner_cache": 0.70,
    "dhcp": 0.80,
    "dhcp_vendor": 0.80,
    "huginn_device": 0.85,
    "huginn_dhcp": 0.80,
    "huginn_dhcp_vendor": 0.80,
    "huginn_dhcpv6": 0.75,
    "huginn_dhcpv6_enterprise": 0.75,
    "icmpv6": 0.60,
    "ja3": 0.75,
    "ja4": 0.75,
    "tcp": 0.65,
    "ttl": 0.15,
    "ssdp_upnp": 0.65,
    "mdns_service_map": 0.70,
    "manual": 0.99,
    "active_probe": 0.85,
    # New protocol sources
    "igmp": 0.35,
    "eap": 0.60,
    "stun": 0.45,
    "quic_sni": 0.60,
    "radius": 0.65,
    "upnp": 0.55,
    "apple_model": 0.90,
    "mdns_apple_model": 0.90,
}

# Agreement boost: when N independent sources agree, multiply certainty
_AGREEMENT_BONUS = {1: 1.0, 2: 1.1, 3: 1.2, 4: 1.25}


def cap_evidence(
    evidence: list[Evidence],
    max_per_source: int = 3,
    max_total: int = 100,
) -> list[Evidence]:
    """Keep the most recent N evidence items per source, capped at max_total."""
    if not evidence:
        return []

    by_source: dict[str, list[Evidence]] = {}
    for e in evidence:
        by_source.setdefault(e.source, []).append(e)

    result = []
    for source, items in by_source.items():
        items.sort(key=lambda e: e.certainty, reverse=True)
        result.extend(items[:max_per_source])

    result.sort(key=lambda e: e.observed_at, reverse=True)
    return result[:max_total]


class VerdictEngine:
    """Compute a host Verdict by fusing all available Evidence."""

    def compute(self, hw_addr: str, evidence: list[Evidence]) -> Verdict:
        """Fuse evidence list into a single verdict.

        For each field (category, vendor, platform, etc.):
        1. Collect all evidence that contributes to this field
        2. Weight by source reliability * evidence certainty
        3. Boost when multiple independent sources agree
        4. Pick the winner
        """
        evidence = cap_evidence(evidence)

        if not evidence:
            return Verdict(hw_addr=hw_addr, certainty=0)

        category = self._fuse_field(evidence, "category")
        vendor = self._fuse_field(evidence, "vendor")
        platform = self._fuse_field(evidence, "platform")
        platform_version = self._fuse_field(evidence, "platform_version")
        model = self._fuse_field(evidence, "model")
        hostname = self._fuse_field(evidence, "hostname")

        # Overall certainty: weighted average of best evidence per field
        field_scores = []
        field_weights = [
            (category, 0.3), (vendor, 0.3), (platform, 0.25),
            (hostname, 0.1), (model, 0.05),
        ]
        for val, score in field_weights:
            if val[0] is not None:
                field_scores.append(val[1] * score)

        weight_sum = sum(w for (val, _score), w in zip(field_weights, [
            0.3, 0.3, 0.25, 0.1, 0.05,
        ]) if val[0] is not None)
        overall = min(100, int(sum(field_scores) / max(weight_sum, 0.01) * 100))

        # Fallback: infer platform from vendor + device type when no
        # protocol-level evidence provided one (common in passive monitoring)
        chosen_platform = platform[0]
        if chosen_platform is None and vendor[0] is not None:
            from leetha.fingerprint.evidence import _guess_os_from_vendor
            chosen_platform = _guess_os_from_vendor(vendor[0], category[0])

        # Validate and clean hostname
        chosen_hostname = hostname[0]
        if chosen_hostname:
            import re
            from leetha.evidence.hostname import is_valid_hostname
            # Strip AirPlay-style "<hex_id>@<name>" prefix — the hex is
            # the advertising device's ID, not a hostname component.
            chosen_hostname = re.sub(
                r'^[0-9A-Fa-f]{6,12}@', '', chosen_hostname,
            )
            # Strip mDNS service type suffix: "Name._service._tcp.local" -> "Name"
            if "._" in chosen_hostname:
                chosen_hostname = chosen_hostname.split("._")[0]
            # Strip trailing hex suffixes that look like auto-generated device
            # IDs (12+ lowercase hex chars, e.g. "-6aa3e8f01b2c"), but keep
            # short suffixes that are likely human-assigned (e.g. "DESKTOP-ABC123").
            chosen_hostname = re.sub(r'-[0-9a-f]{12,}$', '', chosen_hostname, flags=re.IGNORECASE)
            # Strip .local suffix
            if chosen_hostname.endswith(".local"):
                chosen_hostname = chosen_hostname[:-6]
            chosen_hostname = chosen_hostname.strip(".-") or hostname[0]

            # If the cleaned winner is still invalid, try the next-best candidate
            if not is_valid_hostname(chosen_hostname):
                chosen_hostname = self._next_valid_hostname(evidence)

        # Cross-check: reject hostnames that belong to a different vendor
        # than the resolved identity. This catches forwarded mDNS names that
        # leaked through (e.g., a Lutron bridge name on a Ubiquiti router).
        if chosen_hostname and vendor[0]:
            chosen_hostname = self._validate_hostname_coherence(
                chosen_hostname, vendor[0], category[0], evidence,
            )

        # Infer category/platform from hostname when the hostname contains
        # an explicit Apple device type (e.g. "Becca's MacBook Air").
        # This overrides ambiguous mDNS service evidence that can't
        # distinguish macOS from iOS.
        chosen_category = category[0]
        if chosen_hostname and vendor[0] == "Apple":
            hn_lower = chosen_hostname.lower()
            if "macbook" in hn_lower:
                chosen_category = "laptop"
                chosen_platform = "macOS"
            elif "imac" in hn_lower or "mac mini" in hn_lower or "mac pro" in hn_lower or "mac studio" in hn_lower:
                chosen_category = "workstation"
                chosen_platform = "macOS"
            elif "iphone" in hn_lower:
                chosen_category = "phone"
                chosen_platform = "iOS"
            elif "ipad" in hn_lower:
                chosen_category = "tablet"
                chosen_platform = "iPadOS"

        return Verdict(
            hw_addr=hw_addr,
            category=chosen_category,
            vendor=vendor[0],
            platform=chosen_platform,
            platform_version=platform_version[0],
            model=model[0],
            hostname=chosen_hostname,
            certainty=overall,
            evidence_chain=list(evidence),
            computed_at=datetime.now(),
        )

    def update(self, existing: Verdict, new_evidence: list[Evidence]) -> Verdict:
        """Incrementally update a verdict with new evidence.

        Appends new evidence to the chain and recomputes.
        """
        all_evidence = list(existing.evidence_chain) + list(new_evidence)
        return self.compute(existing.hw_addr, all_evidence)

    def _fuse_field(self, evidence: list[Evidence], field: str) -> tuple[str | None, float]:
        """Fuse a single field from all evidence, returning (value, score).

        Returns the highest-scored value after weighting and agreement boosting.
        """
        candidates: dict[str, float] = {}
        source_counts: dict[str, set] = {}

        for e in evidence:
            value = getattr(e, field, None)
            if value is None:
                continue

            weight = _SOURCE_WEIGHTS.get(e.source) or _SOURCE_WEIGHTS.get(
                e.source.rsplit("_", 1)[0] if "_" in e.source else e.source, 0.5)
            score = e.certainty * weight

            if value not in candidates:
                candidates[value] = 0.0
                source_counts[value] = set()

            candidates[value] += score
            source_counts[value].add(e.source)

        if not candidates:
            return (None, 0.0)

        # Apply agreement boost
        for value in candidates:
            n_sources = len(source_counts[value])
            boost = _AGREEMENT_BONUS.get(min(n_sources, 4), 1.25)
            candidates[value] *= boost

        # Pick winner
        winner = max(candidates, key=candidates.get)  # type: ignore[arg-type]
        return (winner, min(candidates[winner], 1.0))

    def _next_valid_hostname(self, evidence: list[Evidence]) -> str | None:
        """Find the best valid hostname from evidence, skipping invalid ones."""
        import re
        from leetha.evidence.hostname import is_valid_hostname

        candidates: dict[str, float] = {}
        source_counts: dict[str, set] = {}

        for e in evidence:
            value = e.hostname
            if value is None:
                continue

            # Clean before validating
            value = re.sub(r'^[0-9A-Fa-f]{6,12}@', '', value)
            if "._" in value:
                value = value.split("._")[0]
            value = re.sub(r'-[0-9a-f]{12,}$', '', value, flags=re.IGNORECASE)
            if value.endswith(".local"):
                value = value[:-6]
            value = value.strip(".-")
            if not value or not is_valid_hostname(value):
                continue

            weight = _SOURCE_WEIGHTS.get(e.source) or _SOURCE_WEIGHTS.get(
                e.source.rsplit("_", 1)[0] if "_" in e.source else e.source, 0.5)
            score = e.certainty * weight
            if value not in candidates:
                candidates[value] = 0.0
                source_counts[value] = set()
            candidates[value] += score
            source_counts[value].add(e.source)

        if not candidates:
            return None

        for value in candidates:
            n_sources = len(source_counts[value])
            boost = _AGREEMENT_BONUS.get(min(n_sources, 4), 1.25)
            candidates[value] *= boost

        return max(candidates, key=candidates.get)  # type: ignore[arg-type]

    # Known vendor/product keywords that appear in mDNS hostnames from
    # devices other than the one whose MAC is being fingerprinted.
    # Format: keyword -> set of vendor names that legitimately use it.
    _HOSTNAME_VENDOR_KEYWORDS: dict[str, set[str]] = {
        "lutron": {"Lutron"},
        "hue": {"Philips", "Signify"},
        "sonos": {"Sonos"},
        "roku": {"Roku"},
        "nest": {"Google"},
        "echo": {"Amazon"},
        "alexa": {"Amazon"},
        "homepod": {"Apple"},
        "office speaker": {"Apple"},
        "living room speaker": {"Apple", "Google"},
        "chromecast": {"Google"},
        "firestick": {"Amazon"},
        "ring": {"Amazon", "Ring"},
    }

    def _validate_hostname_coherence(
        self,
        hostname: str,
        resolved_vendor: str,
        resolved_category: str | None,
        evidence: list[Evidence],
    ) -> str | None:
        """Reject a hostname that clearly belongs to a different vendor.

        Returns the hostname if it's coherent, or the next best hostname
        from evidence that is, or None.
        """
        hn_lower = hostname.lower()
        for keyword, legit_vendors in self._HOSTNAME_VENDOR_KEYWORDS.items():
            if keyword in hn_lower:
                # This hostname contains a vendor keyword — check if
                # the resolved device vendor matches
                if resolved_vendor and resolved_vendor not in legit_vendors:
                    # Hostname belongs to a different vendor — reject it
                    # and try to find a coherent alternative
                    return self._find_coherent_hostname(
                        resolved_vendor, evidence,
                    )
        return hostname

    def _find_coherent_hostname(
        self, resolved_vendor: str, evidence: list[Evidence],
    ) -> str | None:
        """Find the best hostname from evidence that is coherent with the vendor."""
        import re
        from leetha.evidence.hostname import is_valid_hostname

        candidates: list[tuple[str, float]] = []
        for e in evidence:
            if not e.hostname:
                continue
            # Skip hostnames from mDNS sources with wrong or missing vendor
            if e.source.startswith("mdns"):
                if e.vendor and e.vendor != resolved_vendor:
                    continue
                if not e.vendor:
                    continue  # mDNS hostname with no vendor — suspect

            hn = e.hostname
            hn = re.sub(r'^[0-9A-Fa-f]{6,12}@', '', hn)
            if "._" in hn:
                hn = hn.split("._")[0]
            hn = re.sub(r'-[0-9a-f]{12,}$', '', hn, flags=re.IGNORECASE)
            if hn.endswith(".local"):
                hn = hn[:-6]
            hn = hn.strip(".-")
            if not hn or not is_valid_hostname(hn):
                continue

            weight = _SOURCE_WEIGHTS.get(e.source) or _SOURCE_WEIGHTS.get(
                e.source.rsplit("_", 1)[0] if "_" in e.source else e.source, 0.5)
            score = e.certainty * weight
            candidates.append((hn, score))

        if not candidates:
            return None
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]
