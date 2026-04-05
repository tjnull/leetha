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
    "mdns_exclusive": 0.96,  # vendor-exclusive services (Apple, Google, etc.)
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
    "mdns_name": 0.60,
    # Banner source
    "passive_banner": 0.85,
    # IoT/SCADA sources
    "modbus": 0.60,
    "bacnet": 0.65,
    "coap": 0.50,
    "mqtt": 0.55,
    "enip": 0.65,
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
        items.sort(key=lambda e: e.observed_at, reverse=True)
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

        return Verdict(
            hw_addr=hw_addr,
            category=category[0],
            vendor=vendor[0],
            platform=platform[0],
            platform_version=platform_version[0],
            model=model[0],
            hostname=hostname[0],
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

            weight = _SOURCE_WEIGHTS.get(e.source, 0.5)
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
