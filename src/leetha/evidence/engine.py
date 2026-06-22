"""Verdict computation engine.

Fuses multiple Evidence objects into a single Verdict per host. Uses
weighted certainty based on source reliability and agreement boosting
when independent sources agree on the same value.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from leetha.evidence.models import Evidence, Verdict

logger = logging.getLogger(__name__)

# Source reliability weights — single source of truth in evidence/weights.py
from leetha.evidence.weights import SOURCE_WEIGHTS as _SOURCE_WEIGHTS

# Agreement boost: when N independent sources agree, multiply certainty
_AGREEMENT_BONUS = {1: 1.0, 2: 1.1, 3: 1.2, 4: 1.25}

# Values that are non-answers — they must never win a fused field.
_JUNK_VALUES = frozenset({"unknown", "unidentified", "n/a", ""})


def _is_multi_product_vendor(vendor: str | None) -> bool:
    """True for vendors that make many device classes (Samsung, LG, ...).

    Their IEEE OUI registry device-type is an unreliable CATEGORY hint (a
    Samsung OUI block is generically "Phone" even for a Samsung TV), so the
    OUI category must yield to behavioural evidence for these vendors.
    """
    if not vendor:
        return False
    from leetha.fingerprint.evidence import _MULTI_PRODUCT_VENDORS
    vl = vendor.lower()
    return any(v.lower() in vl for v in _MULTI_PRODUCT_VENDORS)


def _source_family(source: str) -> str:
    """Collapse correlated evidence sources into a single family.

    Satori and the Huginn-Muninn datasets share the same upstream lineage,
    so several of them "agreeing" is not independent corroboration. Counting
    them as one family for the agreement boost stops stale fingerprint-DB
    guesses from ganging up to overrule a strong authoritative source (e.g.
    the IEEE OUI vendor).
    """
    if source.startswith("satori") or source.startswith("huginn"):
        return "fingerprint_db"
    return source


def _combined_score(per_source_best: dict[str, float]) -> float:
    """Fuse one candidate value's per-source scores into a single score.

    Dominated by the single best (highest-weight) source, with only a small,
    bounded bonus for additional INDEPENDENT source families — rather than an
    unbounded sum where many weak/correlated sources overrun a strong one.
    """
    if not per_source_best:
        return 0.0
    best = max(per_source_best.values())
    families = {_source_family(s) for s in per_source_best}
    boost = _AGREEMENT_BONUS.get(min(len(families), 4), 1.25)
    return best * boost


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

        # Vendor first: it decides whether to trust the OUI device-type as a
        # category signal. For multi-product vendors (Samsung/LG/...) the OUI
        # category is an unreliable hint and must yield to behavioural
        # evidence (SSDP/mDNS), so demote it for the category fusion only.
        vendor = self._fuse_field(evidence, "vendor")
        cat_demote = {"oui": 0.4} if _is_multi_product_vendor(vendor[0]) else None
        category = self._fuse_field(evidence, "category", demote=cat_demote)
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
            computed_at=datetime.now(timezone.utc),
        )

    def update(self, existing: Verdict, new_evidence: list[Evidence]) -> Verdict:
        """Incrementally update a verdict with new evidence.

        Appends new evidence to the chain and recomputes.
        """
        all_evidence = list(existing.evidence_chain) + list(new_evidence)
        return self.compute(existing.hw_addr, all_evidence)

    def _fuse_field(self, evidence: list[Evidence], field: str,
                    demote: dict[str, float] | None = None) -> tuple[str | None, float]:
        """Fuse a single field from all evidence, returning (value, score).

        Each value is scored by its best (highest-weight) source times a
        bounded agreement boost over independent source families. ``demote``
        optionally scales specific sources' weight for this field (e.g. the
        OUI device-type for a multi-product vendor). Non-answer values
        (``unknown`` etc.) are ignored.
        """
        # value -> {source: best score from that source}. Keeping only the
        # best score per source de-duplicates repeated identical evidence
        # (which would otherwise double-count in the fusion).
        per_source: dict[str, dict[str, float]] = {}

        for e in evidence:
            value = getattr(e, field, None)
            if value is None or str(value).strip().lower() in _JUNK_VALUES:
                continue

            weight = _SOURCE_WEIGHTS.get(e.source) or _SOURCE_WEIGHTS.get(
                e.source.rsplit("_", 1)[0] if "_" in e.source else e.source, 0.5)
            if demote:
                weight *= demote.get(e.source, 1.0)
            score = e.certainty * weight

            ss = per_source.setdefault(value, {})
            if score > ss.get(e.source, 0.0):
                ss[e.source] = score

        if not per_source:
            return (None, 0.0)

        candidates = {v: _combined_score(ss) for v, ss in per_source.items()}
        winner = max(candidates, key=candidates.get)  # type: ignore[arg-type]
        return (winner, min(candidates[winner], 1.0))

    def _next_valid_hostname(self, evidence: list[Evidence]) -> str | None:
        """Find the best valid hostname from evidence, skipping invalid ones."""
        import re
        from leetha.evidence.hostname import is_valid_hostname

        per_source: dict[str, dict[str, float]] = {}

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
            ss = per_source.setdefault(value, {})
            if score > ss.get(e.source, 0.0):
                ss[e.source] = score

        if not per_source:
            return None

        candidates = {v: _combined_score(ss) for v, ss in per_source.items()}
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
