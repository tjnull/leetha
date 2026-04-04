"""DNS behavioral profiling for drift detection.

Tracks per-host DNS query vendor affinity in an adaptive rolling window.
Detects when a host's DNS profile shifts dramatically, indicating a
possible device swap or MAC spoofing attack.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field

from leetha.evidence.models import Evidence


_MIN_QUERIES_FOR_PROFILE = 20
_AFFINITY_EVIDENCE_THRESHOLD = 0.80
_LEARNING_PERIOD_SECONDS = 600
_EARLY_DRIFT_THRESHOLD = 0.60
_STABLE_DRIFT_THRESHOLD = 0.50
_STABLE_DRIFT_DURATION = 1800
_FIRST_HOUR_SECONDS = 3600


@dataclass
class _HostProfile:
    first_seen: float = field(default_factory=time.monotonic)
    vendor_counts: Counter = field(default_factory=Counter)
    total_classified: int = 0
    total_queries: int = 0
    baseline_vendor: str | None = None
    baseline_locked: bool = False
    drift_detected_at: float | None = None


class DnsBehaviorTracker:
    """Track DNS vendor affinity per host for behavioral drift detection."""

    def __init__(self):
        self._profiles: dict[str, _HostProfile] = {}

    def record(self, hw_addr: str, query_name: str, query_type: int) -> None:
        vendor = self._classify_domain(query_name)

        if hw_addr not in self._profiles:
            self._profiles[hw_addr] = _HostProfile()

        profile = self._profiles[hw_addr]
        profile.total_queries += 1

        if vendor:
            profile.vendor_counts[vendor] += 1
            profile.total_classified += 1

            if (not profile.baseline_locked
                    and profile.total_classified >= _MIN_QUERIES_FOR_PROFILE):
                age = time.monotonic() - profile.first_seen
                if age >= _LEARNING_PERIOD_SECONDS:
                    profile.baseline_vendor = profile.vendor_counts.most_common(1)[0][0]
                    profile.baseline_locked = True

    def get_profile(self, hw_addr: str) -> dict | None:
        profile = self._profiles.get(hw_addr)
        if profile is None:
            return None

        top = profile.vendor_counts.most_common(1)
        top_vendor = top[0][0] if top else None
        top_pct = (top[0][1] / profile.total_classified * 100
                   if top and profile.total_classified > 0 else 0)

        return {
            "query_count": profile.total_queries,
            "classified_count": profile.total_classified,
            "top_vendor": top_vendor,
            "top_vendor_pct": round(top_pct, 1),
            "baseline_vendor": profile.baseline_vendor,
            "vendors": dict(profile.vendor_counts),
        }

    def is_profiled(self, hw_addr: str) -> bool:
        profile = self._profiles.get(hw_addr)
        if profile is None:
            return False
        return profile.total_classified >= _MIN_QUERIES_FOR_PROFILE

    def check_drift(self, hw_addr: str) -> dict | None:
        profile = self._profiles.get(hw_addr)
        if profile is None or not profile.baseline_locked:
            return None

        if profile.total_classified < _MIN_QUERIES_FOR_PROFILE:
            return None

        current_top = profile.vendor_counts.most_common(1)
        if not current_top:
            return None

        current_vendor = current_top[0][0]
        current_pct = current_top[0][1] / profile.total_classified

        if current_vendor == profile.baseline_vendor:
            profile.drift_detected_at = None
            return None

        baseline_count = profile.vendor_counts.get(profile.baseline_vendor, 0)
        baseline_pct = baseline_count / profile.total_classified if profile.total_classified else 0

        age = time.monotonic() - profile.first_seen

        if age < _FIRST_HOUR_SECONDS:
            threshold = _EARLY_DRIFT_THRESHOLD
        else:
            threshold = _STABLE_DRIFT_THRESHOLD

        displacement = 1.0 - baseline_pct
        if displacement >= threshold and current_pct >= 0.40:
            now = time.monotonic()

            if age >= _FIRST_HOUR_SECONDS:
                if profile.drift_detected_at is None:
                    profile.drift_detected_at = now
                    return None
                if now - profile.drift_detected_at < _STABLE_DRIFT_DURATION:
                    return None

            return {
                "from_vendor": profile.baseline_vendor,
                "from_pct": round(baseline_pct * 100, 1),
                "to_vendor": current_vendor,
                "to_pct": round(current_pct * 100, 1),
                "observation_minutes": round(age / 60, 1),
            }

        profile.drift_detected_at = None
        return None

    def get_affinity_evidence(self, hw_addr: str) -> Evidence | None:
        """Return Evidence when a host has a confident vendor affinity.

        After the learning period, if a single vendor accounts for
        >= 80% of classified DNS queries, emit an Evidence object so
        the verdict pipeline can incorporate behavioral signals.
        """
        profile = self._profiles.get(hw_addr)
        if profile is None or not profile.baseline_locked:
            return None

        if profile.total_classified < _MIN_QUERIES_FOR_PROFILE:
            return None

        # Build affinity distribution
        affinity: dict[str, float] = {}
        for vendor, count in profile.vendor_counts.items():
            affinity[vendor] = round(count / profile.total_classified, 4)

        top = profile.vendor_counts.most_common(1)
        if not top:
            return None

        top_vendor = top[0][0]
        top_pct = top[0][1] / profile.total_classified

        if top_pct < _AFFINITY_EVIDENCE_THRESHOLD:
            return None

        return Evidence(
            source="dns_behavioral",
            method="heuristic",
            certainty=0.65,
            vendor=top_vendor,
            raw={"affinity": affinity},
        )

    def _classify_domain(self, domain: str) -> str | None:
        try:
            from leetha.patterns.matching import match_dns_query
            match = match_dns_query(domain, 1)
            if match and match.get("confidence", 0) >= 0.5:
                return match.get("manufacturer")
        except ImportError:
            pass
        return None
