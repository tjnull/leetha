"""Core evidence and verdict data models.

Evidence represents a single piece of fingerprint intelligence gathered
from a network observation. Verdict is the computed assessment of a
host's identity, derived by fusing all available evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class Evidence:
    """A single piece of fingerprint intelligence from a network observation."""

    source: str         # e.g. "lldp", "dhcpv4", "tcp_syn", "probe"
    method: str         # "exact", "pattern", "heuristic"
    certainty: float    # 0.0-1.0

    # What this evidence reveals (all optional — each source contributes different fields)
    category: str | None = None
    vendor: str | None = None
    platform: str | None = None
    platform_version: str | None = None
    model: str | None = None
    hostname: str | None = None

    # Provenance
    raw: dict = field(default_factory=dict)
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["observed_at"] = self.observed_at.isoformat()
        return d

    @property
    def weight(self) -> float:
        """Effective weight combining source reliability and certainty."""
        return self.certainty


@dataclass
class Verdict:
    """Computed assessment of a host's identity from fused evidence."""

    hw_addr: str
    category: str | None = None
    vendor: str | None = None
    platform: str | None = None
    platform_version: str | None = None
    model: str | None = None
    hostname: str | None = None
    certainty: int = 0     # 0-100 overall confidence
    evidence_chain: list[Evidence] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        d = {
            "hw_addr": self.hw_addr,
            "category": self.category,
            "vendor": self.vendor,
            "platform": self.platform,
            "platform_version": self.platform_version,
            "model": self.model,
            "hostname": self.hostname,
            "certainty": self.certainty,
            "computed_at": self.computed_at.isoformat(),
            "evidence_chain": [e.to_dict() for e in self.evidence_chain],
        }
        return d

    @property
    def is_classified(self) -> bool:
        """True if we have at least a category or vendor identified."""
        return bool(self.category or self.vendor)
