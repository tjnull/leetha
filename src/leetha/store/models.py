from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from datetime import timezone as _tz
from enum import StrEnum


class AlertType(StrEnum):
    NEW_DEVICE = "new_device"
    OS_CHANGE = "os_change"
    SPOOFING = "spoofing"
    MAC_SPOOFING = "mac_spoofing"
    INFRA_OFFLINE = "infra_offline"
    UNCLASSIFIED = "unclassified"
    SOURCE_STALE = "source_stale"
    MAC_RANDOMIZED = "mac_randomized"
    DHCP_ANOMALY = "dhcp_anomaly"


class AlertSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Device:
    mac: str
    ip_v4: str | None = None
    ip_v6: str | None = None
    manufacturer: str | None = None
    device_type: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    confidence: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    alert_status: str = "new"
    raw_evidence: dict = field(default_factory=dict)
    is_randomized_mac: bool = False
    correlated_mac: str | None = None
    identity_id: int | None = None
    manual_override: dict | None = None

    def to_dict(self) -> dict:
        import re
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        hn = d.get("hostname")
        if hn and ("._tcp." in hn or "._udp." in hn or hn.endswith(".local")):
            c = hn.rstrip(".")
            if "._tcp." in c or "._udp." in c:
                parts = c.split("._")
                inst, svc = parts[0], (parts[1] if len(parts) > 1 else "")
                inst = re.sub(r'-[0-9a-f]{12,}$', '', inst, flags=re.IGNORECASE)
                c = svc if (len(inst) <= 5 and svc and svc not in ("tcp", "udp")) else inst
            if c.endswith(".local"):
                c = c[:-6]
            d["hostname"] = c.rstrip(".") or hn
        return d

    @classmethod
    def from_row(cls, row):
        """Create Device from SQLite row (supports both named and positional access)."""
        import re
        from datetime import datetime

        def _clean_hn(name):
            """Strip mDNS service suffixes and .local from hostnames."""
            if not name:
                return name
            c = name.rstrip(".")
            if "._tcp." in c or "._udp." in c:
                parts = c.split("._")
                instance = parts[0]
                service = parts[1] if len(parts) > 1 else ""
                instance = re.sub(r'-[0-9a-f]{12,}$', '', instance, flags=re.IGNORECASE)
                if len(instance) <= 5 and service and service not in ("tcp", "udp"):
                    c = service
                else:
                    c = instance
            if c.endswith(".local"):
                c = c[:-6]
            return c.rstrip(".") or name

        def _get(key, idx, default=None):
            """Try named access first, fall back to positional index."""
            try:
                val = row[key]
                return val
            except (KeyError, TypeError, IndexError):
                pass
            try:
                if idx < len(row):
                    return row[idx]
            except TypeError:
                pass
            return default

        def _dt(key, idx):
            val = _get(key, idx)
            if val and isinstance(val, str):
                try:
                    return datetime.fromisoformat(val)
                except (ValueError, TypeError):
                    pass
            return datetime.now(_tz.utc)

        raw_ev = _get("raw_evidence", 12)
        override = _get("manual_override", 16)

        return cls(
            mac=_get("mac", 0, ""),
            ip_v4=_get("ip_v4", 1),
            ip_v6=_get("ip_v6", 2),
            manufacturer=_get("manufacturer", 3),
            device_type=_get("device_type", 4),
            os_family=_get("os_family", 5),
            os_version=_get("os_version", 6),
            hostname=_clean_hn(_get("hostname", 7)),
            confidence=_get("confidence", 8, 0),
            first_seen=_dt("first_seen", 9),
            last_seen=_dt("last_seen", 10),
            alert_status=_get("alert_status", 11, "new"),
            raw_evidence=json.loads(raw_ev) if isinstance(raw_ev, str) else (raw_ev or {}),
            is_randomized_mac=bool(_get("is_randomized_mac", 13, False)),
            correlated_mac=_get("correlated_mac", 14),
            identity_id=_get("identity_id", 15),
            manual_override=json.loads(override) if isinstance(override, str) else override,
        )


@dataclass
class DeviceIdentity:
    """A logical device identity, grouping one or more MAC addresses."""
    primary_mac: str
    id: int | None = None
    manufacturer: str | None = None
    device_type: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    confidence: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    correlation_fingerprint: dict = field(default_factory=dict)
    # Populated by JOIN queries, not stored directly:
    mac_count: int = 1
    all_macs: list[str] = field(default_factory=list)
    ip_v4: str | None = None
    ip_v6: str | None = None

    def to_dict(self) -> dict:
        import re
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        # Clean mDNS service instance hostnames at serialization
        for key in ("hostname",):
            hn = d.get(key)
            if hn and ("._tcp." in hn or "._udp." in hn or hn.endswith(".local")):
                c = hn.rstrip(".")
                if "._tcp." in c or "._udp." in c:
                    parts = c.split("._")
                    inst, svc = parts[0], (parts[1] if len(parts) > 1 else "")
                    inst = re.sub(r'-[0-9a-f]{12,}$', '', inst, flags=re.IGNORECASE)
                    c = svc if (len(inst) <= 5 and svc and svc not in ("tcp", "udp")) else inst
                if c.endswith(".local"):
                    c = c[:-6]
                d[key] = c.rstrip(".") or hn
        # Also clean hostname in nested correlation_fingerprint
        cf = d.get("correlation_fingerprint", {})
        if isinstance(cf, dict) and cf.get("hostname"):
            cfh = cf["hostname"]
            if "._tcp." in cfh or "._udp." in cfh or cfh.endswith(".local"):
                c2 = cfh.rstrip(".")
                if "._tcp." in c2 or "._udp." in c2:
                    parts2 = c2.split("._")
                    inst2, svc2 = parts2[0], (parts2[1] if len(parts2) > 1 else "")
                    inst2 = re.sub(r'-[0-9a-f]{12,}$', '', inst2, flags=re.IGNORECASE)
                    c2 = svc2 if (len(inst2) <= 5 and svc2 and svc2 not in ("tcp", "udp")) else inst2
                if c2.endswith(".local"):
                    c2 = c2[:-6]
                cf["hostname"] = c2.rstrip(".") or cfh
        return d


@dataclass
class Observation:
    device_mac: str
    source_type: str
    raw_data: str
    match_result: str
    confidence: int
    id: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    interface: str | None = None
    network: str | None = None


@dataclass
class Alert:
    device_mac: str
    alert_type: AlertType
    severity: AlertSeverity
    message: str
    id: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    acknowledged: bool = False


# ── New domain types for leetha architecture ──

class FindingRule(StrEnum):
    """Rules that generate findings (replaces AlertType in new architecture)."""
    NEW_HOST = "new_host"
    PLATFORM_DRIFT = "platform_drift"
    ADDR_CONFLICT = "addr_conflict"
    LOW_CERTAINTY = "low_certainty"
    STALE_SOURCE = "stale_source"
    RANDOMIZED_ADDR = "randomized_addr"
    DHCP_ANOMALY = "dhcp_anomaly"
    IDENTITY_SHIFT = "identity_shift"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    SENSOR_CONNECT = "sensor_connect"
    SENSOR_DISCONNECT = "sensor_disconnect"


@dataclass
class Host:
    """A network entity identified by its hardware address."""
    hw_addr: str
    ip_addr: str | None = None
    ip_v6: str | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    last_active: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    mac_randomized: bool = False
    real_hw_addr: str | None = None
    disposition: str = "new"  # "new", "known", "self"
    identity_id: int | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["discovered_at"] = self.discovered_at.isoformat()
        d["last_active"] = self.last_active.isoformat()
        return d


@dataclass
class Finding:
    """A noteworthy event: anomaly, threat, or change."""
    hw_addr: str
    rule: FindingRule
    severity: AlertSeverity  # reuse existing severity enum
    message: str
    id: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    resolved: bool = False
    status: str = "new"  # new, reviewing, resolved, false_positive, snoozed
    disposition: str | None = None  # true_positive, false_positive, benign
    snoozed_until: datetime | None = None
    notes: str | None = None


@dataclass
class Sighting:
    """A single protocol observation of a host."""
    hw_addr: str
    source: str
    payload: dict = field(default_factory=dict)
    analysis: dict = field(default_factory=dict)
    certainty: float = 0.0
    interface: str | None = None
    network: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(_tz.utc))


@dataclass
class Identity:
    """A resolved device identity, grouping attributes across sightings."""
    primary_mac: str
    id: int | None = None
    manufacturer: str | None = None
    device_type: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    confidence: int = 0
    fingerprint: dict = field(default_factory=dict)
    first_seen: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(_tz.utc))
