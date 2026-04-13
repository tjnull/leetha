"""Network adapter scanning, routing-table queries, and persistent adapter selection.

Discovers available adapters on the host, classifies them by hardware kind,
reads the kernel routing table, and manages JSON-backed adapter configurations
that survive across sessions.
"""

from __future__ import annotations

import ipaddress
import json as _json
import logging
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Adapter-kind classification tables
# ---------------------------------------------------------------------------

# Maps prefix patterns to adapter kinds.  Checked in order; first match wins.
_KIND_RULES: list[tuple[tuple[str, ...], str]] = [
    (("docker", "veth", "virbr"), "virtual"),
    (("br",), "bridge"),
    (("tun", "tap", "wg"), "tunnel"),
    (("wl", "wlan"), "wireless"),
]


def _identify_adapter_kind(adapter_name: str) -> str:
    """Return the hardware kind for *adapter_name* based on naming conventions."""
    if adapter_name == "lo" or adapter_name.startswith("lo:"):
        return "loopback"
    for prefixes, kind in _KIND_RULES:
        if adapter_name.startswith(prefixes):
            return kind
    return "ethernet"


# ---------------------------------------------------------------------------
# Capture-strategy classification (tap / tun / physical)
# ---------------------------------------------------------------------------

def determine_capture_strategy(adapter_name: str) -> str:
    """Pick the capture strategy for *adapter_name*.

    Returns one of ``"tap"``, ``"tun"``, or ``"physical"``.
    The caller uses this to decide BPF filter breadth and promiscuous-mode.
    """
    lowered = adapter_name.lower()
    # WireGuard and utun (macOS) are L3-only like TUN
    for prefix, strategy in (("tap", "tap"), ("tun", "tun"), ("wg", "tun"), ("utun", "tun")):
        if lowered.startswith(prefix):
            return strategy
    return "physical"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AddressBinding:
    """One IP address assigned to a network adapter."""

    address: str
    netmask: str
    network: str          # CIDR, e.g. "10.0.0.0/24"
    family: str           # "ipv4" or "ipv6"
    active: bool = True   # whether the user selected this binding for capture

    # -- serialisation helpers ------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "netmask": self.netmask,
            "network": self.network,
            "family": self.family,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, mapping: dict) -> AddressBinding:
        return cls(
            address=mapping["address"],
            netmask=mapping["netmask"],
            network=mapping["network"],
            family=mapping["family"],
            active=mapping.get("active", True),
        )


@dataclass
class RoutingEntry:
    """One row from the kernel routing table."""

    destination: str        # CIDR or "default"
    gateway: str | None     # next-hop address, or None when directly connected
    interface: str
    source: str | None      # preferred source address
    metric: int = 0
    scope: str = "global"   # "global" / "link" / "host"


@dataclass
class NetworkAdapter:
    """A network adapter discovered on this host."""

    name: str
    mac: str | None
    bindings: list[AddressBinding]
    state: str              # "up" / "down"
    type: str               # ethernet / wireless / tunnel / bridge / loopback / virtual
    mtu: int = 1500
    routes: list[RoutingEntry] = field(default_factory=list)


@dataclass
class AdapterConfig:
    """Saved per-adapter settings chosen by the operator."""

    name: str
    type: str = "local"           # local / vpn / proxy / pivot
    label: str | None = None
    bpf_filter: str = ""          # manual BPF override; empty -> auto
    bindings: list[AddressBinding] = field(default_factory=list)
    probe_mode: str = "passive"   # "passive" or "probe-enabled"

    # -- derived properties ---------------------------------------------------

    @property
    def active_bindings(self) -> list[AddressBinding]:
        return [b for b in self.bindings if b.active]

    @property
    def attacker_ip(self) -> str | None:
        """Return the first active IPv4 address, or ``None``."""
        for binding in self.active_bindings:
            if binding.family == "ipv4":
                return binding.address
        return None

    # -- BPF generation -------------------------------------------------------

    def auto_bpf(self, base_filter: str) -> str:
        """Wrap *base_filter* with a network-scope clause built from active bindings.

        IPv6 networks are intentionally omitted because libpcap ``ip6 net``
        behaviour varies across versions; link-local IPv6 traffic is already
        caught by protocol-level filters (ICMPv6, DHCPv6, mDNS, etc.).
        """
        net_clauses = [
            f"net {b.network}"
            for b in self.active_bindings
            if b.family == "ipv4"
        ]
        if not net_clauses:
            return base_filter
        scope = " or ".join(net_clauses)
        return f"({scope}) and ({base_filter})"

    # -- serialisation --------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "label": self.label,
            "bpf_filter": self.bpf_filter,
            "bindings": [b.to_dict() for b in self.bindings],
            "probe_mode": self.probe_mode,
        }

    @classmethod
    def from_dict(cls, mapping: dict) -> AdapterConfig:
        return cls(
            name=mapping["name"],
            type=mapping.get("type", "local"),
            label=mapping.get("label"),
            bpf_filter=mapping.get("bpf_filter", ""),
            bindings=[
                AddressBinding.from_dict(b)
                for b in mapping.get("bindings", [])
            ],
            probe_mode=mapping.get("probe_mode", "passive"),
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_cidr(addr: str, mask: str) -> str:
    """Derive the CIDR network string from an address and its netmask."""
    try:
        return str(ipaddress.ip_interface(f"{addr}/{mask}").network)
    except ValueError:
        return f"{addr}/32"


_LINK_FAMILY = getattr(psutil, "AF_LINK", getattr(socket, "AF_PACKET", -1)) if psutil else -1

_V4_DEFAULT_MASK = "255.255.255.0"
_V6_DEFAULT_MASK = "ffff:ffff:ffff:ffff::"


def _extract_bindings_and_mac(
    addr_list: list,
) -> tuple[list[AddressBinding], str | None]:
    """Walk the per-adapter address list returned by psutil and split it
    into ``(bindings, mac_address)``."""
    collected: list[AddressBinding] = []
    hw_addr: str | None = None

    for entry in addr_list:
        fam = entry.family
        if fam == socket.AF_INET:
            mask = entry.netmask or _V4_DEFAULT_MASK
            collected.append(AddressBinding(
                address=entry.address,
                netmask=mask,
                network=_compute_cidr(entry.address, mask),
                family="ipv4",
            ))
        elif fam == socket.AF_INET6:
            raw_addr = entry.address.split("%")[0]
            mask = entry.netmask or _V6_DEFAULT_MASK
            collected.append(AddressBinding(
                address=raw_addr,
                netmask=mask,
                network=_compute_cidr(raw_addr, mask),
                family="ipv6",
            ))
        elif fam == _LINK_FAMILY:
            hw_addr = entry.address

    return collected, hw_addr


# ---------------------------------------------------------------------------
# Adapter scanning
# ---------------------------------------------------------------------------

def scan_adapters(include_down: bool = False) -> list[NetworkAdapter]:
    """Probe the OS for network adapters, returning one `NetworkAdapter` per NIC.

    Loopback devices are silently skipped.  Adapters in the *down* state are
    included only when *include_down* is ``True``.
    """
    if psutil is None:
        _log.warning("psutil unavailable -- adapter scanning disabled")
        return []

    all_addrs = psutil.net_if_addrs()
    all_stats = psutil.net_if_stats()
    adapters: list[NetworkAdapter] = []

    for iface_name in sorted(all_addrs):
        kind = _identify_adapter_kind(iface_name)
        if kind == "loopback":
            continue

        stat_info = all_stats.get(iface_name)
        up = stat_info.isup if stat_info else False
        if not up and not include_down:
            continue

        bindings, mac = _extract_bindings_and_mac(all_addrs[iface_name])
        adapters.append(NetworkAdapter(
            name=iface_name,
            mac=mac,
            bindings=bindings,
            state="up" if up else "down",
            type=kind,
            mtu=stat_info.mtu if stat_info else 1500,
        ))

    return adapters


# ---------------------------------------------------------------------------
# Routing table
# ---------------------------------------------------------------------------

def read_routing_table() -> list[RoutingEntry]:
    """Query the kernel routing table and return a list of `RoutingEntry` objects.

    Uses ``ip -j route`` for structured JSON output.  Returns an empty list
    when the command is unavailable or fails.
    """
    from leetha.platform import get_routes as _platform_routes
    try:
        raw_entries = _platform_routes()
    except Exception:
        return []

    return [
        RoutingEntry(
            destination=row.get("dst", "default"),
            gateway=row.get("gateway"),
            interface=row.get("dev", ""),
            source=row.get("prefsrc"),
            metric=row.get("metric", 0),
            scope=row.get("scope", "global"),
        )
        for row in raw_entries
    ]


def resolve_source_for_target(
    target_ip: str,
    table: list[RoutingEntry],
) -> tuple[str, str] | None:
    """Find the (adapter, source_ip) pair best suited to reach *target_ip*.

    Performs longest-prefix matching across *table*; the default route acts as
    a fallback when no more-specific entry matches.
    """
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return None

    winner: RoutingEntry | None = None
    longest = -1

    for row in table:
        if row.destination == "default":
            if longest < 0:
                winner, longest = row, 0
            continue
        try:
            net = ipaddress.ip_network(row.destination, strict=False)
        except ValueError:
            continue
        if target in net and net.prefixlen > longest:
            winner, longest = row, net.prefixlen

    if winner is not None and winner.source:
        return (winner.interface, winner.source)
    return None


# ---------------------------------------------------------------------------
# Enrichment and ranking
# ---------------------------------------------------------------------------

def augment_adapters(
    adapters: list[NetworkAdapter],
    table: list[RoutingEntry],
) -> None:
    """Attach each `RoutingEntry` in *table* to its owning adapter in-place."""
    by_name = {a.name: a for a in adapters}
    for entry in table:
        owner = by_name.get(entry.interface)
        if owner is not None:
            owner.routes.append(entry)


# Ranking weights: lower value = higher priority.
_KIND_PRIORITY = {
    "ethernet": 0,
    "wireless": 1,
    "tunnel": 2,
    "bridge": 3,
    "virtual": 4,
}


def rank_adapters(adapters: list[NetworkAdapter]) -> list[NetworkAdapter]:
    """Sort adapters so that real hardware comes first, virtual last, up before down."""
    return sorted(adapters, key=lambda a: (
        _KIND_PRIORITY.get(a.type, 3),
        0 if a.state == "up" else 1,
        a.name,
    ))


# ---------------------------------------------------------------------------
# Persistent adapter selection (JSON file)
# ---------------------------------------------------------------------------

_STORAGE_FILENAME = "interfaces.json"


def persist_adapter_selection(
    data_dir: Path,
    configs: list[AdapterConfig],
) -> None:
    """Atomically write the operator's adapter selection to disk."""
    from datetime import datetime as _dt

    payload = {
        "selected": [cfg.to_dict() for cfg in configs],
        "auto_resume": True,
        "last_updated": _dt.now().isoformat(),
    }
    dest = data_dir / _STORAGE_FILENAME
    fd, scratch = tempfile.mkstemp(dir=data_dir, suffix=".tmp")
    try:
        with open(fd, "w") as fh:
            _json.dump(payload, fh, indent=2)
        Path(scratch).replace(dest)
    except Exception:
        Path(scratch).unlink(missing_ok=True)
        raise


def load_saved_adapters(data_dir: Path) -> list[AdapterConfig]:
    """Read previously saved adapter configs.  Returns ``[]`` on any error."""
    path = data_dir / _STORAGE_FILENAME
    if not path.exists():
        return []
    try:
        blob = _json.loads(path.read_text())
        return [AdapterConfig.from_dict(d) for d in blob.get("selected", [])]
    except (ValueError, KeyError, _json.JSONDecodeError):
        return []


# ===================================================================
# Backward-compatibility aliases
#
# Other modules throughout the project import the original names.
# These aliases ensure everything keeps working without changes.
# ===================================================================

# Dataclass aliases
IPBinding = AddressBinding
InterfaceConfig = AdapterConfig
Route = RoutingEntry
DetectedInterface = NetworkAdapter

# Function aliases
classify_capture_mode = determine_capture_strategy
classify_interface_type = _identify_adapter_kind
detect_interfaces = scan_adapters
sort_interfaces = rank_adapters
get_routes = read_routing_table
get_source_for_target = resolve_source_for_target
enrich_interfaces = augment_adapters
save_interface_config = persist_adapter_selection
load_interface_config = load_saved_adapters

# Private helper alias (kept for completeness)
_netmask_to_cidr = _compute_cidr
