"""Fingerprint signal fusion and device identity resolution.

Collects identification signals from diverse network sources (MAC OUI,
TCP stack analysis, service banners, DHCP options, mDNS/SSDP discovery,
etc.) and resolves them into a single coherent device profile through
weighted ballot consensus with cross-validation guards.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signal trust tiers -- single source of truth in evidence/weights.py.
# Re-exported here so existing consumers keep working.
# ---------------------------------------------------------------------------

from leetha.evidence.weights import SOURCE_WEIGHTS, FALLBACK_TRUST as _FALLBACK_TRUST


# ---------------------------------------------------------------------------
# Core data container
# ---------------------------------------------------------------------------

@dataclass
class FingerprintMatch:
    """Single identification signal produced by one fingerprint source."""

    source: str
    match_type: str
    confidence: float

    device_type: str | None = None
    category: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    vendor: str | None = None
    raw_data: dict = field(default_factory=dict)

    def effective_weight(self) -> float:
        """Compute the ballot weight for this signal."""
        return SOURCE_WEIGHTS.get(self.source, _FALLBACK_TRUST) * self.confidence

    def __repr__(self) -> str:
        parts = [f"src={self.source!r}", f"conf={self.confidence:.2f}"]
        if self.manufacturer:
            parts.append(f"mfr={self.manufacturer!r}")
        if self.os_family:
            parts.append(f"os={self.os_family!r}")
        if self.device_type:
            parts.append(f"dev={self.device_type!r}")
        return f"FingerprintMatch({', '.join(parts)})"


# ---------------------------------------------------------------------------
# OUI device-type labels that represent product-line assumptions rather
# than confirmed observations.  When a real operating system has been
# verified by stack/banner/DHCP analysis, these guesses should be
# heavily discounted so the verified OS drives classification.
# ---------------------------------------------------------------------------

_SPECULATIVE_DEVICE_LABELS = frozenset({
    "smart_speaker", "media_player", "smart_tv", "phone", "smart_display",
    "iot", "thermostat", "ip_camera", "doorbell", "smart_plug",
    "smart_lighting", "smart_lock", "home_hub", "game_console",
    "streaming_device", "set_top_box", "wearable", "sensor",
    "router", "switch", "access_point", "wireless_bridge",
})


# ---------------------------------------------------------------------------
# Full-stack operating systems -- indicates a general-purpose computing
# platform rather than a single-purpose appliance firmware.
# ---------------------------------------------------------------------------

_FULLSTACK_OS_NAMES = frozenset({
    "Linux", "Windows", "macOS", "FreeBSD", "OpenBSD", "NetBSD",
    "Solaris", "Unix", "AIX",
    "ESXi", "VMkernel", "vSphere", "vCenter",
    "Proxmox VE", "Proxmox", "Hyper-V", "XenServer", "AHV",
})

_FULLSTACK_OS_PREFIXES = (
    "linux", "windows", "freebsd", "openbsd", "netbsd", "unix",
    "kali", "parrot", "blackarch", "backbox", "pentoo", "archstrike",
    "caine", "deft", "tsurugi", "sift", "remnux", "tails", "whonix",
)


def _is_fullstack_os(name: str) -> bool:
    """Return True when *name* identifies a general-purpose operating system."""
    if name in _FULLSTACK_OS_NAMES:
        return True
    return name.lower().startswith(_FULLSTACK_OS_PREFIXES)


# Keep the old name accessible for external callers (tests import it)
_is_general_purpose_os = _is_fullstack_os


# ---------------------------------------------------------------------------
# Vendor-locked OS rules -- maps lower-cased OS family to the set of
# manufacturer substrings that legitimately ship that OS.  A mismatch
# with OUI data means the OS detection is almost certainly a false
# positive (e.g. macOS detected on Dell hardware).
# ---------------------------------------------------------------------------

_ANDROID_DEVICE_MAKERS = frozenset({
    "Google", "Pixel", "Samsung", "Xiaomi", "Huawei", "OnePlus", "Oppo",
    "Vivo", "Realme", "Honor", "Nothing", "Sony Mobile", "LG Mobile",
    "HTC", "Motorola", "Nokia", "Lenovo", "ASUS",
    "Infinix", "Tecno", "Meizu", "ZTE",
    "Sony TV", "TCL", "Hisense", "Chromecast", "Amazon",
    "Meta",
})

_OS_EXCLUSIVE_MANUFACTURERS: dict[str, frozenset[str]] = {
    # Apple ecosystem
    "macos":       frozenset({"Apple"}),
    "macos 13+":   frozenset({"Apple"}),
    "mac os x":    frozenset({"Apple"}),
    "darwin":      frozenset({"Apple"}),
    "ios":         frozenset({"Apple", "Cisco"}),
    "ios 16+":     frozenset({"Apple"}),
    "ios/macos":   frozenset({"Apple"}),
    "ipados":      frozenset({"Apple"}),
    "tvos":        frozenset({"Apple"}),
    "tvos/macos":  frozenset({"Apple"}),
    "watchos":     frozenset({"Apple"}),
    "audioos":     frozenset({"Apple"}),
    "visionos":    frozenset({"Apple"}),
    # Cisco proprietary
    "ios (cisco)":  frozenset({"Cisco"}),
    "cisco ios":    frozenset({"Cisco"}),
    "ios xe":       frozenset({"Cisco"}),
    "ios xr":       frozenset({"Cisco"}),
    "ios-xr":       frozenset({"Cisco"}),
    "nx-os":        frozenset({"Cisco"}),
    "asa":          frozenset({"Cisco"}),
    # Network equipment
    "routeros":     frozenset({"MikroTik", "Mikrotikls"}),
    "junos":        frozenset({"Juniper"}),
    "fortios":      frozenset({"Fortinet"}),
    "arubaos":      frozenset({"Aruba", "HPE"}),
    "pan-os":       frozenset({"Palo Alto"}),
    "edgeos":       frozenset({"Ubiquiti"}),
    "asuswrt":      frozenset({"ASUS", "ASUSTek"}),
    "exos":         frozenset({"Extreme"}),
    "fabricos":     frozenset({"Broadcom", "Brocade"}),
    "ontap":        frozenset({"NetApp"}),
    "procurve":     frozenset({"HP", "HPE", "Hewlett"}),
    "comware":      frozenset({"HP", "HPE", "H3C", "Hewlett"}),
    # Storage appliances
    "dsm":          frozenset({"Synology"}),
    "qts":          frozenset({"QNAP"}),
    "adm":          frozenset({"ASUSTOR"}),
    # Consumer/appliance locked OS
    "fire os":      frozenset({"Amazon"}),
    "cast os":      frozenset({"Google"}),
    "webos":        frozenset({"LG"}),
    "tizen":        frozenset({"Samsung"}),
    "roku":         frozenset({"Roku"}),
    "smartcast":    frozenset({"Vizio"}),
    "xbox":         frozenset({"Microsoft"}),
    "playstation":  frozenset({"Sony"}),
    # Android variants
    "android":      _ANDROID_DEVICE_MAKERS,
    "android 10+":  _ANDROID_DEVICE_MAKERS,
    "android 12+":  _ANDROID_DEVICE_MAKERS,
    "android tv":   _ANDROID_DEVICE_MAKERS,
    "oxygenos":     frozenset({"OnePlus"}),
    "coloros":      frozenset({"Oppo"}),
    "funtouch os":  frozenset({"Vivo"}),
    "realme ui":    frozenset({"Realme"}),
    "one ui":       frozenset({"Samsung"}),
    "miui":         frozenset({"Xiaomi"}),
    "hyperos":      frozenset({"Xiaomi"}),
    "emui":         frozenset({"Huawei"}),
    "harmonyos":    frozenset({"Huawei"}),
    "magicos":      frozenset({"Honor"}),
    "nothing os":   frozenset({"Nothing"}),
}


# ---------------------------------------------------------------------------
# Virtualisation / container vendors -- bypass OS-exclusivity checks
# because a VM or container can host any guest OS.
# ---------------------------------------------------------------------------

_VIRTUALISATION_VENDORS = frozenset({
    "VMware", "QEMU/KVM", "QEMU", "KVM", "Xen", "XCP-ng",
    "Citrix", "Docker", "Podman", "LXC", "Parallels",
    "VirtualBox", "Oracle VM", "bhyve", "Firecracker",
    "Nutanix", "Microsoft",
})


# Manufacturers that require OUI confirmation before trusting non-OUI signals
_HARDWARE_LOCKED_VENDORS = frozenset({"Apple"})

# Multi-product vendors: OUI/Huginn device_type is unreliable because the
# same vendor makes phones, TVs, appliances, etc.  For these, only trust
# device_type from protocol-level evidence (mDNS, SSDP, DHCP), not OUI.
_MULTI_PRODUCT_VENDORS = frozenset({
    "Samsung", "Samsung Electronics",
    "LG", "LG Electronics",
    "Sony",
    "Microsoft",
    "Google",
    "Amazon",
    "Xiaomi",
    "Huawei",
    "Dell",
    "HP", "Hewlett Packard", "Hewlett-Packard",
    "Lenovo",
    "ASUS", "ASUSTek",
    "Apple",
    "Roku",
    "Philips",
    "Panasonic",
    "TCL",
    "Bosch",
})


# ---------------------------------------------------------------------------
# OS-to-device-type and manufacturer-to-OS inference tables
# ---------------------------------------------------------------------------

_SERVER_OS_KEYWORDS = (
    "windows server", "esxi", "vmkernel", "vsphere", "vcenter",
    "proxmox", "hyper-v", "xenserver", "ahv",
)


def _derive_device_role_from_os(os_name: str) -> str:
    """Translate a confirmed OS family into a broad device role."""
    lowered = os_name.lower()
    for kw in _SERVER_OS_KEYWORDS:
        if kw in lowered:
            return "server"
    if "bsd" in lowered or "solaris" in lowered:
        return "server"
    # Mobile device class
    if lowered in ("ios", "ipados", "android", "watchos", "wear os", "harmonyos"):
        return "phone"
    if lowered == "tvos":
        return "media_player"
    if lowered in ("fire os", "cast os", "roku os", "tizen", "webos"):
        return "media_player"
    # Desktop / workstation class
    return "computer"


_VENDOR_TO_DEFAULT_OS: dict[str, str | dict[str, str]] = {
    "cisco": {"router": "IOS", "switch": "IOS", "firewall": "ASA", "_default": "IOS"},
    "juniper": "Junos",
    "arista": "EOS",
    "mikrotik": "RouterOS",
    "fortinet": "FortiOS",
    "palo alto": "PAN-OS",
    "ubiquiti": "UniFi OS",
    "aruba": "ArubaOS",
    "ruckus": "SmartZone",
    "draytek": "DrayOS",
    "vmware": {
        "hypervisor": "ESXi", "esxi": "ESXi",
        "virtual_machine": None, "virtual_router": None, "_default": None,
    },
    "broadcom": {"hypervisor": "ESXi", "server": "ESXi", "_default": None},
    "siemens": {"plc": "VxWorks", "hmi": "Windows CE", "_default": None},
    "schneider electric": {"plc": "VxWorks", "_default": None},
    "rockwell automation": {"plc": "VxWorks", "_default": None},
    "allen-bradley": {"plc": "VxWorks", "_default": None},
    "abb": {"plc": "QNX", "_default": None},
    "honeywell": {"plc": "VxWorks", "_default": None},
    "apple": {"phone": "iOS", "tablet": "iPadOS", "computer": "macOS", "smart_speaker": "HomePod OS", "smart_tv": "tvOS", "_default": "macOS"},
    "samsung": {"phone": "Android", "tablet": "Android", "smart_tv": "Tizen", "smart_speaker": "Android", "_default": None},
    "google": {"smart_speaker": "Cast OS", "smart_display": "Cast OS", "smart_home": "Cast OS", "phone": "Android", "_default": None},
    "amazon": {"smart_speaker": "Fire OS", "tablet": "Fire OS", "_default": None},
    "lutron": {"_default": None},
    "roborock": {"_default": None},
    "xiaomi": {"phone": "Android", "robot_vacuum": None, "_default": "Android"},
    "espressif": {"_default": None},
    "sony": {"game_console": "PlayStation", "_default": None},
    "nintendo": "Nintendo",
    "microsoft": {"game_console": "Xbox", "_default": None},
    "sonos": "Sonos S2",
    "roku": "RokuOS",
    "proxmox": {"hypervisor": "Proxmox VE", "_default": "Linux"},
    "citrix": {"hypervisor": "XenServer", "load_balancer": "NetScaler", "_default": None},
    "xen": {"hypervisor": "Xen", "_default": None},
    "xcp-ng": {"hypervisor": "XCP-ng", "_default": None},
    "docker": {"container_host": "Linux", "_default": None},
    "kubernetes": {"k8s_node": "Linux", "_default": None},
    "openstack": {"_default": "Linux"},
    "nutanix": {"hypervisor": "AHV", "_default": None},
    "ovirt": {"hypervisor": "oVirt", "_default": "Linux"},
    "digitalocean": {"_default": "Linux"},
    "hetzner": {"_default": "Linux"},
    "linode": {"_default": "Linux"},
    "openmediavault": {"nas": "Linux", "_default": "Linux"},
    "truenas": {"nas": "FreeBSD", "_default": "FreeBSD"},
    "unraid": {"nas": "Linux", "_default": "Linux"},
    "synology": {"nas": "DSM", "_default": "DSM"},
    "qnap": {"nas": "QTS", "_default": "QTS"},
}


# Vendor names that imply a specific device category when no other type is known.
_VENDOR_DEFAULT_DEVICE_TYPE: dict[str, str] = {
    "lutron": "smart_home",
    "chamberlain": "smart_home",
    "jbl": "smart_speaker",
    "sonos": "smart_speaker",
    "ecobee": "thermostat",
    "nest": "smart_home",
    "ring": "doorbell",
    "arlo": "camera",
    "wyze": "camera",
    "philips hue": "smart_lighting",
    "hue": "smart_lighting",
    "lifx": "smart_lighting",
    "tp-link": "smart_plug",
    "kasa": "smart_plug",
    "shelly": "smart_plug",
    "august": "smart_lock",
    "yale": "smart_lock",
    "gaoshengda": "smart_speaker",  # WiFi modules used in JBL/others
    "hui zhou gaoshengda": "smart_speaker",
    "openmediavault": "nas",
    "truenas": "nas",
    "freenas": "nas",
    "unraid": "nas",
    "synology": "nas",
    "qnap": "nas",
    "hikvision": "ip_camera",
    "dahua": "ip_camera",
    "amcrest": "ip_camera",
    "reolink": "ip_camera",
    "arlo": "camera",
    "roku": "streaming_device",
    "ecobee": "thermostat",
    "philips": "smart_lighting",
    "amazon": "smart_speaker",
    "nest": "smart_home",
}


def _guess_device_type_from_vendor(vendor_name: str) -> str | None:
    """Infer device category from manufacturer when no other type is known."""
    if not vendor_name:
        return None
    vendor_lc = vendor_name.lower()
    for pattern, dtype in _VENDOR_DEFAULT_DEVICE_TYPE.items():
        if pattern in vendor_lc:
            return dtype
    return None


def _guess_os_from_vendor(vendor_name: str, dev_role: str | None) -> str | None:
    """Attempt to derive an OS family from vendor name and device role."""
    vendor_lc = vendor_name.lower()
    for pattern, mapping in _VENDOR_TO_DEFAULT_OS.items():
        if pattern not in vendor_lc:
            continue
        if isinstance(mapping, str):
            return mapping
        if dev_role and dev_role in mapping:
            return mapping[dev_role]
        return mapping.get("_default")
    return None


# ---------------------------------------------------------------------------
# Cross-validation helpers
# ---------------------------------------------------------------------------

def _os_compatible_with_manufacturer(
    os_family: str, manufacturer: str | None,
) -> bool:
    """Determine whether *os_family* is plausible on hardware from *manufacturer*.

    Returns True when there is no exclusivity constraint, when the
    manufacturer matches an allowed vendor, or when the manufacturer
    is a virtualisation platform (VMs can host any guest OS).
    """
    if not manufacturer or not os_family:
        return True
    mfr_lc = manufacturer.lower()
    if any(v.lower() in mfr_lc for v in _VIRTUALISATION_VENDORS):
        return True
    permitted = _OS_EXCLUSIVE_MANUFACTURERS.get(os_family.lower())
    if permitted is None:
        return True
    return any(p.lower() in mfr_lc for p in permitted)


def _is_virtualisation_vendor(mfr: str) -> bool:
    """Check if a manufacturer string corresponds to a VM/container platform."""
    mfr_lc = mfr.lower()
    return any(v.lower() in mfr_lc for v in _VIRTUALISATION_VENDORS)


# ---------------------------------------------------------------------------
# Pre-processing passes that adjust signal confidence before voting
# ---------------------------------------------------------------------------

def _downweight_unconfirmed_locked_vendors(
    signals: list[FingerprintMatch],
) -> None:
    """Reduce confidence of hardware-locked vendor attributions lacking OUI backup.

    When a MAC address is randomised or the OUI is unrecognised, non-OUI
    sources can produce false manufacturer attributions.  The penalty
    scales with how few independent source types corroborate the claim:
      * single source type  -> multiply confidence by 0.10
      * two source types    -> multiply confidence by 0.35
      * three or more       -> no penalty (strong corroboration)
    """
    for locked_name in _HARDWARE_LOCKED_VENDORS:
        locked_lc = locked_name.lower()

        corroborating = [
            sig for sig in signals
            if sig.source != "oui"
            and sig.manufacturer
            and locked_lc in sig.manufacturer.lower()
        ]
        if not corroborating:
            continue

        # Exempt mDNS exclusive services — _companion-link._tcp,
        # _apple-mobdev2._tcp, etc. are DEFINITIVE vendor identifiers.
        # No false positives possible for these services.
        _DEFINITIVE_MDNS = {
            "_companion-link._tcp", "_apple-mobdev2._tcp", "_apple-mobdev._tcp",
            "_homekit._tcp", "_rdlink._tcp", "_touch-able._tcp",
            "_apple-pairable._tcp", "_googlecast._tcp", "_samsung-osp._tcp",
            "_samsungtvrc._tcp", "_amzn-wplay._tcp",
        }
        has_definitive = any(
            sig.source == "mdns" and sig.raw_data.get("service_type") in _DEFINITIVE_MDNS
            for sig in corroborating
        )
        if has_definitive:
            continue  # skip penalty — exclusive service is definitive proof

        distinct_sources = {sig.source for sig in corroborating}
        n_distinct = len(distinct_sources)
        if n_distinct >= 3:
            continue

        reduction = 0.10 if n_distinct <= 1 else 0.35

        for sig in corroborating:
            _log.debug(
                "Reducing confidence for manufacturer=%s via %s "
                "(no OUI, %d source(s): %s) factor=%.2f",
                sig.manufacturer, sig.source, n_distinct,
                distinct_sources, reduction,
            )
            sig.confidence *= reduction

            if n_distinct <= 1:
                sig.manufacturer = None

            if sig.os_family and sig.os_family.lower() in _OS_EXCLUSIVE_MANUFACTURERS:
                permitted = _OS_EXCLUSIVE_MANUFACTURERS[sig.os_family.lower()]
                if any(locked_lc in p.lower() for p in permitted):
                    sig.os_family = None
                    sig.os_version = None


def _invalidate_incompatible_os(
    signals: list[FingerprintMatch],
    oui_vendor: str | None,
) -> None:
    """Discard OS detections that conflict with the known OUI manufacturer.

    Only applies to non-fullstack OS families with exclusivity rules
    (e.g. Android on Cisco hardware, Tizen on Dell).  Full-stack OS
    conflicts are handled during the verified-OS scan.
    """
    if not oui_vendor:
        return
    for sig in signals:
        if sig.source == "oui" or not sig.os_family:
            continue
        if _is_fullstack_os(sig.os_family):
            continue
        if _os_compatible_with_manufacturer(sig.os_family, oui_vendor):
            continue
        _log.debug(
            "Discarding OS '%s' from %s -- incompatible with OUI vendor '%s'",
            sig.os_family, sig.source, oui_vendor,
        )
        sig.os_family = None
        sig.os_version = None
        sig.confidence *= 0.30


def _suppress_android_without_oui(signals: list[FingerprintMatch]) -> None:
    """Penalise Android attributions when no OUI is available.

    Android and Linux share DHCP option prefixes, so partial DHCP
    matches can incorrectly identify Linux hosts as Android.  When the
    MAC vendor is unknown, reduce Android signal confidence so that
    competing Linux signals dominate.
    """
    android_sigs = [
        s for s in signals
        if s.os_family and "android" in s.os_family.lower()
    ]
    if not android_sigs:
        return

    linux_sigs = [
        s for s in signals
        if s.os_family
        and _is_fullstack_os(s.os_family)
        and "android" not in s.os_family.lower()
    ]

    all_partial = all(
        s.raw_data.get("match_source", "").endswith("_partial")
        or (s.source == "dhcp_opt55" and s.match_type == "partial")
        for s in android_sigs
    )

    if not (linux_sigs or all_partial):
        return

    reason = "linux signals present" if linux_sigs else "partial DHCP only"
    for sig in android_sigs:
        _log.debug(
            "Reducing Android confidence from %s (no OUI, %s)",
            sig.source, reason,
        )
        sig.confidence *= 0.20


# ---------------------------------------------------------------------------
# Ballot tallying helpers
# ---------------------------------------------------------------------------

def _tally_ballots(
    signals: list[FingerprintMatch],
    verified_os: str | None,
    verified_os_src: str | None,
    verified_os_role: str | None,
) -> dict[str, dict[str, float]]:
    """Accumulate weighted votes for each identity dimension.

    Returns a mapping of dimension name to {candidate_value: accumulated_weight}.
    """
    dimensions = ("device_type", "manufacturer", "os_family")
    ballots: dict[str, dict[str, float]] = {dim: {} for dim in dimensions}

    for sig in signals:
        w = sig.effective_weight()

        for dim in dimensions:
            candidate = getattr(sig, dim, None)
            if candidate is None:
                continue

            adjusted_w = w

            # Discount speculative OUI device labels when a real OS is confirmed
            if (
                dim == "device_type"
                and verified_os
                and sig.source == "oui"
                and candidate in _SPECULATIVE_DEVICE_LABELS
            ):
                adjusted_w *= 0.15
                _log.debug(
                    "Discounting OUI device_type=%s (verified OS=%s from %s)",
                    candidate, verified_os, verified_os_src,
                )

            # Discount OUI non-server labels when a server-class OS is confirmed
            if (
                dim == "device_type"
                and verified_os_role == "server"
                and sig.source == "oui"
                and candidate != "server"
                and candidate not in _SPECULATIVE_DEVICE_LABELS
            ):
                adjusted_w *= 0.25
                _log.debug(
                    "Discounting OUI device_type=%s (server OS=%s verified)",
                    candidate, verified_os,
                )

            # Drop OUI/Huginn device_type for multi-product vendors entirely.
            # Samsung makes phones AND TVs — OUI can't tell which.
            # Only protocol-level evidence (mDNS, SSDP, DHCP) should
            # determine device_type for these vendors.
            if (
                dim == "device_type"
                and sig.source in ("oui", "huginn_mac", "huginn_device")
            ):
                mfr = getattr(sig, "manufacturer", "") or ""
                if any(vname.lower() in mfr.lower() for vname in _MULTI_PRODUCT_VENDORS):
                    continue  # skip this vote entirely

            ballots[dim][candidate] = ballots[dim].get(candidate, 0.0) + adjusted_w

    return ballots


def _pick_top_candidate(ballot: dict[str, float]) -> str | None:
    """Return the candidate with the highest accumulated weight, or None."""
    if not ballot:
        return None
    return max(ballot, key=ballot.__getitem__)


def _prune_contradictory_votes(
    ballots: dict[str, dict[str, float]],
    verified_os: str,
) -> None:
    """Remove manufacturer and OS votes that contradict a verified OS.

    When no OUI is present but a full-stack OS has been verified,
    eliminate votes from OS-exclusive ecosystems that do not match
    the verified OS (e.g. Apple manufacturer when OS is Linux).
    """
    verified_lc = verified_os.lower()

    # Prune manufacturer votes tied to incompatible exclusive ecosystems
    for mfr_candidate in list(ballots.get("manufacturer", {})):
        if not mfr_candidate:
            continue
        bound_os_families: set[str] = set()
        for os_key, permitted_mfrs in _OS_EXCLUSIVE_MANUFACTURERS.items():
            if any(p.lower() in mfr_candidate.lower() for p in permitted_mfrs):
                bound_os_families.add(os_key)
        if bound_os_families and not any(
            verified_lc == bound or verified_lc.startswith(bound)
            for bound in bound_os_families
        ):
            _log.debug(
                "Pruning manufacturer=%s (bound to %s, verified OS=%s, no OUI)",
                mfr_candidate, bound_os_families, verified_os,
            )
            del ballots["manufacturer"][mfr_candidate]

    # Prune non-fullstack OS votes from exclusive ecosystems
    for os_candidate in list(ballots.get("os_family", {})):
        if not os_candidate or os_candidate == verified_os:
            continue
        if _is_fullstack_os(os_candidate):
            continue
        if os_candidate.lower() in _OS_EXCLUSIVE_MANUFACTURERS:
            _log.debug(
                "Pruning os_family=%s (exclusive OS, verified=%s, no OUI)",
                os_candidate, verified_os,
            )
            del ballots["os_family"][os_candidate]


# ---------------------------------------------------------------------------
# Confidence computation
# ---------------------------------------------------------------------------

def _compute_overall_confidence(signals: list[FingerprintMatch]) -> float:
    """Weighted average of signal confidences normalised by trust weights."""
    numerator = 0.0
    denominator = 0.0
    for sig in signals:
        trust = SOURCE_WEIGHTS.get(sig.source, _FALLBACK_TRUST)
        numerator += trust * sig.confidence
        denominator += trust
    return numerator / denominator if denominator > 0.0 else 0.0


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_best_field(
    signals: list[FingerprintMatch],
    attr: str,
) -> Any:
    """Find the highest-confidence signal that populates *attr* and return its value."""
    relevant = [s for s in signals if getattr(s, attr, None) is not None]
    if not relevant:
        return None
    best = max(relevant, key=lambda s: s.confidence)
    return getattr(best, attr)


def _build_evidence_trail(signals: list[FingerprintMatch]) -> list[dict[str, Any]]:
    """Serialise each signal into a summary dict for the output evidence list."""
    trail: list[dict[str, Any]] = []
    for sig in signals:
        entry: dict[str, Any] = {
            "source": sig.source,
            "match_type": sig.match_type,
            "confidence": sig.confidence,
        }
        for optional in ("manufacturer", "device_type", "os_family", "os_version", "model"):
            val = getattr(sig, optional, None)
            if val is not None:
                entry[optional] = val
        trail.append(entry)
    return trail


# ---------------------------------------------------------------------------
# Public API -- main fusion entry point
# ---------------------------------------------------------------------------

_EMPTY_PROFILE: dict[str, Any] = {
    "device_type": "Unknown",
    "manufacturer": None,
    "model": None,
    "os_family": None,
    "os_version": None,
    "confidence": 0.0,
    "evidence": [],
}


def aggregate_evidence(matches: list[FingerprintMatch]) -> dict:
    """Fuse a collection of fingerprint signals into a unified device profile.

    Each signal votes for device attributes (manufacturer, device_type,
    os_family) with a weight derived from source trust and signal
    confidence.  Several cross-validation passes adjust or discard
    signals that are implausible given other evidence before the final
    ballot is tallied.

    The returned dict contains: device_type, manufacturer, model,
    os_family, os_version, confidence, evidence, and os_confirmed.
    """
    if not matches:
        return dict(_EMPTY_PROFILE)

    # --- Phase 1: locate the OUI vendor for cross-validation ----------
    oui_vendor: str | None = None
    for sig in matches:
        if sig.source == "oui" and sig.manufacturer:
            oui_vendor = sig.manufacturer
            break

    # --- Phase 2: pre-process signals (adjust confidences) ------------

    # 2a. Discard non-fullstack OS detections incompatible with OUI vendor
    _invalidate_incompatible_os(matches, oui_vendor)

    # 2b. Penalise hardware-locked vendors when OUI is absent
    if oui_vendor is None:
        _downweight_unconfirmed_locked_vendors(matches)

    # 2c. Penalise ambiguous Android signals when OUI is absent
    if oui_vendor is None:
        _suppress_android_without_oui(matches)

    # --- Phase 3: verify whether a full-stack OS is confirmed ---------
    verified_os: str | None = None
    verified_os_src: str | None = None

    sorted_matches = sorted(matches, key=lambda m: m.effective_weight(), reverse=True)
    for sig in sorted_matches:
        if sig.source == "oui" or not sig.os_family:
            continue
        if not _is_fullstack_os(sig.os_family):
            continue
        if _os_compatible_with_manufacturer(sig.os_family, oui_vendor):
            verified_os = sig.os_family
            verified_os_src = sig.source
            break
        # Incompatible full-stack OS (e.g. macOS on Dell) -- discard
        _log.debug(
            "Discarding OS '%s' from %s -- incompatible with OUI '%s'",
            sig.os_family, sig.source, oui_vendor,
        )
        sig.os_family = None
        sig.os_version = None
        sig.confidence *= 0.15

    verified_os_role = _derive_device_role_from_os(verified_os) if verified_os else None

    # --- Phase 4: tally weighted ballots ------------------------------
    ballots = _tally_ballots(matches, verified_os, verified_os_src, verified_os_role)

    # Cross-validate ballots when OS is verified but OUI is absent
    if verified_os and not oui_vendor:
        _prune_contradictory_votes(ballots, verified_os)

    # Inject a device-role vote derived from the verified OS
    if verified_os:
        role_from_os = _derive_device_role_from_os(verified_os)
        role_boost = SOURCE_WEIGHTS.get(verified_os_src or "tcp", 0.80) * 0.85
        ballots["device_type"][role_from_os] = (
            ballots["device_type"].get(role_from_os, 0.0) + role_boost
        )

    # Give OUI manufacturer a dominant boost so it always wins
    if oui_vendor:
        prev = ballots["manufacturer"].get(oui_vendor, 0.0)
        ballots["manufacturer"][oui_vendor] = prev + 2.0

    # --- Phase 5: pick winners ----------------------------------------
    chosen_device_type = _pick_top_candidate(ballots["device_type"])
    chosen_manufacturer = _pick_top_candidate(ballots["manufacturer"])
    chosen_os = _pick_top_candidate(ballots["os_family"])

    # Fallback: infer device type from manufacturer when no signal provided one
    if (chosen_device_type is None or chosen_device_type == "Unknown") and chosen_manufacturer:
        inferred_type = _guess_device_type_from_vendor(chosen_manufacturer)
        if inferred_type:
            chosen_device_type = inferred_type

    if not chosen_device_type:
        chosen_device_type = "Unknown"

    # Fallback: infer OS from manufacturer when no signal provided one
    if chosen_os is None and chosen_manufacturer is not None:
        chosen_os = _guess_os_from_vendor(chosen_manufacturer, chosen_device_type)

    # --- Phase 6: assemble the output profile -------------------------
    return {
        "device_type": chosen_device_type,
        "manufacturer": chosen_manufacturer,
        "model": _extract_best_field(matches, "model"),
        "os_family": chosen_os,
        "os_version": _extract_best_field(matches, "os_version"),
        "confidence": _compute_overall_confidence(matches),
        "evidence": _build_evidence_trail(matches),
        "os_confirmed": verified_os is not None,
    }
