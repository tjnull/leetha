"""
Signature matching engine for network device identification.

Provides a unified interface for correlating observed network artefacts
(MAC prefixes, TCP/IP stack behaviour, service banners, DHCP options,
mDNS advertisements, SSDP responses, TLS fingerprints, etc.) against
known device signatures.  All matching is synchronous and in-memory,
backed by optional JSON data files under ``~/.leetha/cache/``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from leetha.fingerprint.evidence import FingerprintMatch
from leetha.fingerprint.mac_intel import is_randomized_mac
from leetha.patterns.matching import match_banner as _match_banner_pattern
from leetha.patterns.matching import match_mdns_service as _match_mdns_pattern, MDNS_SERVICE_DEVICE_MAP
from leetha.patterns.matching import match_dhcp_opt55, match_dhcp_opt60
from leetha.patterns.matching import (
    match_dhcpv6_oro,
    match_dhcpv6_enterprise,
    match_dhcpv6_vendor_class,
)

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Device-type -> high-level category mapping
# ---------------------------------------------------------------------------
DEVICE_CATEGORIES: dict[str, str] = {
    # Network Infrastructure
    "router": "Network Device",
    "switch": "Network Device",
    "firewall": "Network Device",
    "access_point": "Network Device",
    "ap": "Network Device",
    "wap": "Network Device",
    "hub": "Network Device",
    "bridge": "Network Device",
    "gateway": "Network Device",
    "load_balancer": "Network Device",
    "vpn_gateway": "Network Device",
    "wireless_controller": "Network Device",
    "wireless_bridge": "Network Device",
    "mesh_router": "Network Device",

    # Computing Devices
    "workstation": "Computing",
    "laptop": "Computing",
    "server": "Computing",
    "desktop": "Computing",
    "computer": "Computing",
    "pc": "Computing",
    "thin_client": "Computing",

    # Mobile Devices
    "mobile": "Mobile Device",
    "phone": "Mobile Device",
    "smartphone": "Mobile Device",
    "tablet": "Mobile Device",
    "pda": "Mobile Device",

    # Peripherals
    "printer": "Peripheral",
    "scanner": "Peripheral",
    "multifunction": "Peripheral",
    "mfp": "Peripheral",

    # Media Devices
    "smart_tv": "Media Device",
    "tv": "Media Device",
    "smart_speaker": "Media Device",
    "game_console": "Media Device",
    "media_server": "Media Device",
    "media_player": "Media Device",
    "streaming": "Media Device",
    "streaming_device": "Media Device",
    "set_top_box": "Media Device",
    "set-top box": "Media Device",
    "stb": "Media Device",
    "smart_display": "Media Device",
    "portable_speaker": "Media Device",
    "audio_streamer": "Media Device",
    "amplifier": "Media Device",
    "soundbar": "Media Device",
    "subwoofer": "Media Device",

    # IoT Devices
    "iot": "IoT Device",
    "camera": "IoT Device",
    "ip_camera": "IoT Device",
    "iot_gateway": "IoT Device",
    "sensor": "IoT Device",
    "smart_sensor": "IoT Device",
    "smart_lock": "IoT Device",
    "thermostat": "IoT Device",
    "doorbell": "IoT Device",
    "smart_plug": "IoT Device",
    "smart_lighting": "IoT Device",
    "wearable": "IoT Device",
    "wireless_earbuds": "IoT Device",
    "wireless_headphones": "IoT Device",
    "ar_headset": "IoT Device",
    "vr_headset": "IoT Device",
    "smoke_detector": "IoT Device",
    "robot_vacuum": "IoT Device",
    "earbuds": "IoT Device",
    "smartwatch": "IoT Device",
    "smart home": "IoT Device",
    "smart_home": "IoT Device",
    "home_hub": "IoT Device",
    "home_automation": "IoT Device",

    # Storage
    "nas": "Storage",
    "san": "Storage",
    "storage_array": "Storage",
    "backup_appliance": "Storage",

    # Communication
    "voip_phone": "Communication",
    "pbx": "Communication",
    "video_conferencing": "Communication",
    "sip_gateway": "Communication",

    # SCADA/ICS (Industrial Control Systems)
    "plc": "SCADA/ICS",
    "hmi": "SCADA/ICS",
    "rtu": "SCADA/ICS",
    "scada_server": "SCADA/ICS",
    "dcs": "SCADA/ICS",
    "ied": "SCADA/ICS",
    "industrial_switch": "SCADA/ICS",
    "industrial_router": "SCADA/ICS",
    "motor_drive": "SCADA/ICS",
    "power_meter": "SCADA/ICS",
    "building_automation": "SCADA/ICS",
    "industrial": "SCADA/ICS",
    "automation": "SCADA/ICS",

    # AI/ML Services
    "ai_inference": "AI/ML",
    "ai_gateway": "AI/ML",
    "ai_platform": "AI/ML",

    # Virtualization
    "hypervisor": "Virtualization",
    "virtual_machine": "Virtualization",
    "esxi": "Virtualization",
    "vcenter": "Virtualization",
    "proxmox": "Virtualization",
    "hyper_v": "Virtualization",
    "xen": "Virtualization",
    "kvm_host": "Virtualization",

    # Containers & Orchestration
    "container": "Container",
    "container_host": "Container",
    "container_orchestrator": "Container",
    "kubernetes_node": "Container",
    "kubernetes_master": "Container",
    "docker_host": "Container",
    "container_registry": "Container",
    "openshift": "Container",

    # Cloud Platform
    "cloud": "Cloud Platform",
    "hci": "Cloud Platform",
    "ci_cd": "Cloud Platform",
    "management": "Cloud Platform",
    "provisioning": "Cloud Platform",

    # Web Services & Applications
    "web_server": "Web Service",
    "application_server": "Web Service",
    "api_gateway": "Web Service",
    "reverse_proxy": "Web Service",
    "cdn_node": "Web Service",
    "waf": "Web Service",

    # Database
    "database_server": "Database",
    "cache_server": "Database",

    # Security Appliances
    "ids_ips": "Security",
    "siem": "Security",
    "proxy": "Security",
    "authentication_server": "Security",

    # Embedded & Specialty
    "embedded": "Embedded",
    "kiosk": "Embedded",
    "pos_terminal": "Embedded",
    "atm": "Embedded",
    "digital_signage": "Embedded",

    # Medical
    "medical_device": "Medical",
    "patient_monitor": "Medical",
    "imaging_system": "Medical",
}

# ---------------------------------------------------------------------------
# Huginn-Muninn translation helpers
# ---------------------------------------------------------------------------

# Translate Huginn device_type labels to internal canonical values.
_HUGINN_TYPE_TRANSLATION: dict[str, str] = {
    "router": "router",
    "wireless router": "router",
    "switch": "switch",
    "wireless access point": "access_point",
    "wireless controller": "wireless_controller",
    "firewall": "firewall",
    "load balancer": "load_balancer",
    "workstation": "computer",
    "phone": "phone",
    "smartphone": "phone",
    "tablet": "tablet",
    "printer": "printer",
    "scanner": "scanner",
    "voip phone": "voip_phone",
    "voip gateway": "voip_gateway",
    "video phone": "voip_phone",
    "video conferencing": "voip_phone",
    "smart tv": "smart_tv",
    "smarttv": "smart_tv",
    "iptv": "smart_tv",
    "game console": "game_console",
    "nas": "nas",
    "thin client": "thin_client",
    "ebook reader": "tablet",
    "digital media player": "media_player",
    "multimedia device": "media_player",
    "media link controller": "media_player",
    "digital signage": "digital_signage",
    "dvr": "ip_camera",
    "ip network camera": "ip_camera",
    "sensor": "sensor",
    "ups": "ups",
    "dsp": "iot",
    "pda": "phone",
    "network diagnostics": "network_device",
    "key lock box": "iot",
    "miscellaneous": "unknown",
    # ICS/SCADA device types
    "programmable logic controller": "plc",
    "plc": "plc",
    "human machine interface": "hmi",
    "hmi": "hmi",
    "remote terminal unit": "rtu",
    "rtu": "rtu",
    "distributed control system": "dcs",
    "dcs": "dcs",
    "intelligent electronic device": "ied",
    "ied": "ied",
    "variable frequency drive": "motor_drive",
    "vfd": "motor_drive",
    "servo drive": "motor_drive",
    "motor drive": "motor_drive",
    "safety controller": "plc",
    "industrial gateway": "industrial_router",
    "protocol converter": "industrial_router",
    "industrial switch": "industrial_switch",
    "industrial router": "industrial_router",
    "power meter": "power_meter",
    "energy meter": "power_meter",
    "building controller": "building_automation",
    "building automation controller": "building_automation",
    "scada server": "scada_server",
    "data historian": "scada_server",
    "relay": "ied",
    "protective relay": "ied",
}


def _translate_huginn_type(raw_type: str) -> str:
    """Convert a Huginn-Muninn device type label to an internal value."""
    cleaned = raw_type.strip().lower()
    return _HUGINN_TYPE_TRANSLATION.get(cleaned, cleaned)

# Keep the old name around for anything that references it directly.
_normalize_huginn_device_type = _translate_huginn_type


# Compiled regex table for pulling OS family out of satori name strings.
_SATORI_OS_EXTRACTORS: list[tuple[re.Pattern, str]] = [
    # ICS/RTOS-specific (checked first for higher specificity)
    (re.compile(r"\bVxWorks\b", re.I), "VxWorks"),
    (re.compile(r"\bQNX\b", re.I), "QNX"),
    (re.compile(r"\bNucleus\s*RTOS\b", re.I), "Nucleus RTOS"),
    (re.compile(r"\bThreadX\b|\bAzure\s*RTOS\b", re.I), "ThreadX"),
    (re.compile(r"\bINTEGRITY\b", re.I), "INTEGRITY"),
    (re.compile(r"\bFreeRTOS\b", re.I), "FreeRTOS"),
    (re.compile(r"\bZephyr\b", re.I), "Zephyr"),
    (re.compile(r"\bRTEMS\b", re.I), "RTEMS"),
    (re.compile(r"\beCos\b", re.I), "eCos"),
    (re.compile(r"\bPikeOS\b", re.I), "PikeOS"),
    (re.compile(r"\bLynxOS\b", re.I), "LynxOS"),
    (re.compile(r"\bCisco\s+IOS\b", re.I), "Cisco IOS"),
    (re.compile(r"\bENEA\s+OSE\b", re.I), "ENEA OSE"),
    # General-purpose OS families
    (re.compile(r"\bWindows\s+(?:Server\s+)?(\d+(?:\.\d+)?)", re.I), "Windows"),
    (re.compile(r"\bWindows\b", re.I), "Windows"),
    (re.compile(r"\bmacOS\b|\bMac\s*OS\s*X?\b|\bOS\s*X\b", re.I), "macOS"),
    (re.compile(r"\biOS\b|\biPhone\b|\biPad\b", re.I), "iOS"),
    (re.compile(r"\bAndroid\b", re.I), "Android"),
    (re.compile(r"\bLinux\b", re.I), "Linux"),
    (re.compile(r"\bChromeOS\b|\bChrome\s*OS\b", re.I), "ChromeOS"),
    (re.compile(r"\bFreeBSD\b", re.I), "FreeBSD"),
    (re.compile(r"\bESXi\b|\bVMkernel\b", re.I), "ESXi"),
    (re.compile(r"\bFire\s*OS\b", re.I), "Android"),
    (re.compile(r"\btvOS\b", re.I), "tvOS"),
    (re.compile(r"\bwatchOS\b", re.I), "watchOS"),
    (re.compile(r"\bTizen\b", re.I), "Tizen"),
    (re.compile(r"\bwebOS\b", re.I), "webOS"),
    (re.compile(r"\bRoku\s*OS\b", re.I), "RokuOS"),
    (re.compile(r"\bPlayStation\b", re.I), "PlayStation"),
    (re.compile(r"\bXbox\b", re.I), "Xbox"),
    (re.compile(r"\bNintendo\b", re.I), "Nintendo"),
]


def _os_family_from_satori(label: str) -> str | None:
    """Return the OS family embedded in a Huginn satori_name, or None."""
    for rx, family in _SATORI_OS_EXTRACTORS:
        if rx.search(label):
            return family
    return None

# Backward-compat alias
_extract_os_from_satori_name = _os_family_from_satori


# ===================================================================
# SignatureMatcher -- primary class
# ===================================================================

class SignatureMatcher:
    """Correlate observed network artefacts with known device signatures.

    Wraps in-memory pattern matching (banners, mDNS, DHCP, DHCPv6) and
    on-disk JSON data stores (OUI, TCP/IP fingerprints, Huginn-Muninn
    tables) behind a simple synchronous API.
    """

    def __init__(self, data_root: Path | str | None = None) -> None:
        """Create a new matcher instance.

        Parameters
        ----------
        data_root:
            Directory that holds JSON data files.  When *None* the path
            is read from ``leetha.config.get_config().cache_dir``
            (typically ``~/.leetha/cache/``).
        """
        if data_root is not None:
            self._data_dir = Path(data_root)
        else:
            from leetha.config import get_config
            self._data_dir = get_config().cache_dir

        # Lazy-loaded JSON store (name -> parsed content or None)
        self._store: dict[str, dict | list | None] = {}
        # Backward-compat: app.py accesses _json_cache directly
        self._json_cache = self._store

        # Normalised OUI prefix -> vendor info for O(1) lookups
        self._oui_index: dict[str, dict] = {}
        self._build_oui_index()

    # -- cache_dir property for backward compat --
    @property
    def _cache_dir(self) -> Path:
        return self._data_dir

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Flush cached data and rebuild the OUI index.  Call after sync."""
        self._store.clear()
        self._oui_index.clear()
        self._build_oui_index()
        _log.info("Signature data reloaded")

    def load_custom_patterns(self, data_dir: Path) -> None:
        """Merge user-supplied patterns from *data_dir* into memory."""
        from leetha.patterns import HOSTNAME_PATTERNS

        user_patterns = load_custom_patterns(data_dir)
        if not user_patterns:
            return

        # Hostname rules
        for item in user_patterns.get("hostname", []):
            record = (
                item["pattern"],
                item["device_type"],
                item.get("manufacturer"),
                item.get("os_family"),
                item.get("model"),
                item.get("confidence", 80),
            )
            if record not in HOSTNAME_PATTERNS:
                HOSTNAME_PATTERNS.append(record)

        # Additional MAC prefix rules
        for pfx, meta in user_patterns.get("mac_prefix", {}).items():
            key = pfx.replace(":", "").replace("-", "").upper()
            self._oui_index[key] = meta

        _log.info("Custom patterns loaded from %s", data_dir)

    # ------------------------------------------------------------------
    # OUI index builder
    # ------------------------------------------------------------------

    def _build_oui_index(self) -> None:
        """Populate the in-memory OUI prefix dictionary."""
        from leetha.patterns.vendors import load_oui_data

        raw = load_oui_data(self._data_dir)
        if not raw:
            _log.warning("No OUI data available")
            return

        for prefix_str, vendor_meta in raw.items():
            key = prefix_str.replace(":", "").replace("-", "").upper()
            self._oui_index[key] = vendor_meta

        _log.info("OUI index built with %d prefixes", len(self._oui_index))

    # ==================================================================
    # Public matching methods
    # ==================================================================

    def match_mac(self, mac: str) -> list[FingerprintMatch]:
        """Identify a device by its MAC address via OUI and Huginn data.

        Both the IEEE OUI database and the Huginn MAC vendor table are
        consulted; all hits are returned so the evidence aggregator can
        weigh them.

        Parameters
        ----------
        mac:
            Hardware address in common hex notation (e.g.
            ``"AA:BB:CC:DD:EE:FF"``).

        Returns
        -------
        list[FingerprintMatch]
            Possibly empty list of matches.
        """
        hits: list[FingerprintMatch] = []

        if not mac:
            return hits

        if is_randomized_mac(mac):
            return hits

        norm = mac.replace(":", "").replace("-", "").upper()

        # IEEE OUI (longest-prefix wins)
        if self._oui_index:
            for n_chars in (9, 8, 7, 6, 4):
                pfx = norm[:n_chars]
                if pfx in self._oui_index:
                    info = self._oui_index[pfx]
                    hits.append(FingerprintMatch(
                        source="oui",
                        match_type="exact",
                        confidence=0.95,
                        manufacturer=info.get("manufacturer"),
                        device_type=info.get("device_type"),
                        model=info.get("model"),
                        category=info.get("category"),
                        raw_data={
                            "source_db": "IEEE OUI Master Database",
                            "source_file": "~/.leetha/cache/ieee_oui/master_oui.csv",
                            "matched_key": f"OUI prefix {pfx}",
                        },
                    ))
                    break

        # Huginn MAC vendor table — only fall back to the massive
        # huginn_mac_vendors (667 MB) if OUI lookup returned nothing
        if not hits:
            huginn_hit = self._resolve_huginn_mac(norm)
            if huginn_hit:
                hits.append(huginn_hit)

        return hits

    # Backward-compat alias
    lookup_mac = match_mac

    # ------------------------------------------------------------------

    def _resolve_huginn_mac(self, norm_mac: str) -> FingerprintMatch | None:
        """Check the Huginn-Muninn MAC vendor table for *norm_mac*."""
        blob = self._fetch_json("huginn_mac_vendors")
        if not blob:
            return None

        rows = blob.get("entries", {})
        short = norm_mac[:6].lower()
        row = rows.get(short)
        if not row:
            return None

        vendor_name = row.get("name", "")
        if not vendor_name:
            return None

        return FingerprintMatch(
            source="huginn_mac",
            match_type="exact",
            confidence=0.80,
            manufacturer=vendor_name,
            raw_data={
                "source_db": "Huginn-Muninn MAC Vendors",
                "source_file": "~/.leetha/cache/huginn_mac_vendors/",
                "matched_key": f"MAC prefix {short}",
                "huginn_device_id": row.get("device_id"),
            },
        )

    # ------------------------------------------------------------------

    def match_tcp_signature(self, sig: str) -> FingerprintMatch | None:
        """Match a p0f-style TCP/IP stack signature against known entries.

        Parameters
        ----------
        sig:
            Signature string produced by the TCP capture layer.

        Returns
        -------
        FingerprintMatch | None
        """
        if not sig:
            return None

        blob = self._fetch_json("p0f")
        if not blob:
            return None

        for rec in blob.get("entries", []):
            if rec.get("signature") == sig:
                conf = rec.get("confidence", 80)
                return FingerprintMatch(
                    source="tcp",
                    match_type="exact",
                    confidence=conf / 100.0 if conf > 1 else conf,
                    os_family=rec.get("os_family"),
                    os_version=rec.get("os_version"),
                    device_type=rec.get("device_type"),
                    raw_data={
                        "source_db": "p0f TCP/IP Fingerprints",
                        "source_file": "~/.leetha/cache/p0f/p0f.fp",
                        "matched_key": f"TCP signature {sig[:40]}",
                        "signature": rec.get("signature"),
                        "label": rec.get("label"),
                        "ttl": rec.get("ttl"),
                        "window_size": rec.get("window_size"),
                        "mss": rec.get("mss"),
                    },
                )

        return None

    # Backward-compat alias
    lookup_tcp = match_tcp_signature

    # ------------------------------------------------------------------

    def match_banner(
        self, protocol: str, banner_text: str
    ) -> FingerprintMatch | None:
        """Identify a device from a service banner string.

        The built-in pattern library is tried first; then the on-disk
        ``banners.json`` data store is consulted.

        Parameters
        ----------
        protocol:
            Protocol name (``ssh``, ``http``, ``smb``, ``ftp``, ...).
        banner_text:
            Raw banner captured from the wire.

        Returns
        -------
        FingerprintMatch | None
        """
        if not banner_text:
            return None

        # Built-in patterns take precedence.
        hit = _match_banner_pattern(protocol, banner_text)
        if hit:
            conf = hit["confidence"]
            return FingerprintMatch(
                source="banner",
                match_type="pattern",
                confidence=conf / 100.0 if conf > 1 else conf,
                os_family=hit.get("os_family"),
                manufacturer=hit.get("vendor"),
                device_type=hit.get("device_type"),
                raw_data={
                    "product": hit.get("product"),
                    "vendor": hit.get("vendor"),
                    "version": hit.get("version"),
                    "matched_pattern": hit.get("matched_pattern"),
                },
            )

        # Fallback: cached banner patterns on disk.
        blob = self._fetch_json("banners")
        if blob:
            for pat_rec in blob.get("entries", []):
                if pat_rec.get("protocol") != protocol.lower():
                    continue

                rx_str = pat_rec.get("pattern", "")
                kind = pat_rec.get("pattern_type", "regex")

                try:
                    found = False
                    if kind == "regex":
                        found = bool(re.search(rx_str, banner_text, re.IGNORECASE))
                    elif kind == "exact":
                        found = banner_text == rx_str
                    elif kind == "contains":
                        found = rx_str.lower() in banner_text.lower()

                    if found:
                        conf = pat_rec.get("confidence", 65)
                        return FingerprintMatch(
                            source="banner_cache",
                            match_type="pattern",
                            confidence=conf / 100.0 if conf > 1 else conf,
                            os_family=pat_rec.get("os_family"),
                            manufacturer=pat_rec.get("vendor"),
                            device_type=pat_rec.get("device_type"),
                            raw_data={
                                "product": pat_rec.get("product"),
                            },
                        )
                except re.error:
                    continue

        return None

    # Backward-compat alias
    lookup_banner = match_banner

    # ------------------------------------------------------------------

    # Apple model code -> human-readable device name
    APPLE_MODEL_MAP: dict[str, str] = {
        "AudioAccessory1,1": "HomePod",
        "AudioAccessory1,2": "HomePod",
        "AudioAccessory5,1": "HomePod mini",
        "AudioAccessory6,1": "HomePod 2nd gen",
        "AppleTV2,1": "Apple TV 2nd gen",
        "AppleTV3,1": "Apple TV 3rd gen",
        "AppleTV3,2": "Apple TV 3rd gen rev A",
        "AppleTV5,3": "Apple TV 4th gen",
        "AppleTV6,2": "Apple TV 4K",
        "AppleTV11,1": "Apple TV 4K 2nd gen",
        "AppleTV14,1": "Apple TV 4K 3rd gen",
        "iPhone14,5": "iPhone 13",
        "iPhone15,2": "iPhone 14 Pro",
        "iPhone16,1": "iPhone 15 Pro",
        "iPad13,1": "iPad Air 4th gen",
        "iPad14,1": "iPad mini 6th gen",
        "MacBookPro18,1": "MacBook Pro 16-inch M1 Pro",
        "MacBookAir10,1": "MacBook Air M1",
        "iMac21,1": "iMac 24-inch M1",
    }

    def match_mdns_service(
        self, service_type: str, name: str = None, packet_data: dict | None = None,
    ) -> list[FingerprintMatch]:
        """Correlate mDNS service advertisements to a device profile.

        Parameters
        ----------
        service_type:
            Service type string such as ``_airplay._tcp``.
        name:
            Optional advertised instance name.
        packet_data:
            Optional parsed packet dict that may carry ``model``,
            ``apple_model``, ``txt_records``, etc.

        Returns
        -------
        list[FingerprintMatch]
        """
        hits: list[FingerprintMatch] = []
        if packet_data is None:
            packet_data = {}

        # Standard service/name pattern matching
        svc_hit = _match_mdns_pattern(service_type, name)
        if svc_hit:
            conf = svc_hit["confidence"]
            hits.append(FingerprintMatch(
                source="mdns",
                match_type="pattern",
                confidence=conf / 100.0 if conf > 1 else conf,
                device_type=svc_hit.get("device_type"),
                manufacturer=svc_hit.get("manufacturer"),
                os_family=svc_hit.get("os_family"),
                raw_data={
                    "service_type": service_type,
                    "name": name,
                    "match_source": svc_hit.get("match_source"),
                },
            ))

        # Service-type category fallback when patterns missed
        svc_clean = service_type.lower().strip()
        svc_meta = MDNS_SERVICE_DEVICE_MAP.get(svc_clean, {})
        if svc_meta and not hits:
            if svc_meta.get("device_type") or svc_meta.get("manufacturer"):
                hits.append(FingerprintMatch(
                    source="mdns_service_map",
                    match_type="pattern",
                    confidence=0.65,
                    device_type=svc_meta.get("device_type"),
                    manufacturer=svc_meta.get("manufacturer"),
                    os_family=svc_meta.get("os_family"),
                    raw_data={
                        "service_type": service_type,
                        "category": svc_meta.get("category"),
                    },
                ))

        # Google Cast model (md field)
        if "model" in packet_data:
            hits.append(FingerprintMatch(
                source="mdns_txt",
                match_type="exact",
                confidence=0.92,
                model=packet_data["model"],
                device_type=svc_meta.get("device_type", "smart_speaker"),
                manufacturer=packet_data.get("txt_manufacturer"),
                raw_data={
                    "txt_model": packet_data["model"],
                    "friendly_name": packet_data.get("friendly_name"),
                    "txt_records": packet_data.get("txt_records"),
                },
            ))

        # Apple model code (am field)
        if "apple_model" in packet_data:
            a_code = packet_data["apple_model"]
            a_name = self.APPLE_MODEL_MAP.get(a_code, a_code)
            a_dtype = "media_player"
            if a_code.startswith("AudioAccessory"):
                a_dtype = "smart_speaker"
            elif a_code.startswith("AppleTV"):
                a_dtype = "media_player"
            elif a_code.startswith("iPhone"):
                a_dtype = "phone"
            elif a_code.startswith("iPad"):
                a_dtype = "tablet"
            elif a_code.startswith("MacBook"):
                a_dtype = "laptop"
            elif a_code.startswith("iMac"):
                a_dtype = "desktop"

            hits.append(FingerprintMatch(
                source="mdns_txt",
                match_type="exact",
                confidence=0.95,
                model=a_name,
                device_type=a_dtype,
                manufacturer="Apple",
                os_family="iOS" if a_code.startswith("iPhone") else None,
                raw_data={
                    "apple_model_code": a_code,
                    "friendly_name": packet_data.get("friendly_name"),
                },
            ))

        return hits

    # Backward-compat alias
    lookup_mdns = match_mdns_service

    # ------------------------------------------------------------------

    def match_dhcp(
        self, opt55: str = None, opt60: str = None
    ) -> list[FingerprintMatch]:
        """Collect evidence from DHCP Option 55 and Option 60.

        Consults built-in patterns, Huginn combination tables, Huginn
        DHCP signature tables, and Huginn vendor-class tables in
        parallel. All hits are returned for the evidence aggregator.

        Parameters
        ----------
        opt55:
            Comma-separated DHCP Parameter Request List.
        opt60:
            Vendor Class Identifier string.

        Returns
        -------
        list[FingerprintMatch]
        """
        hits: list[FingerprintMatch] = []

        # Option 60 -- built-in patterns
        if opt60:
            res = match_dhcp_opt60(opt60)
            if res:
                conf = res["confidence"]
                hits.append(FingerprintMatch(
                    source="dhcp_vendor",
                    match_type="pattern",
                    confidence=conf / 100.0 if conf > 1 else conf,
                    device_type=res.get("device_type"),
                    manufacturer=res.get("manufacturer"),
                    os_family=res.get("os_family"),
                    raw_data={"vendor_class": opt60},
                ))

        # Option 60 -- Huginn vendor class
        if opt60:
            hv = self._resolve_huginn_dhcp_vendor(opt60)
            if hv:
                hits.append(hv)

        # Option 55 -- Huginn combinations
        if opt55:
            combo = self._resolve_huginn_combo(opt55)
            if combo:
                hits.append(combo)

        # Option 55 -- Huginn DHCP signatures
        if opt55:
            sig_hit = self._resolve_huginn_dhcp_sig(opt55)
            if sig_hit:
                hits.append(sig_hit)

        # Option 55 -- built-in patterns
        if opt55:
            res = match_dhcp_opt55(opt55)
            if res:
                conf = res["confidence"]
                hits.append(FingerprintMatch(
                    source="dhcp",
                    match_type=res.get("match_source", "pattern"),
                    confidence=conf / 100.0 if conf > 1 else conf,
                    device_type=res.get("device_type"),
                    manufacturer=res.get("manufacturer"),
                    os_family=res.get("os_family"),
                    raw_data={"options": opt55},
                ))

        return hits

    # Backward-compat alias
    lookup_dhcp = match_dhcp

    # ------------------------------------------------------------------
    # Internal Huginn DHCP helpers
    # ------------------------------------------------------------------

    def _resolve_huginn_combo(
        self, opt55: str
    ) -> FingerprintMatch | None:
        """Match opt55 via the Huginn-Muninn combinations table.

        When several entries share the same opt55 value the most
        specific one is chosen (longest satori_name as a proxy for
        specificity).
        """
        blob = self._fetch_json("huginn_combinations")
        if not blob:
            return None

        rows = blob.get("entries", {})
        candidates = rows.get(opt55)
        if not candidates:
            return None

        best = max(candidates, key=lambda c: len(c.get("satori_name", "")))

        satori_label = best.get("satori_name", "")
        dtype = _translate_huginn_type(best.get("device_type", ""))
        vendor = best.get("device_vendor", "")
        dev_id = best.get("device_id")

        os_fam = _os_family_from_satori(satori_label)

        # Enrich via device hierarchy
        hier_display = None
        if dev_id:
            dev_blob = self._fetch_json("huginn_devices")
            if dev_blob:
                dev_rows = dev_blob.get("entries", {})
                dev_rec = dev_rows.get(str(dev_id))
                if dev_rec:
                    hier_display = dev_rec.get("hierarchy_str")
                    if not dtype or dtype == "unknown":
                        for lvl in dev_rec.get("hierarchy", []):
                            refined = _translate_huginn_type(lvl)
                            if refined != lvl.strip().lower():
                                dtype = refined
                                break

        return FingerprintMatch(
            source="huginn_device",
            match_type="exact",
            confidence=0.90,
            device_type=dtype or None,
            manufacturer=vendor or None,
            os_family=os_fam,
            model=satori_label or None,
            raw_data={
                "options": opt55,
                "huginn_device_id": dev_id,
                "satori_name": satori_label,
                "hierarchy_str": hier_display,
            },
        )

    def _resolve_huginn_dhcp_sig(self, opt55: str) -> FingerprintMatch | None:
        """Match opt55 against the Huginn DHCP signature table."""
        idx = self._dhcp_opt55_index()
        if idx is None:
            return None

        found_id = idx.get(opt55)
        if not found_id:
            return None

        return FingerprintMatch(
            source="huginn_dhcp",
            match_type="exact",
            confidence=0.82,
            raw_data={
                "source_db": "Huginn-Muninn DHCP Signatures",
                "source_file": "~/.leetha/cache/huginn_dhcp/dhcp_signature.json",
                "matched_key": f"DHCP Option 55: {opt55[:60]}",
                "huginn_fingerprint_id": found_id,
            },
        )

    def _dhcp_opt55_index(self) -> dict[str, str] | None:
        """Return (and lazily build) a reverse index: opt55_value -> fingerprint_id."""
        key = "_dhcp_opt55_idx"
        if key in self._store:
            return self._store[key]

        blob = self._fetch_json("huginn_dhcp")
        if not blob:
            return None

        rows = blob.get("entries", {})
        idx: dict[str, str] = {}
        for fid, rec in rows.items():
            val = rec.get("value")
            if val:
                idx[val] = fid
        self._store[key] = idx
        return idx

    def _resolve_huginn_dhcp_vendor(self, opt60: str) -> FingerprintMatch | None:
        """Find the best Huginn vendor-class substring match for *opt60*."""
        blob = self._fetch_json("huginn_dhcp_vendor")
        if not blob:
            return None

        rows = blob.get("entries", {})
        opt60_lc = opt60.lower()

        winner = None
        winner_len = 0

        for _vid, rec in rows.items():
            val = rec.get("value", "")
            if not val:
                continue
            val_lc = val.lower()
            if opt60_lc.startswith(val_lc) or val_lc in opt60_lc:
                if len(val) > winner_len:
                    winner = rec
                    winner_len = len(val)

        if not winner:
            return None

        mfr = winner.get("vendor_hint", "")
        return FingerprintMatch(
            source="huginn_dhcp_vendor",
            match_type="substring",
            confidence=0.75,
            manufacturer=mfr or None,
            raw_data={
                "vendor_class": opt60,
                "matched_value": winner.get("value"),
            },
        )

    # ------------------------------------------------------------------

    def match_dhcpv6(
        self,
        oro: str = None,
        vendor_class: str = None,
        enterprise_id: int = None,
    ) -> list[FingerprintMatch]:
        """Collect evidence from DHCPv6 options.

        Built-in pattern tables and Huginn caches are both consulted.
        """
        hits: list[FingerprintMatch] = []

        # ORO built-in patterns
        if oro:
            res = match_dhcpv6_oro(oro)
            if res:
                conf = res["confidence"]
                hits.append(FingerprintMatch(
                    source="dhcpv6",
                    match_type="pattern",
                    confidence=conf / 100.0 if conf > 1 else conf,
                    device_type=res.get("device_type"),
                    manufacturer=res.get("manufacturer"),
                    os_family=res.get("os_family"),
                    raw_data={"oro": oro, "match_source": res.get("match_source")},
                ))

        # ORO Huginn DHCPv6 signatures
        if oro:
            hm = self._resolve_huginn_dhcpv6(oro)
            if hm:
                hits.append(hm)

        # Vendor class built-in
        if vendor_class:
            res = match_dhcpv6_vendor_class(vendor_class)
            if res:
                conf = res["confidence"]
                hits.append(FingerprintMatch(
                    source="dhcpv6",
                    match_type="pattern",
                    confidence=conf / 100.0 if conf > 1 else conf,
                    device_type=res.get("device_type"),
                    manufacturer=res.get("manufacturer"),
                    os_family=res.get("os_family"),
                    raw_data={"vendor_class": vendor_class, "match_source": res.get("match_source")},
                ))

        # Enterprise ID built-in
        if enterprise_id is not None:
            res = match_dhcpv6_enterprise(enterprise_id)
            if res:
                hits.append(FingerprintMatch(
                    source="dhcpv6",
                    match_type="exact",
                    confidence=0.75,
                    manufacturer=res.get("manufacturer"),
                    raw_data={"enterprise_id": enterprise_id, "device_types": res.get("device_types"), "match_source": res.get("match_source")},
                ))

        # Enterprise ID Huginn
        if enterprise_id is not None:
            he = self._resolve_huginn_dhcpv6_enterprise(enterprise_id)
            if he:
                hits.append(he)

        # Enterprise ID IANA fallback
        if enterprise_id is not None and not any(h.source == "huginn_dhcpv6_enterprise" for h in hits):
            ie = self._resolve_iana_enterprise(enterprise_id)
            if ie:
                hits.append(ie)

        return hits

    # Backward-compat alias
    lookup_dhcpv6 = match_dhcpv6

    # ------------------------------------------------------------------

    def _resolve_huginn_dhcpv6(self, oro: str) -> FingerprintMatch | None:
        """Check the Huginn DHCPv6 signature table."""
        blob = self._fetch_json("huginn_dhcpv6")
        if not blob:
            return None
        for fid, rec in blob.get("entries", {}).items():
            if rec.get("value") == oro:
                return FingerprintMatch(
                    source="huginn_dhcpv6",
                    match_type="exact",
                    confidence=0.70,
                    raw_data={"oro": oro, "huginn_fingerprint_id": fid},
                )
        return None

    def _resolve_huginn_dhcpv6_enterprise(self, eid: int) -> FingerprintMatch | None:
        """Check the Huginn DHCPv6 enterprise table."""
        blob = self._fetch_json("huginn_dhcpv6_enterprise")
        if not blob:
            return None
        rec = blob.get("entries", {}).get(str(eid))
        if not rec:
            return None
        org = rec.get("organization", "")
        return FingerprintMatch(
            source="huginn_dhcpv6_enterprise",
            match_type="exact",
            confidence=0.70,
            manufacturer=org or None,
            raw_data={"enterprise_id": eid, "organization": org},
        )

    def _resolve_iana_enterprise(self, eid: int) -> FingerprintMatch | None:
        """Check IANA Enterprise Numbers registry for vendor name."""
        blob = self._fetch_json("iana_enterprise")
        if not blob:
            return None
        rec = blob.get("entries", {}).get(str(eid))
        if not rec:
            return None
        org = rec.get("organization") or rec.get("name") or ""
        if not org:
            return None
        return FingerprintMatch(
            source="iana_enterprise",
            match_type="exact",
            confidence=0.60,
            manufacturer=org,
            raw_data={"enterprise_id": eid, "organization": org,
                       "source_db": "IANA Private Enterprise Numbers"},
        )

    # ------------------------------------------------------------------
    # Satori fingerprint matching (generic across all Satori databases)
    # ------------------------------------------------------------------

    def _satori_index(self, source_name: str, test_field: str) -> dict[str, dict]:
        """Build or return an indexed lookup for a Satori source.

        Index maps lowercase match values to the best device metadata entry
        (highest weight wins when multiple entries match the same value).
        """
        idx_key = f"_satori_idx_{source_name}"
        if idx_key in self._store:
            return self._store[idx_key] or {}

        blob = self._fetch_json(source_name)
        if not blob:
            self._store[idx_key] = {}
            return {}

        entries = blob if isinstance(blob, list) else blob.get("entries", [])
        idx: dict[str, dict] = {}
        for entry in entries:
            for test in entry.get("tests", []):
                val = test.get(test_field)
                if not val:
                    continue
                weight = int(test.get("weight", 0))
                key = val.lower() if test.get("matchtype") != "exact" else val
                existing = idx.get(key)
                if not existing or weight > existing.get("_weight", 0):
                    idx[key] = {
                        "name": entry.get("name", ""),
                        "os_family": entry.get("os_class") or entry.get("os_name") or None,
                        "os_vendor": entry.get("os_vendor") or None,
                        "device_type": entry.get("device_type") or None,
                        "manufacturer": entry.get("device_vendor") or entry.get("os_vendor") or None,
                        "matchtype": test.get("matchtype", "exact"),
                        "_weight": weight,
                    }
        self._store[idx_key] = idx
        _log.info("Satori index %s: %d entries", source_name, len(idx))
        return idx

    def _match_satori(self, source_name: str, test_field: str,
                      value: str, confidence: float = 0.80) -> FingerprintMatch | None:
        """Look up a value against a Satori fingerprint index."""
        if not value:
            return None
        idx = self._satori_index(source_name, test_field)
        if not idx:
            return None

        # Try exact match first, then partial (substring) matches
        hit = idx.get(value) or idx.get(value.lower())
        if not hit:
            # Partial matching: check if any index key is a substring
            val_lower = value.lower()
            for pattern, entry in idx.items():
                if entry.get("matchtype") == "partial" and pattern in val_lower:
                    if not hit or entry.get("_weight", 0) > hit.get("_weight", 0):
                        hit = entry
            if not hit:
                return None

        return FingerprintMatch(
            source=f"satori_{source_name.replace('satori_', '')}",
            match_type=hit.get("matchtype", "exact"),
            confidence=confidence,
            manufacturer=hit.get("manufacturer"),
            os_family=hit.get("os_family"),
            device_type=hit.get("device_type"),
            raw_data={"satori_name": hit.get("name"), "source_db": f"Satori {source_name}"},
        )

    def match_satori_dhcp(self, opt55: str) -> FingerprintMatch | None:
        """Match DHCP Option 55 against Satori annotated DHCP fingerprints."""
        return self._match_satori("satori_dhcp", "dhcpoption55", opt55, 0.85)

    def match_satori_useragent(self, ua: str) -> FingerprintMatch | None:
        """Match HTTP User-Agent against Satori UA fingerprints."""
        return self._match_satori("satori_useragent", "webuseragent", ua, 0.80)

    def match_satori_ssh(self, banner: str) -> FingerprintMatch | None:
        """Match SSH banner against Satori SSH fingerprints."""
        return self._match_satori("satori_ssh", "ssh", banner, 0.82)

    def match_satori_smb(self, native_os: str) -> FingerprintMatch | None:
        """Match SMB native OS string against Satori SMB fingerprints."""
        return self._match_satori("satori_smb", "smbnativename", native_os, 0.82)

    def match_satori_web(self, server: str) -> FingerprintMatch | None:
        """Match HTTP Server header against Satori web fingerprints."""
        return self._match_satori("satori_web", "webserver", server, 0.78)

    # ------------------------------------------------------------------

    def match_ssdp_server(self, server: str | None = None, st: str | None = None) -> FingerprintMatch | None:
        """Identify a device from SSDP SERVER header or search target."""
        from leetha.patterns.matching import match_ssdp_server as _match_ssdp, match_upnp_device_type
        if server:
            res = _match_ssdp(server)
            if res:
                conf = res["confidence"]
                return FingerprintMatch(
                    source="ssdp", match_type="pattern",
                    confidence=conf / 100.0 if conf > 1 else conf,
                    os_family=res.get("os_family"), os_version=res.get("os_version"),
                    device_type=res.get("device_type"), manufacturer=res.get("manufacturer"),
                    raw_data={"server": server, "st": st},
                )
        if st:
            dtype = match_upnp_device_type(st)
            if dtype:
                return FingerprintMatch(
                    source="ssdp", match_type="pattern", confidence=0.70,
                    device_type=dtype, raw_data={"st": st},
                )
        return None

    # Backward-compat alias
    lookup_ssdp = match_ssdp_server

    # ------------------------------------------------------------------

    def match_netbios(self, query_name: str, query_type: str = "llmnr", netbios_suffix: int | None = None) -> FingerprintMatch | None:
        """Identify device from NetBIOS/LLMNR query patterns."""
        from leetha.patterns.matching import match_netbios_suffix, match_llmnr_query
        if query_type == "netbios" and netbios_suffix is not None:
            res = match_netbios_suffix(netbios_suffix)
            if res:
                conf = res["confidence"]
                return FingerprintMatch(
                    source="netbios", match_type="exact",
                    confidence=conf / 100.0 if conf > 1 else conf,
                    os_family=res.get("os_family"), device_type=res.get("device_type"),
                    raw_data={"query_name": query_name, "service": res.get("service"), "suffix": netbios_suffix},
                )
        res = match_llmnr_query(query_name)
        conf = res["confidence"]
        return FingerprintMatch(
            source="netbios", match_type="heuristic",
            confidence=conf / 100.0 if conf > 1 else conf,
            os_family=res.get("os_family"),
            raw_data={"query_name": query_name, "query_type": query_type},
        )

    # Backward-compat alias
    lookup_netbios = match_netbios

    # ------------------------------------------------------------------

    def match_ja3(self, hash_value: str) -> FingerprintMatch | None:
        """Match a JA3 TLS client fingerprint hash."""
        from leetha.patterns.tls import lookup_ja3

        # Built-in table
        res = lookup_ja3(hash_value)
        if res:
            conf = res["confidence"]
            return FingerprintMatch(
                source="ja3",
                match_type="exact",
                confidence=conf / 100.0 if conf > 1 else conf,
                os_family=res.get("os_family"),
                raw_data={
                    "ja3_hash": hash_value,
                    "app": res.get("app"),
                },
            )

        # On-disk synced database
        blob = self._fetch_json("ja3")
        if blob:
            rec = blob.get("entries", {}).get(hash_value)
            if rec:
                return FingerprintMatch(
                    source="ja3",
                    match_type="exact",
                    confidence=0.72,
                    os_family=rec.get("os_family"),
                    raw_data={
                        "ja3_hash": hash_value,
                        "app": rec.get("app"),
                        "description": rec.get("description"),
                    },
                )

        return None

    # Backward-compat alias
    lookup_ja3 = match_ja3

    # ------------------------------------------------------------------

    def match_ja4(self, fingerprint: str) -> FingerprintMatch | None:
        """Match a JA4 TLS fingerprint against the synced database."""
        blob = self._fetch_json("ja4")
        if not blob:
            return None

        rec = blob.get("entries", {}).get(fingerprint)
        if rec:
            return FingerprintMatch(
                source="ja4",
                match_type="exact",
                confidence=0.75,
                os_family=rec.get("os_family"),
                raw_data={
                    "ja4": fingerprint,
                    "app": rec.get("app"),
                    "description": rec.get("description"),
                },
            )

        return None

    # Backward-compat alias
    lookup_ja4 = match_ja4

    # ------------------------------------------------------------------

    def match_ttl(self, ttl_value: int) -> FingerprintMatch | None:
        """Record the observed TTL for evidence without guessing OS.

        TTL is NOT a reliable platform indicator:
        - TTL 64: Linux, iOS, macOS, Android, FreeBSD, most embedded
        - TTL 128: Windows, but ALSO UniFi OS, many routers/switches
        - TTL 255: Cisco, Juniper, other network devices

        We record the TTL value as raw evidence but never set os_family.
        Real platform identification comes from DHCP, mDNS, DNS, banners.
        """
        if ttl_value <= 0:
            return None
        if ttl_value <= 64:
            return FingerprintMatch(
                source="ttl",
                match_type="heuristic",
                confidence=0.10,
                raw_data={"ttl": ttl_value, "initial_ttl": 64},
            )
        elif ttl_value <= 128:
            return FingerprintMatch(
                source="ttl",
                match_type="heuristic",
                confidence=0.10,
                raw_data={"ttl": ttl_value, "initial_ttl": 128},
            )
        else:
            return FingerprintMatch(
                source="ttl",
                match_type="heuristic",
                confidence=0.25,
                device_type="network_device",
                raw_data={"ttl": ttl_value, "initial_ttl": 255},
            )

    # Backward-compat alias
    lookup_ttl = match_ttl

    # ------------------------------------------------------------------

    def match_dns_query(self, qname: str, qtype: int) -> FingerprintMatch | None:
        """Identify device from a DNS query domain pattern."""
        from leetha.patterns.matching import match_dns_query

        hit = match_dns_query(qname, qtype)
        if not hit:
            return None

        return FingerprintMatch(
            source="dns",
            match_type="pattern",
            confidence=hit.get("confidence", 0.50),
            manufacturer=hit.get("manufacturer"),
            device_type=hit.get("device_type"),
            os_family=hit.get("os_family"),
            raw_data={
                "query_name": qname,
                "query_type": qtype,
                "note": hit.get("note"),
            },
        )

    # Backward-compat alias
    lookup_dns = match_dns_query

    # ------------------------------------------------------------------

    def match_icmpv6(
        self, icmpv6_type: str, hop_limit: int, managed: int, other: int, options: dict
    ) -> FingerprintMatch | None:
        """Match an ICMPv6 Router Advertisement fingerprint."""
        from leetha.patterns.matching import match_ra_fingerprint

        if icmpv6_type != "router_advertisement":
            return None

        hit = match_ra_fingerprint(hop_limit, managed, other, options)
        if not hit:
            return None

        return FingerprintMatch(
            source="icmpv6",
            match_type="exact",
            confidence=hit.get("confidence", 0.50),
            manufacturer=hit.get("manufacturer"),
            device_type=hit.get("device_type"),
            os_family=hit.get("os_family"),
        )

    # Backward-compat alias
    lookup_icmpv6 = match_icmpv6

    # ------------------------------------------------------------------

    def match_user_agent(self, ua_string: str) -> FingerprintMatch | None:
        """Parse an HTTP User-Agent header to infer OS and device type."""
        if not ua_string:
            return None

        import re as _re

        detected_os = None
        detected_ver = None
        detected_dtype = "workstation"

        # Android (check before Linux -- Android UA contains "Linux")
        m = _re.search(r"Android\s+([\d.]+)", ua_string)
        if m:
            detected_os = "Android"
            detected_ver = m.group(1)
            detected_dtype = "phone"
            if "Tablet" in ua_string or "iPad" in ua_string:
                detected_dtype = "tablet"
        elif "iPhone" in ua_string:
            detected_os = "iOS"
            detected_dtype = "phone"
            m = _re.search(r"iPhone OS ([\d_]+)", ua_string)
            if m:
                detected_ver = m.group(1).replace("_", ".")
        elif "iPad" in ua_string:
            detected_os = "iPadOS"
            detected_dtype = "tablet"
            m = _re.search(r"CPU OS ([\d_]+)", ua_string)
            if m:
                detected_ver = m.group(1).replace("_", ".")
        elif "Macintosh" in ua_string or "Mac OS X" in ua_string:
            detected_os = "macOS"
            m = _re.search(r"Mac OS X ([\d_]+)", ua_string)
            if m:
                detected_ver = m.group(1).replace("_", ".")
        elif "Windows NT" in ua_string:
            detected_os = "Windows"
            m = _re.search(r"Windows NT ([\d.]+)", ua_string)
            if m:
                nt = m.group(1)
                detected_ver = {"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7"}.get(nt, nt)
        elif "Linux" in ua_string:
            detected_os = "Linux"

        # --- IoT / streaming / gaming devices ---
        # These override the generic OS detection above when specific
        # device tokens are present in the UA string.
        if "Roku/DVP" in ua_string or "Roku/" in ua_string:
            detected_os = "RokuOS"
            detected_dtype = "streaming_device"
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="streaming_device",
                manufacturer="Roku",
                os_family="RokuOS",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "Silk/" in ua_string or ua_string.startswith("AFTM"):
            detected_os = "Fire OS"
            detected_dtype = "streaming_device"
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="streaming_device",
                manufacturer="Amazon",
                os_family="Fire OS",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "Tizen/" in ua_string or "SmartTV" in ua_string or "SMART-TV" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="smart_tv",
                manufacturer="Samsung",
                os_family="Tizen",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "LG NetCast" in ua_string or "Web0S" in ua_string or "webOS" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="smart_tv",
                manufacturer="LG",
                os_family="webOS",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "Sonos/" in ua_string or ("Linux UPnP" in ua_string and "Sonos" in ua_string):
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="smart_speaker",
                manufacturer="Sonos",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "PlayStation" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="game_console",
                manufacturer="Sony",
                os_family="PlayStation",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "Xbox" in ua_string or "XboxOne" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="game_console",
                manufacturer="Microsoft",
                os_family="Xbox",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "Nintendo" in ua_string or "NintendoBrowser" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="game_console",
                manufacturer="Nintendo",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "CrKey" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="streaming_device",
                manufacturer="Google",
                os_family="Cast OS",
                raw_data={"user_agent": ua_string[:200]},
            )
        if "AppleTV" in ua_string:
            return FingerprintMatch(
                source="http_useragent",
                match_type="pattern",
                confidence=0.85,
                device_type="smart_tv",
                manufacturer="Apple",
                os_family="tvOS",
                raw_data={"user_agent": ua_string[:200]},
            )

        if not detected_os:
            return None

        return FingerprintMatch(
            source="http_useragent",
            match_type="pattern",
            confidence=0.80,
            device_type=detected_dtype,
            os_family=detected_os,
            os_version=detected_ver,
            raw_data={"user_agent": ua_string[:200]},
        )

    # Backward-compat alias
    lookup_useragent = match_user_agent

    # ------------------------------------------------------------------

    def match_hostname(self, hostname_str: str) -> FingerprintMatch | None:
        """Identify a device by its advertised hostname pattern.

        Hostnames like ``roborock-vacuum-a75`` or ``Roomba-31A`` are
        strong signals that can override generic DHCP fingerprints.
        """
        if not hostname_str:
            return None
        from leetha.patterns.matching import match_hostname
        res = match_hostname(hostname_str)
        if res:
            conf = res["confidence"]
            return FingerprintMatch(
                source="hostname",
                match_type="pattern",
                confidence=conf / 100.0 if conf > 1 else conf,
                device_type=res.get("device_type"),
                manufacturer=res.get("manufacturer"),
                os_family=res.get("os_family"),
                model=res.get("model"),
                raw_data={"hostname": hostname_str},
            )
        return None

    # Backward-compat alias
    lookup_hostname = match_hostname

    # ------------------------------------------------------------------
    # HTTP Host / TLS SNI cloud-service patterns
    # ------------------------------------------------------------------

    _HOST_CLOUD_PATTERNS: list[tuple[str, str | None, str | None, str | None]] = [
        # Apple
        (r"\.apple\.com$", "Apple", None, None),
        (r"\.icloud\.com$", "Apple", None, "iOS/macOS"),
        # Google
        (r"\.google\.com$", "Google", None, None),
        (r"clients\d+\.google\.com", "Google", None, "Android"),
        (r"connectivitycheck\.gstatic\.com", "Google", None, "Android"),
        # Amazon
        (r"\.amazon\.com$", "Amazon", None, None),
        (r"\.amazonaws\.com$", None, None, None),
        # Samsung
        (r"\.samsungcloudsolution\.com", "Samsung", "smart_tv", None),
        (r"\.samsungcloud\.tv", "Samsung", "smart_tv", None),
        # Nest/Google Home
        (r"home\.nest\.com", "Google", "smart_home", None),
        (r"\.googlevideo\.com", None, "streaming_device", None),
        # Roku
        (r"\.roku\.com$", "Roku", "streaming_device", None),
        # Sonos
        (r"\.sonos\.com$", "Sonos", "smart_speaker", None),
        # Ring
        (r"\.ring\.com$", "Ring", "camera", None),
        # Wyze
        (r"\.wyzecam\.com$", "Wyze", "camera", None),
        # Tesla
        (r"\.tesla\.com$", "Tesla", "iot", None),
        (r"\.teslamotors\.com$", "Tesla", "iot", None),
    ]

    def lookup_http_host(self, host: str) -> FingerprintMatch | None:
        """Match HTTP Host header against known device cloud services."""
        if not host:
            return None
        return self._try_host_patterns(host, origin="http_host")

    def lookup_tls_sni(self, sni: str) -> FingerprintMatch | None:
        """Match TLS SNI hostname against known device cloud services."""
        if not sni:
            return None
        return self._try_host_patterns(sni, origin="tls_sni")

    def _try_host_patterns(self, hostname: str, origin: str) -> FingerprintMatch | None:
        """Scan cloud-service patterns for a hostname/SNI match."""
        hostname_lc = hostname.lower().strip()
        for rx, mfr, dtype, os_fam in self._HOST_CLOUD_PATTERNS:
            if re.search(rx, hostname_lc):
                if not mfr and not dtype and not os_fam:
                    continue
                return FingerprintMatch(
                    source=origin,
                    match_type="pattern",
                    confidence=0.55,
                    manufacturer=mfr,
                    device_type=dtype,
                    os_family=os_fam,
                    raw_data={"hostname": hostname},
                )
        return None

    # ==================================================================
    # JSON data-store loader
    # ==================================================================

    # Caches too large for on-demand loading -- only available after the
    # background warm-up task populates ``_store``.
    _WARM_ONLY_STORES = frozenset({
        "huginn_mac_vendors",
        "huginn_dhcp",
        "huginn_devices",
        "huginn_dhcp_vendor",
        "huginn_dhcpv6_enterprise",
    })

    def _fetch_json(self, name: str) -> dict | list | None:
        """Retrieve a parsed JSON data file by logical name.

        Files are lazily loaded on first access and thereafter served
        from ``_store``.  Entries listed in ``_WARM_ONLY_STORES`` are
        skipped unless they were previously populated by the background
        warm-up task (to avoid blocking the event loop).
        """
        if name in self._store:
            return self._store[name]

        if name in self._WARM_ONLY_STORES:
            filepath = self._data_dir / f"{name}.json"
            if not filepath.is_file():
                return None
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                data = self._compact_cache(name, data)
                self._store[name] = data
                _log.debug("Sync-loaded WARM_ONLY cache: %s", name)
                return data
            except Exception:
                self._store[name] = None
                return None

        filepath = self._data_dir / f"{name}.json"
        if not filepath.is_file():
            self._store[name] = None
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                parsed = json.load(fh)
            parsed = self._compact_cache(name, parsed)
            self._store[name] = parsed
            return parsed
        except (json.JSONDecodeError, OSError) as err:
            _log.warning("Unable to load data file %s: %s", filepath, err)
            self._store[name] = None
            return None

    @staticmethod
    def _compact_cache(name: str, data: dict) -> dict:
        """Reduce memory footprint of loaded caches.

        - huginn_mac_vendors: intern repeated vendor strings (~60% savings)
        - huginn_dhcp: drop redundant 'options' lists and 'options_hash'
        """
        entries = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, dict):
            return data

        if name == "huginn_mac_vendors":
            intern_pool: dict[str, str] = {}
            for key, rec in entries.items():
                if isinstance(rec, dict):
                    vendor = rec.get("name", "")
                    if vendor not in intern_pool:
                        intern_pool[vendor] = vendor
                    entries[key] = {"name": intern_pool[vendor]}

        elif name == "huginn_dhcp":
            for rec in entries.values():
                if isinstance(rec, dict):
                    rec.pop("options", None)
                    rec.pop("options_hash", None)

        return data

    # Backward-compat alias for the internal cache loader
    _load_json_cache = _fetch_json

    # ------------------------------------------------------------------

    def _get_device_category(self, device_type: str) -> str | None:
        """Translate a device_type into a high-level category string."""
        if not device_type:
            return None
        return DEVICE_CATEGORIES.get(device_type.lower())


# ======================================================================
# Backward-compatibility: FingerprintLookup is the old class name
# ======================================================================
FingerprintLookup = SignatureMatcher


# ======================================================================
# Module-level utility functions
# ======================================================================

def load_custom_patterns(data_dir: Path) -> dict:
    """Read user-defined patterns from ``data_dir/custom_patterns.json``.

    Returns an empty dict when the file is absent.
    """
    target = data_dir / "custom_patterns.json"
    if not target.is_file():
        return {}
    try:
        with open(target, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as err:
        _log.warning("Could not load custom patterns: %s", err)
        return {}


def save_custom_patterns(data_dir: Path, patterns: dict) -> None:
    """Persist user-defined patterns to ``data_dir/custom_patterns.json``."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Ensure every entry has hits and created_at
    for key, entries in patterns.items():
        if isinstance(entries, list):
            for entry in entries:
                entry.setdefault("hits", 0)
                entry.setdefault("created_at", now)
        elif isinstance(entries, dict):
            for _k, entry in entries.items():
                if isinstance(entry, dict):
                    entry.setdefault("hits", 0)
                    entry.setdefault("created_at", now)

    data_dir.mkdir(parents=True, exist_ok=True)
    target = data_dir / "custom_patterns.json"
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(patterns, fh, indent=2)


# ── Debounced hit counter for custom patterns ──

import threading as _threading

_hit_buffer: dict[tuple[str, str], int] = {}
_hit_lock = _threading.Lock()


def record_pattern_hit(pattern_type: str, pattern: str) -> None:
    """Record a hit in memory (flushed periodically by the app)."""
    with _hit_lock:
        key = (pattern_type, pattern)
        _hit_buffer[key] = _hit_buffer.get(key, 0) + 1


def flush_pattern_hits(data_dir: Path) -> None:
    """Flush accumulated hits to disk."""
    global _hit_buffer
    with _hit_lock:
        if not _hit_buffer:
            return
        buffer = _hit_buffer.copy()
        _hit_buffer.clear()

    patterns = load_custom_patterns(data_dir)
    for (ptype, pattern), count in buffer.items():
        entries = patterns.get(ptype, [])
        if isinstance(entries, list):
            for entry in entries:
                if entry.get("pattern") == pattern:
                    entry["hits"] = entry.get("hits", 0) + count
        elif isinstance(entries, dict):
            if pattern in entries:
                entries[pattern]["hits"] = entries[pattern].get("hits", 0) + count
    save_custom_patterns(data_dir, patterns)
