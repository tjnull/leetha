"""Pattern matching functions for network device identification.

These functions were extracted from the legacy Python pattern modules
(banners.py, ssdp.py, mdns.py, dns.py, dhcpv4.py, dhcpv6.py,
netbios.py, icmpv6.py, hostname.py, ai_services.py) during the JSON
migration.  They operate on the JSON-sourced data loaded by
``patterns.loader.load()``.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Optional

from leetha.patterns.loader import load, load_compiled


def _domain_matches(query: str, domain: str) -> bool:
    """Check if *query* matches *domain* as a suffix with proper boundary.

    Returns True if query equals domain or ends with '.domain'.
    Avoids substring false positives like 'pineapple.com' matching 'apple.com'.
    """
    return query == domain or query.endswith("." + domain)

# =====================================================================
# Banner matching
# =====================================================================

# JSON banners.json key names differ from legacy Python:
#   JSON: match, product, vendor, platform, version_match, certainty
#   Legacy: (regex, product, vendor, os_family, version_regex, confidence)
#
# Extended banner categories additionally carry a "device_type" field.

# Categories whose entries have a ``device_type`` (7-element extended).
_EXTENDED_CATEGORIES = frozenset({
    "cloud", "scada", "virtualization", "container",
    "security", "webapp", "database", "communication",
    "iot_http",
})

# Protocol-to-category mapping for basic (6-element) banner patterns.
_PROTOCOL_MAP: dict[str, str] = {
    "ssh": "ssh", "ssh-2.0": "ssh",
    "http": "http", "https": "http", "http-proxy": "http",
    "smb": "smb", "microsoft-ds": "smb", "netbios-ssn": "smb",
    "ftp": "ftp",
    "smtp": "smtp", "smtps": "smtp", "submission": "smtp",
    "imap": "imap_pop", "imaps": "imap_pop", "pop3": "imap_pop", "pop3s": "imap_pop",
    "telnet": "telnet",
    "dns": "dns", "domain": "dns",
    "ldap": "ldap", "ldaps": "ldap",
    "snmp": "snmp",
    "rdp": "rdp_vnc", "ms-wbt-server": "rdp_vnc", "vnc": "rdp_vnc", "rfb": "rdp_vnc",
    "sip": "sip", "sips": "sip", "h323": "sip",
    "ntp": "ntp",
    "mqtt": "mqtt",
    "ipp": "printer", "jetdirect": "printer", "printer": "printer",
    "kerberos": "kerberos", "krb5": "kerberos", "kpasswd": "kerberos",
    "radius": "radius", "tacacs": "radius",
    "amqp": "message_queue", "stomp": "message_queue",
    "memcache": "cache", "memcached": "cache",
    "rtsp": "streaming", "rtmp": "streaming", "rtp": "streaming",
    "git": "vcs", "svn": "vcs", "hg": "vcs",
    "xmpp": "chat", "jabber": "chat", "irc": "chat",
    "stun": "webrtc", "turn": "webrtc",
    "modbus": "industrial", "dnp3": "industrial", "bacnet": "industrial", "opcua": "industrial",
    "coap": "iot_protocol", "lwm2m": "iot_protocol",
    "rsync": "file_sync",
    "grpc": "api", "graphql": "api",
}

# All basic (non-extended) banner category keys used when protocol is unknown.
_ALL_BASIC_CATEGORIES = [
    "ssh", "http", "smb", "ftp", "smtp", "imap_pop", "telnet", "dns",
    "ldap", "snmp", "rdp_vnc", "sip", "ntp", "mqtt", "printer",
    "gaming_media", "network", "storage", "backup",
    "kerberos", "radius", "message_queue", "cache", "streaming",
    "vcs", "chat", "webrtc", "industrial", "iot_protocol",
    "file_sync", "api",
]

# Priority order for extended banner matching.
_EXTENDED_PRIORITY = [
    "cloud", "scada", "virtualization", "container",
    "security", "webapp", "database", "communication", "iot_http",
]


def _match_extended(banner: str, patterns: list) -> Optional[Dict]:
    """Match banner against extended pattern dicts (with device_type).

    Accepts both compiled tuples ``(re.Pattern, dict)`` from
    ``load_compiled()`` and raw dicts from ``load()``.
    """
    for item in patterns:
        if isinstance(item, tuple):
            regex_obj, entry = item
            m = regex_obj.search(banner)
            regex_str = regex_obj.pattern
        else:
            entry = item
            regex_str = entry.get("match", "")
            if not regex_str:
                continue
            m = re.search(regex_str, banner, re.IGNORECASE)
        if m:
            version = None
            version_re = entry.get("version_match")
            if version_re:
                vm = re.search(version_re, banner, re.IGNORECASE)
                if vm:
                    version = vm.group(1)
            return {
                "product": entry.get("product"),
                "vendor": entry.get("vendor"),
                "os_family": entry.get("platform"),
                "version": version,
                "confidence": entry.get("certainty", 50),
                "device_type": entry.get("device_type"),
                "matched_pattern": regex_str,
            }
    return None


def match_banner(protocol: str, banner: str) -> Optional[Dict]:
    """Match a service banner against known patterns.

    Args:
        protocol: Service protocol (e.g. ssh, http, smb, ftp).
        banner: Service banner string.

    Returns:
        Dict with product, vendor, os_family, version, confidence keys
        or None if no pattern matched.
    """
    if not banner:
        return None

    banners = load("banners")  # dict of category -> list[dict]
    compiled = load_compiled("banners")  # list[(re.Pattern, dict)]
    protocol_lower = protocol.lower()

    # Build a lookup from compiled patterns keyed by category.
    # load_compiled flattens all entries; we use the raw banners dict
    # to get per-category compiled lists via _match_extended which now
    # accepts both compiled tuples and raw dicts.

    # 1. Try extended patterns first (they carry device_type)
    for cat in _EXTENDED_PRIORITY:
        patterns = banners.get(cat, [])
        if patterns:
            result = _match_extended(banner, patterns)
            if result:
                return result

    # 2. Pick the basic pattern list for this protocol
    cat = _PROTOCOL_MAP.get(protocol_lower)
    if cat:
        patterns = banners.get(cat, [])
    else:
        # Unknown protocol: search all basic categories
        patterns = []
        for c in _ALL_BASIC_CATEGORIES:
            patterns.extend(banners.get(c, []))

    for item in patterns:
        if isinstance(item, tuple):
            regex_obj, entry = item
            m = regex_obj.search(banner)
            regex_str = regex_obj.pattern
        else:
            entry = item
            regex_str = entry.get("match", "")
            if not regex_str:
                continue
            m = re.search(regex_str, banner, re.IGNORECASE)
        if m:
            version = None
            version_re = entry.get("version_match")
            if version_re:
                vm = re.search(version_re, banner, re.IGNORECASE)
                if vm:
                    version = vm.group(1)
            return {
                "product": entry.get("product"),
                "vendor": entry.get("vendor"),
                "os_family": entry.get("platform"),
                "version": version,
                "confidence": entry.get("certainty", 50),
                "matched_pattern": regex_str,
            }

    return None


def match_banner_extended(banner: str) -> Optional[Dict]:
    """Match a banner against all extended pattern lists.

    This function is specifically for identifying IoT, SCADA, containers,
    virtualization, and other specialized device types.
    """
    if not banner:
        return None
    banners = load("banners")
    for cat in _EXTENDED_PRIORITY:
        patterns = banners.get(cat, [])
        if patterns:
            result = _match_extended(banner, patterns)
            if result:
                return result
    return None


# =====================================================================
# SSDP matching
# =====================================================================

_ssdp_compiled: list[tuple[re.Pattern, dict]] | None = None


def _get_ssdp_compiled() -> list[tuple[re.Pattern, dict]]:
    global _ssdp_compiled
    if _ssdp_compiled is not None:
        return _ssdp_compiled
    data = load("ssdp")
    compiled = []
    for entry in data.get("server_patterns", []):
        pat = entry.get("pattern", "")
        if pat:
            try:
                compiled.append((re.compile(pat, re.IGNORECASE), entry))
            except re.error:
                pass
    _ssdp_compiled = compiled
    return compiled


def match_ssdp_server(server_header: str) -> Optional[Dict]:
    """Match an SSDP SERVER header against known patterns.

    Returns dict with os_family, os_version, device_type, manufacturer,
    confidence keys, or None.
    """
    if not server_header:
        return None

    for compiled_re, entry in _get_ssdp_compiled():
        m = compiled_re.search(server_header)
        if m:
            os_version = None
            version_group = entry.get("os_version_group")
            if version_group is not None:
                try:
                    os_version = m.group(version_group)
                except (IndexError, AttributeError):
                    pass
            return {
                "os_family": entry.get("os_family"),
                "os_version": os_version,
                "device_type": entry.get("device_type"),
                "manufacturer": entry.get("manufacturer"),
                "confidence": entry["confidence"],
                "match_source": "ssdp_server",
            }
    return None


def match_upnp_device_type(st_or_nt: str) -> Optional[str]:
    """Match a UPnP Search Target or Notification Type header.

    Returns device type string (e.g. "media_player") or None.
    """
    if not st_or_nt:
        return None
    data = load("ssdp")
    upnp_types = data.get("upnp_device_types", {})
    for prefix, info in upnp_types.items():
        if st_or_nt.startswith(prefix):
            # JSON stores {"category": "..."}, extract the value
            if isinstance(info, dict):
                return info.get("category")
            return info
    return None


# =====================================================================
# mDNS matching
# =====================================================================

def get_mdns_service_device_map() -> Dict[str, Dict[str, str]]:
    """Return the mDNS service type -> device category mapping.

    This is the equivalent of the legacy MDNS_SERVICE_DEVICE_MAP constant.
    It provides quick device categorization from service type alone.
    """
    # Build from the legacy inline data since the JSON does not carry
    # the "device_map" section separately.
    return {
        "_googlecast._tcp": {"device_type": "smart_speaker", "category": "cast"},
        "_airplay._tcp": {"device_type": "media_player", "manufacturer": "Apple", "category": "airplay"},
        "_raop._tcp": {"device_type": "media_player", "manufacturer": "Apple", "category": "airplay"},
        "_companion-link._tcp": {"device_type": "media_player", "manufacturer": "Apple"},
        "_mediaremotetv._tcp": {"device_type": "smart_tv", "manufacturer": "Apple"},
        "_hap._tcp": {"manufacturer": "Apple", "category": "homekit"},
        "_homekit._tcp": {"manufacturer": "Apple", "category": "homekit"},
        "_amzn-wplay._tcp": {"device_type": "smart_speaker", "manufacturer": "Amazon"},
        "_spotify-connect._tcp": {"device_type": "media_device", "category": "audio"},
        "_sonos._tcp": {"device_type": "smart_speaker", "manufacturer": "Sonos"},
        "_roku._tcp": {"device_type": "streaming_device", "manufacturer": "Roku"},
        "_hue._tcp": {"device_type": "smart_home", "manufacturer": "Philips"},
        "_ipp._tcp": {"device_type": "printer"},
        "_ipps._tcp": {"device_type": "printer"},
        "_pdl-datastream._tcp": {"device_type": "printer"},
        "_printer._tcp": {"device_type": "printer"},
        "_scanner._tcp": {"device_type": "scanner"},
        "_smb._tcp": {"device_type": "server", "category": "file_share"},
        "_afpovertcp._tcp": {"device_type": "server", "manufacturer": "Apple", "category": "file_share"},
        "_nfs._tcp": {"device_type": "server", "category": "file_share"},
        "_readynas._tcp": {"device_type": "nas", "manufacturer": "Netgear"},
        "_ssh._tcp": {"category": "remote_access"},
        "_rfb._tcp": {"category": "vnc"},
        "_teamviewer._tcp": {"category": "remote_access"},
        "_androidtvremote._tcp": {"device_type": "smart_tv", "os_family": "Android"},
        "_androidtvremote2._tcp": {"device_type": "smart_tv", "os_family": "Android"},
        "_nvstream._tcp": {"device_type": "streaming_device", "manufacturer": "NVIDIA"},
        "_smartthings._tcp": {"device_type": "smart_home", "manufacturer": "Samsung"},
        "_http._tcp": {"category": "web_service"},
        "_https._tcp": {"category": "web_service"},
        "_axis-video._tcp": {"device_type": "camera", "manufacturer": "Axis"},
        "_hass._tcp": {"device_type": "smart_home", "category": "home_assistant"},
        "_mqtt._tcp": {"device_type": "iot", "category": "mqtt"},
        "_googlezone._tcp": {"device_type": "smart_speaker", "manufacturer": "Google"},
    }


# Module-level cached instance
MDNS_SERVICE_DEVICE_MAP: Dict[str, Dict[str, str]] = get_mdns_service_device_map()


def match_mdns_service(service_type: str, name: str = None) -> Optional[Dict]:
    """Match an mDNS service to device info.

    Args:
        service_type: mDNS service type (e.g. "_airplay._tcp")
        name: Optional service name for additional matching.

    Returns:
        Dict with device_type, manufacturer, os_family, confidence or None.
    """
    data = load("mdns")
    services = data.get("services", {})
    names = data.get("names", [])

    result = None

    # Clean service type
    service_clean = service_type.lower().strip()
    if service_clean.endswith(".local."):
        service_clean = service_clean[:-7]

    # Try service type match
    if service_clean in services:
        svc = services[service_clean]
        device_type = svc.get("category")
        manufacturer = svc.get("vendor")
        os_family = svc.get("platform")
        confidence = svc.get("certainty", 50)
        if device_type or manufacturer or os_family:
            result = {
                "device_type": device_type,
                "manufacturer": manufacturer,
                "os_family": os_family,
                "confidence": confidence,
                "match_source": "service_type",
            }

    # Try name patterns
    if name:
        for entry in names:
            pattern = entry.get("match", "")
            if pattern and re.search(pattern, name, re.IGNORECASE):
                confidence = entry.get("certainty", 50)
                if result is None or confidence > result.get("confidence", 0):
                    result = {
                        "device_type": entry.get("category"),
                        "manufacturer": entry.get("vendor"),
                        "os_family": entry.get("platform"),
                        "confidence": confidence,
                        "match_source": "name_pattern",
                    }
                break

    return result


# =====================================================================
# DNS matching
# =====================================================================

def match_dns_query(query_name: str, query_type: int) -> Optional[Dict]:
    """Match DNS query domain against known patterns.

    This function preserves the exact logic from the legacy dns.py module.
    The DNS matching uses procedural domain-comparison logic rather than
    simple regex patterns, so it cannot be driven purely from JSON data.

    Args:
        query_name: DNS query domain name.
        query_type: DNS query type (1=A, 28=AAAA, etc.)

    Returns:
        Dict with manufacturer, device_type, os_family, confidence, note
        or None if no match.
    """
    if not query_name:
        return None

    domain_lower = query_name.lower()

    # Apple Domains
    apple_core_domains = [
        "icloud.com", "apple.com", "apple-dns.net", "mzstatic.com",
        "itunes.apple.com", "appleiphonecell.com", "apple-cloudkit.com",
        "icloud-content.com", "me.com", "cdn-apple.com",
        "push.apple.com", "gs.apple.com", "p-push-ssl.apple.com",
        "courier.push.apple.com", "albert.apple.com",
        "setup.icloud.com", "swscan.apple.com",
    ]
    for domain in apple_core_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Apple",
                "device_type": None,
                "os_family": "iOS/macOS",
                "confidence": 0.90,
                "note": f"Apple cloud service: {domain}"
            }

    if "phobos.apple.com" in domain_lower or "mesu.apple.com" in domain_lower:
        return {
            "manufacturer": "Apple", "device_type": None,
            "os_family": "iOS/macOS", "confidence": 0.95,
            "note": "Apple update server"
        }

    apple_activation = [
        "push.apple.com", "courier.push.apple.com",
        "albert.apple.com", "gs.apple.com",
    ]
    for domain in apple_activation:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Apple", "device_type": None,
                "os_family": "iOS/macOS", "confidence": 0.92,
                "note": "Apple push/activation service"
            }

    # Microsoft Windows Domains
    if "windowsupdate.microsoft.com" in domain_lower or "update.microsoft.com" in domain_lower:
        return {
            "manufacturer": "Microsoft", "device_type": None,
            "os_family": "Windows", "confidence": 0.95,
            "note": "Windows Update server"
        }

    windows_connectivity = ["msftncsi.com", "msftconnecttest.com", "windows.com"]
    for domain in windows_connectivity:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Microsoft", "device_type": None,
                "os_family": "Windows", "confidence": 0.85,
                "note": f"Windows connectivity: {domain}"
            }

    ms_generic_domains = [
        "live.com", "outlook.com", "office.com", "onedrive.live.com",
        "microsoft.com", "microsoftonline.com",
    ]
    for domain in ms_generic_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": None, "device_type": None,
                "os_family": None, "confidence": 0.30,
                "note": f"Microsoft service (cross-platform): {domain}"
            }

    # Android-only domains
    android_only_domains = [
        "android.clients.google.com", "play.googleapis.com",
        "android.googleapis.com", "time.android.com",
    ]
    for domain in android_only_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": None, "device_type": None,
                "os_family": "Android", "confidence": 0.88,
                "note": f"Android service: {domain}"
            }

    # Google Home / Nest / Cast
    google_device_domains = [
        "home.nest.com", "home.ft.nest.com",
        "device-provisioning.googleapis.com",
    ]
    for domain in google_device_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Google", "device_type": "smart_speaker",
                "os_family": None, "confidence": 0.85,
                "note": "Google Home/Nest service"
            }

    if "connectivitycheck.gstatic.com" in domain_lower:
        return {
            "manufacturer": None, "device_type": "computer",
            "os_family": None, "confidence": 0.40,
            "note": "Connectivity check (Android and Linux NetworkManager)"
        }

    # Google AI API domains
    _google_ai_apis = {
        "generativelanguage.googleapis.com": "Google Gemini",
        "aiplatform.googleapis.com": "Google Vertex AI",
    }
    for _gai_domain, _gai_service in _google_ai_apis.items():
        if _gai_domain in domain_lower:
            return {
                "manufacturer": None, "device_type": None,
                "os_family": None, "confidence": 0.85,
                "note": f"AI service consumer: {_gai_service}",
                "ai_service": _gai_service, "ai_category": "cloud_api",
            }

    if "gemini.google.com" in domain_lower:
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.75,
            "note": "AI service consumer: Google Gemini",
            "ai_service": "Google Gemini", "ai_category": "ai_saas",
        }

    if _domain_matches(domain_lower, "gstatic.com") or _domain_matches(domain_lower, "googleapis.com"):
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.20,
            "note": "Generic Google service (not device-specific)"
        }

    generic_google_domains = [
        "mtalk.google.com", "alt1-mtalk.google.com",
        "dl.google.com", "clients3.google.com",
        "clients4.google.com", "clients.google.com",
    ]
    for domain in generic_google_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": None, "device_type": None,
                "os_family": None, "confidence": 0.25,
                "note": f"Generic Google service: {domain}"
            }

    # Linux Distribution Update Servers
    linux_update_patterns = {
        r".*\.kali\.org": ("Kali Linux", 0.95),
        r".*kali\.download": ("Kali Linux", 0.95),
        r".*kali-linux-mirror": ("Kali Linux", 0.92),
        r".*\.parrotsec\.org": ("Parrot OS", 0.95),
        r".*\.ubuntu\.com": ("Ubuntu", 0.90),
        r".*\.debian\.org": ("Debian", 0.90),
        r".*\.linuxmint\.com": ("Linux Mint", 0.90),
        r".*\.pop-os\.org": ("Pop!_OS", 0.90),
        r".*\.elementary\.io": ("elementary OS", 0.90),
        r".*\.fedoraproject\.org": ("Fedora", 0.90),
        r".*\.redhat\.com": ("Red Hat", 0.85),
        r".*\.centos\.org": ("CentOS", 0.90),
        r".*\.rockylinux\.org": ("Rocky Linux", 0.90),
        r".*\.almalinux\.org": ("AlmaLinux", 0.90),
        r".*\.archlinux\.org": ("Arch Linux", 0.90),
        r".*\.manjaro\.org": ("Manjaro", 0.90),
        r".*\.opensuse\.org": ("openSUSE", 0.90),
        r".*\.gentoo\.org": ("Gentoo", 0.90),
        r".*\.voidlinux\.org": ("Void Linux", 0.90),
        r".*\.nixos\.org": ("NixOS", 0.90),
        r".*\.raspberrypi\.org": ("Raspberry Pi OS", 0.90),
        r".*\.raspberrypi\.com": ("Raspberry Pi OS", 0.90),
    }

    for pattern, (distro, confidence) in linux_update_patterns.items():
        if re.match(pattern, domain_lower):
            return {
                "manufacturer": None, "device_type": None,
                "os_family": f"Linux/{distro}", "confidence": confidence,
                "note": f"{distro} update server"
            }

    # IoT Vendor Domains
    iot_vendor_domains = {
        "tuya.com": ("Tuya", "iot", 0.90),
        "tuyacn.com": ("Tuya", "iot", 0.90),
        "tuyaeu.com": ("Tuya", "iot", 0.90),
        "tuyaus.com": ("Tuya", "iot", 0.90),
        "xiaomi.com": ("Xiaomi", "iot", 0.85),
        "mi.com": ("Xiaomi", "iot", 0.85),
        "miui.com": ("Xiaomi", "mobile", 0.85),
        "huawei.com": ("Huawei", "iot", 0.80),
        "meizu.com": ("Meizu", "iot", 0.80),
        "nest.com": ("Google Nest", "iot", 0.90),
        "nestlabs.com": ("Google Nest", "iot", 0.90),
        "ring.com": ("Amazon Ring", "iot", 0.90),
        "wyze.com": ("Wyze", "iot", 0.90),
        "arlo.com": ("Arlo", "camera", 0.90),
        "netgear.com": ("Netgear", None, 0.75),
        "tp-link.com": ("TP-Link", None, 0.75),
        "dlink.com": ("D-Link", None, 0.75),
        "belkin.com": ("Belkin", "iot", 0.75),
        "wemo.com": ("Belkin WeMo", "smart_plug", 0.90),
        "lifx.com": ("LIFX", "smart_lighting", 0.90),
        "philips-hue.com": ("Philips", "smart_lighting", 0.90),
        "meethue.com": ("Philips Hue", "smart_lighting", 0.90),
        "ecobee.com": ("ecobee", "thermostat", 0.90),
        "honeywell.com": ("Honeywell", "iot", 0.70),
        "august.com": ("August", "smart_lock", 0.90),
        "smartthings.com": ("Samsung SmartThings", "home_hub", 0.90),
        "wink.com": ("Wink", "home_hub", 0.90),
        "axis.com": ("Axis", "camera", 0.85),
        "hikvision.com": ("Hikvision", "camera", 0.90),
        "dahua.com": ("Dahua", "camera", 0.90),
        "ubnt.com": ("Ubiquiti", "camera", 0.80),
        "ubiquiti.com": ("Ubiquiti", "camera", 0.80),
        "samsungcloud.tv": ("Samsung", "smart_tv", 0.90),
        "samsungcloudsolution.com": ("Samsung", "smart_tv", 0.85),
        "lgtvsdp.com": ("LG", "smart_tv", 0.90),
        "lge.com": ("LG", "smart_tv", 0.85),
        "vizio.com": ("Vizio", "smart_tv", 0.90),
        "roku.com": ("Roku", "streaming_device", 0.90),
        "netflix.com": (None, "streaming_device", 0.60),
        "playstation.net": ("Sony", "game_console", 0.95),
        "playstation.com": ("Sony", "game_console", 0.90),
        "xbox.com": ("Microsoft", "game_console", 0.90),
        "xboxlive.com": ("Microsoft", "game_console", 0.95),
        "nintendo.net": ("Nintendo", "game_console", 0.90),
        "nintendowifi.net": ("Nintendo", "game_console", 0.95),
    }

    for domain, (manufacturer, device_type, confidence) in iot_vendor_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": manufacturer, "device_type": device_type,
                "os_family": None, "confidence": confidence,
                "note": f"IoT vendor domain: {domain}"
            }

    # Virtualization & Container Platform Domains
    docker_domains = [
        "docker.internal", "host.docker.internal",
        "containers.internal", "gateway.docker.internal",
    ]
    for domain in docker_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Docker", "device_type": "container",
                "os_family": "Linux", "confidence": 0.95,
                "note": f"Docker container DNS: {domain}"
            }

    if _domain_matches(domain_lower, "docker.io") or _domain_matches(domain_lower, "docker.com"):
        return {
            "manufacturer": "Docker", "device_type": "container_host",
            "os_family": "Linux", "confidence": 0.85,
            "note": "Docker registry/hub access"
        }

    k8s_patterns = [
        ".cluster.local", ".svc.cluster.local",
        ".default.svc", ".kube-system.svc",
    ]
    for pattern in k8s_patterns:
        if _domain_matches(domain_lower, pattern):
            return {
                "manufacturer": "Kubernetes", "device_type": "container",
                "os_family": "Linux", "confidence": 0.95,
                "note": f"Kubernetes cluster DNS: {pattern}"
            }

    k8s_api_domains = [
        "k8s.io", "kubernetes.io", "k8s.gcr.io",
        "registry.k8s.io", "storage.googleapis.com/kubernetes-release",
    ]
    for domain in k8s_api_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Kubernetes", "device_type": "kubernetes_node",
                "os_family": "Linux", "confidence": 0.85,
                "note": f"Kubernetes API/registry: {domain}"
            }

    if _domain_matches(domain_lower, "proxmox.com") or domain_lower.endswith(".pve"):
        return {
            "manufacturer": "Proxmox", "device_type": "hypervisor",
            "os_family": "Linux/Debian", "confidence": 0.90,
            "note": "Proxmox VE platform"
        }

    vmware_domains = [
        "vmware.com", "vsphere.local", "vcsa.local",
        "vmwareidentity.com", "vmwarehorizon.com",
    ]
    for domain in vmware_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "VMware", "device_type": "hypervisor",
                "os_family": "ESXi", "confidence": 0.85,
                "note": f"VMware infrastructure: {domain}"
            }

    citrix_domains = [
        "citrix.com", "xenserver.org", "xenproject.org",
        "cloud.com", "netsvc.net",
    ]
    for domain in citrix_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Citrix", "device_type": "hypervisor",
                "os_family": "XenServer", "confidence": 0.85,
                "note": f"Citrix infrastructure: {domain}"
            }

    hyperv_domains = ["hyperv.local", "azurestack.local"]
    for domain in hyperv_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Microsoft", "device_type": "hyper_v",
                "os_family": "Windows Server", "confidence": 0.90,
                "note": f"Microsoft Hyper-V: {domain}"
            }

    if "nutanix.com" in domain_lower or domain_lower.endswith(".nutanix"):
        return {
            "manufacturer": "Nutanix", "device_type": "hypervisor",
            "os_family": "AHV", "confidence": 0.90,
            "note": "Nutanix AHV platform"
        }

    ovirt_domains = ["ovirt.org", "rhev.local"]
    for domain in ovirt_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": "Red Hat", "device_type": "kvm_host",
                "os_family": "Linux/RHEL", "confidence": 0.85,
                "note": f"oVirt/RHV infrastructure: {domain}"
            }

    if domain_lower.endswith(".consul") or "consul.io" in domain_lower:
        return {
            "manufacturer": "HashiCorp", "device_type": "container_host",
            "os_family": "Linux", "confidence": 0.85,
            "note": "HashiCorp Consul service mesh"
        }

    container_registries = {
        "quay.io": ("Red Hat", "container_host"),
        "gcr.io": ("Google", "container_host"),
        "ghcr.io": ("GitHub", "container_host"),
        "registry.hub.docker.com": ("Docker", "container_host"),
        "azurecr.io": ("Microsoft", "container_host"),
        "ecr.aws": ("Amazon", "container_host"),
    }
    for domain, (manufacturer, device_type) in container_registries.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": manufacturer, "device_type": device_type,
                "os_family": "Linux", "confidence": 0.80,
                "note": f"Container registry: {domain}"
            }

    ntp_patterns = [
        r"^\d+\.pool\.ntp\.org$",
        r"^time\.\w+\.\w+$",
        r"^ntp\.\w+\.\w+$",
    ]
    for pattern in ntp_patterns:
        if re.match(pattern, domain_lower):
            return {
                "manufacturer": None, "device_type": "embedded",
                "os_family": "Linux/Embedded", "confidence": 0.60,
                "note": "NTP time sync (common in embedded/IoT devices)"
            }

    if "ocsp" in domain_lower or "crl" in domain_lower:
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.30,
            "note": "Certificate validation (OCSP/CRL)"
        }

    if "inference.ai.cloudflare.com" in domain_lower:
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.85,
            "note": "AI service consumer: Cloudflare Workers AI",
            "ai_service": "Cloudflare Workers AI", "ai_category": "cloud_api",
        }

    cdn_domains = {
        "cloudfront.net": ("Amazon", 0.40),
        "s3.amazonaws.com": ("Amazon", 0.45),
        "akamaiedge.net": (None, 0.30),
        "cloudflare.com": (None, 0.30),
        "fastly.net": (None, 0.30),
    }
    for domain, (manufacturer, confidence) in cdn_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": manufacturer, "device_type": None,
                "os_family": None, "confidence": confidence,
                "note": f"CDN/cloud storage: {domain}"
            }

    # Cloud Provider Domains
    cloud_provider_domains = {
        "amazonaws.com": ("Amazon", None, "Linux", 0.70, "AWS cloud service"),
        "ec2.internal": ("Amazon", "server", "Linux", 0.90, "AWS EC2 instance"),
        "azure-devices.net": ("Microsoft", "iot", None, 0.85, "Azure IoT Hub"),
        "metadata.google.internal": ("Google", "server", "Linux", 0.90, "GCP metadata service"),
        "digitaloceanspaces.com": ("DigitalOcean", None, None, 0.75, "DigitalOcean Spaces"),
        "hetzner.cloud": ("Hetzner", "server", "Linux", 0.85, "Hetzner Cloud"),
    }
    for domain, (manufacturer, device_type, os_family, confidence, note) in cloud_provider_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": manufacturer, "device_type": device_type,
                "os_family": os_family, "confidence": confidence,
                "note": f"Cloud provider: {note}"
            }

    captive_portal_domains = [
        "captive.apple.com",
        "connectivitycheck.android.com",
        "detectportal.firefox.com",
    ]
    for domain in captive_portal_domains:
        if _domain_matches(domain_lower, domain):
            if "apple" in domain:
                os_family, manufacturer = "iOS/macOS", "Apple"
            elif "android" in domain:
                os_family, manufacturer = "Android", None
            elif "firefox" in domain:
                os_family, manufacturer = None, "Mozilla"
            else:
                os_family, manufacturer = None, None
            return {
                "manufacturer": manufacturer, "device_type": None,
                "os_family": os_family, "confidence": 0.85,
                "note": "Captive portal detection"
            }

    if domain_lower.endswith(".local"):
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.50,
            "note": "mDNS-capable device (.local domain)"
        }

    router_local_domains = [
        "router.asus.com", "routerlogin.net", "tplinkwifi.net",
        "dlinkrouter.local", "myrouter.local",
    ]
    for domain in router_local_domains:
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": None, "device_type": "router",
                "os_family": None, "confidence": 0.80,
                "note": f"Router admin domain: {domain}"
            }

    printer_domains = {
        "hp.com": ("HP", "printer", 0.70),
        "hpconnectedsolutions.com": ("HP", "printer", 0.85),
        "canon.com": ("Canon", "printer", 0.70),
        "epson.com": ("Epson", "printer", 0.70),
        "brother.com": ("Brother", "printer", 0.70),
        "xerox.com": ("Xerox", "printer", 0.80),
        "lexmark.com": ("Lexmark", "printer", 0.85),
    }
    for domain, (manufacturer, device_type, confidence) in printer_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": manufacturer, "device_type": device_type,
                "os_family": None, "confidence": confidence,
                "note": f"Printer vendor domain: {domain}"
            }

    auto_domains = {
        "tesla.com": ("Tesla", "automotive", 0.85),
        "teslamotors.com": ("Tesla", "automotive", 0.85),
        "mbusa.com": ("Mercedes-Benz", "automotive", 0.80),
        "bmw.com": ("BMW", "automotive", 0.75),
        "toyota.com": ("Toyota", "automotive", 0.70),
        "onstar.com": ("GM OnStar", "automotive", 0.90),
    }
    for domain, (manufacturer, device_type, confidence) in auto_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": manufacturer, "device_type": device_type,
                "os_family": None, "confidence": confidence,
                "note": f"Automotive telematics: {domain}"
            }

    # Cloud AI / LLM Service Consumers
    ai_api_domains = {
        "api.openai.com": "OpenAI (GPT/ChatGPT)",
        "api.anthropic.com": "Anthropic (Claude)",
        "api.groq.com": "Groq",
        "api.together.xyz": "Together AI",
        "api.fireworks.ai": "Fireworks AI",
        "api.replicate.com": "Replicate",
        "api.cohere.com": "Cohere",
        "api.mistral.ai": "Mistral AI",
        "api-inference.huggingface.co": "Hugging Face Inference",
        "api.perplexity.ai": "Perplexity AI",
        "api.deepseek.com": "DeepSeek",
        "api.x.ai": "xAI (Grok)",
        "api.stability.ai": "Stability AI",
        "api.elevenlabs.io": "ElevenLabs (Voice AI)",
        "api.runpod.io": "RunPod (GPU Cloud)",
        "api.databricks.com": "Databricks Model Serving",
        "api.deepinfra.com": "DeepInfra",
        "api.anyscale.com": "Anyscale Endpoints",
        "api.sambanova.ai": "SambaNova",
        "api.cerebras.ai": "Cerebras",
    }
    for domain, service_name in ai_api_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": None, "device_type": None,
                "os_family": None, "confidence": 0.85,
                "note": f"AI service consumer: {service_name}",
                "ai_service": service_name, "ai_category": "cloud_api",
            }

    if domain_lower.endswith(".openai.azure.com"):
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.85,
            "note": "AI service consumer: Azure OpenAI",
            "ai_service": "Azure OpenAI", "ai_category": "cloud_api",
        }

    if "bedrock-runtime" in domain_lower and "amazonaws.com" in domain_lower:
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.85,
            "note": "AI service consumer: AWS Bedrock",
            "ai_service": "AWS Bedrock", "ai_category": "cloud_api",
        }

    if domain_lower.endswith(".modal.run"):
        return {
            "manufacturer": None, "device_type": None,
            "os_family": None, "confidence": 0.80,
            "note": "AI service consumer: Modal",
            "ai_service": "Modal", "ai_category": "cloud_api",
        }

    ai_saas_domains = {
        "chat.openai.com": "ChatGPT",
        "chatgpt.com": "ChatGPT",
        "claude.ai": "Claude",
        "copilot.microsoft.com": "Microsoft Copilot",
        "copilot.github.com": "GitHub Copilot",
    }
    for domain, service_name in ai_saas_domains.items():
        if _domain_matches(domain_lower, domain):
            return {
                "manufacturer": None, "device_type": None,
                "os_family": None, "confidence": 0.75,
                "note": f"AI service consumer: {service_name}",
                "ai_service": service_name, "ai_category": "ai_saas",
            }

    return None


# =====================================================================
# DHCPv4 matching
# =====================================================================

# Device types that should NOT be returned from partial matching.
_MOBILE_DEVICE_TYPES = frozenset({"phone", "mobile", "tablet"})


def _load_dhcp_patterns():
    """Load and convert DHCP patterns from JSON to lookup-friendly format."""
    import json
    from pathlib import Path

    data_dir = Path(__file__).parent / "data"
    opt55_path = data_dir / "dhcp_opt55.json"
    opt60_path = data_dir / "dhcp_opt60.json"

    opt55: dict = {}
    opt60: list = []

    if opt55_path.exists():
        with open(opt55_path) as f:
            raw_opt55 = json.load(f)
        for key, v in raw_opt55.items():
            entry = (v["device_type"], v.get("os_family"), v.get("manufacturer"), v["confidence"])
            opt55[key] = entry
            try:
                sorted_key = ",".join(str(o) for o in sorted(int(x) for x in key.split(",")))
                if sorted_key != key and sorted_key not in opt55:
                    opt55[sorted_key] = entry
            except ValueError:
                pass

    if opt60_path.exists():
        with open(opt60_path) as f:
            raw_opt60 = json.load(f)
        opt60 = [
            (p["pattern"], p["device_type"], p.get("manufacturer"), p.get("os_family"), p["confidence"])
            for p in raw_opt60
        ]

    return opt55, opt60


_dhcp_opt55: dict | None = None
_dhcp_opt60: list | None = None


def _get_dhcp_patterns():
    global _dhcp_opt55, _dhcp_opt60
    if _dhcp_opt55 is None:
        _dhcp_opt55, _dhcp_opt60 = _load_dhcp_patterns()
    return _dhcp_opt55, _dhcp_opt60


def match_dhcp_opt55(options: str) -> Optional[Dict]:
    """Match DHCP Option 55 (Parameter Request List) to device info."""
    if not options:
        return None

    opt55, _ = _get_dhcp_patterns()

    try:
        opts = [int(o.strip()) for o in options.split(",") if o.strip()]
        normalized = ",".join(str(o) for o in sorted(opts))
    except ValueError:
        normalized = options

    for candidate in (normalized, options):
        if candidate in opt55:
            device_type, os_family, manufacturer, confidence = opt55[candidate]
            return {
                "device_type": device_type, "os_family": os_family,
                "manufacturer": manufacturer, "confidence": confidence,
                "match_source": "dhcp_opt55_exact",
            }

    try:
        input_set = set(opts)
    except Exception:
        input_set = None

    if input_set is not None:
        best_set: Optional[Dict] = None
        best_set_size = 0
        for pattern, (device_type, os_family, manufacturer, confidence) in opt55.items():
            if device_type in _MOBILE_DEVICE_TYPES:
                continue
            try:
                pattern_set = set(int(x) for x in pattern.split(","))
            except ValueError:
                continue
            psize = len(pattern_set)
            if psize <= best_set_size:
                continue
            if pattern_set.issubset(input_set) and pattern_set != input_set:
                extra_ratio = (len(input_set) - psize) / len(input_set)
                penalty = int(15 + 10 * extra_ratio)
                best_set = {
                    "device_type": device_type, "os_family": os_family,
                    "manufacturer": manufacturer,
                    "confidence": max(confidence - penalty, 20),
                    "match_source": "dhcp_opt55_partial",
                }
                best_set_size = psize

        if best_set is not None:
            return best_set

    return None


def match_dhcp_opt60(vendor_class: str) -> Optional[Dict]:
    """Match DHCP Option 60 (Vendor Class Identifier) to device info."""
    if not vendor_class:
        return None

    _, opt60 = _get_dhcp_patterns()

    for pattern, device_type, manufacturer, os_family, confidence in opt60:
        if re.match(pattern, vendor_class, re.IGNORECASE):
            return {
                "device_type": device_type, "manufacturer": manufacturer,
                "os_family": os_family, "confidence": confidence,
                "match_source": "dhcp_opt60",
            }

    return None


def get_dhcp_fingerprint_hash(options: str) -> str:
    """Generate MD5 hash of DHCP options for database lookup."""
    try:
        opts = [int(o.strip()) for o in options.split(",") if o.strip()]
        normalized = ",".join(str(o) for o in sorted(opts))
    except ValueError:
        normalized = options
    return hashlib.md5(normalized.encode()).hexdigest()


# =====================================================================
# DHCPv6 matching
# =====================================================================

def _load_dhcpv6_data():
    """Load DHCPv6 pattern data from JSON."""
    data = load("dhcpv6")
    # oro is stored as empty list in JSON (matching was in Python code)
    # enterprise_ids: str(int) -> dict
    # vendor_class: list of dicts
    # duid_types: str(int) -> str
    return data


def match_dhcpv6_oro(oro: str) -> Optional[Dict]:
    """Match DHCPv6 ORO (Option Request Option) to device info."""
    if not oro:
        return None

    data = load("dhcpv6")
    oro_data = data.get("oro", {})

    # Build ORO_PATTERNS from JSON data (dict keyed by sorted option string)
    ORO_PATTERNS: dict = {}
    if isinstance(oro_data, dict):
        for key, entry in oro_data.items():
            ORO_PATTERNS[key] = (
                entry.get("device_type"),
                entry.get("os_family"),
                entry.get("manufacturer"),
                entry.get("confidence", 50),
            )

    try:
        opts = [int(o.strip()) for o in oro.split(",") if o.strip()]
        normalized = ",".join(str(o) for o in sorted(opts))
    except ValueError:
        normalized = oro

    if normalized in ORO_PATTERNS:
        device_type, os_family, manufacturer, confidence = ORO_PATTERNS[normalized]
        return {
            "device_type": device_type, "os_family": os_family,
            "manufacturer": manufacturer, "confidence": confidence,
            "match_source": "dhcpv6_oro_exact",
        }

    if oro in ORO_PATTERNS:
        device_type, os_family, manufacturer, confidence = ORO_PATTERNS[oro]
        return {
            "device_type": device_type, "os_family": os_family,
            "manufacturer": manufacturer, "confidence": confidence,
            "match_source": "dhcpv6_oro_exact",
        }

    input_opts = set(normalized.split(","))
    best_match = None
    best_match_size = 0
    for pattern_key, (device_type, os_family, manufacturer, confidence) in ORO_PATTERNS.items():
        pattern_opts = set(pattern_key.split(","))
        if pattern_opts.issubset(input_opts) and len(pattern_opts) > best_match_size:
            best_match = {
                "device_type": device_type, "os_family": os_family,
                "manufacturer": manufacturer,
                "confidence": max(confidence - 20, 10),
                "match_source": "dhcpv6_oro_subset",
            }
            best_match_size = len(pattern_opts)

    return best_match


def match_dhcpv6_enterprise(enterprise_id: int) -> Optional[Dict]:
    """Match IANA enterprise number to manufacturer info."""
    data = load("dhcpv6")
    enterprise_ids = data.get("enterprise_ids", {})
    entry = enterprise_ids.get(str(enterprise_id))
    if entry:
        return {
            "manufacturer": entry["manufacturer"],
            "device_types": entry["device_types"],
            "match_source": "dhcpv6_enterprise_id",
        }
    return None


def match_dhcpv6_vendor_class(vendor_class: str) -> Optional[Dict]:
    """Match DHCPv6 Vendor Class option to device info."""
    if not vendor_class:
        return None

    data = load("dhcpv6")
    vc_patterns = data.get("vendor_class", [])

    # If JSON has vendor_class entries, use them
    if vc_patterns:
        for entry in vc_patterns:
            pattern = entry.get("pattern", "")
            if pattern and re.match(pattern, vendor_class, re.IGNORECASE):
                return {
                    "device_type": entry.get("device_type"),
                    "manufacturer": entry.get("manufacturer"),
                    "os_family": entry.get("os_family"),
                    "confidence": entry.get("confidence", 50),
                    "match_source": "dhcpv6_vendor_class",
                }

    # Fallback: inline patterns (same as legacy Python)
    _VC_PATTERNS = [
        (r"^MSFT\s+\d", "workstation", "Microsoft", "Windows", 90),
        (r"^dhcpcd", "workstation", None, "Linux", 75),
        (r"^udhcp", "router", None, "Linux (Embedded)", 70),
        (r"^Cisco\s", "network", "Cisco", "IOS", 90),
        (r"^Juniper", "router", "Juniper", "JunOS", 90),
        (r"^Fortinet", "firewall", "Fortinet", "FortiOS", 90),
        (r"^MikroTik", "router", "MikroTik", "RouterOS", 90),
        (r"^Aruba", "access_point", "Aruba", "ArubaOS", 90),
        (r"^(ubnt|UniFi)", "access_point", "Ubiquiti", None, 85),
        (r"^AAPLBSDPC/", "workstation", "Apple", "macOS", 90),
        (r"^android-dhcp", "mobile", None, "Android", 85),
        (r"^VMware", "virtual_machine", "VMware", None, 85),
        (r"^HP\s+(LaserJet|OfficeJet|DeskJet)", "printer", "HP", None, 95),
        (r"^EPSON", "printer", "Epson", None, 95),
        (r"^Canon", "printer", "Canon", None, 90),
        (r"^Brother", "printer", "Brother", None, 90),
        (r"^XEROX", "printer", "Xerox", None, 90),
        (r"^Polycom", "voip_phone", "Polycom", None, 90),
        (r"^Yealink", "voip_phone", "Yealink", None, 90),
        (r"^Synology", "nas", "Synology", "DSM", 90),
        (r"^QNAP", "nas", "QNAP", "QTS", 90),
    ]
    for pattern, device_type, manufacturer, os_family, confidence in _VC_PATTERNS:
        if re.match(pattern, vendor_class, re.IGNORECASE):
            return {
                "device_type": device_type, "manufacturer": manufacturer,
                "os_family": os_family, "confidence": confidence,
                "match_source": "dhcpv6_vendor_class",
            }

    return None


def get_duid_type_hint(duid_type: int) -> Optional[str]:
    """Get description for a DUID type code."""
    _DUID_TYPE_HINTS = {
        1: "DUID-LLT (Link-Layer Address Plus Time)",
        2: "DUID-EN (Enterprise Number)",
        3: "DUID-LL (Link-Layer Address)",
        4: "DUID-UUID (RFC 6355)",
    }
    return _DUID_TYPE_HINTS.get(duid_type)


# =====================================================================
# NetBIOS matching
# =====================================================================

def match_netbios_suffix(suffix: int) -> Optional[Dict]:
    """Look up a NetBIOS name suffix byte to identify the service."""
    # Inline the suffix table (small, fixed data)
    _NETBIOS_SUFFIXES = {
        0x00: {"service": "Workstation", "device_type": "workstation"},
        0x01: {"service": "Messenger (client)", "device_type": "workstation"},
        0x03: {"service": "Messenger", "device_type": "workstation"},
        0x06: {"service": "RAS Server", "device_type": "server"},
        0x1B: {"service": "Domain Master Browser", "device_type": "server"},
        0x1C: {"service": "Domain Controller", "device_type": "server"},
        0x1D: {"service": "Master Browser", "device_type": "server"},
        0x1E: {"service": "Browser Service Elections", "device_type": "workstation"},
        0x1F: {"service": "NetDDE Service", "device_type": "workstation"},
        0x20: {"service": "File Server", "device_type": "server"},
        0x21: {"service": "RAS Client", "device_type": "workstation"},
        0x22: {"service": "Microsoft Exchange Interchange", "device_type": "server"},
        0x23: {"service": "Microsoft Exchange Store", "device_type": "server"},
        0x24: {"service": "Microsoft Exchange Directory", "device_type": "server"},
        0x30: {"service": "Modem Sharing Server", "device_type": "server"},
        0x31: {"service": "Modem Sharing Client", "device_type": "workstation"},
        0x43: {"service": "SMS Clients Remote Control", "device_type": "workstation"},
        0x44: {"service": "SMS Admin Remote Control Tool", "device_type": "server"},
        0x45: {"service": "SMS Clients Remote Chat", "device_type": "workstation"},
        0x46: {"service": "SMS Clients Remote Transfer", "device_type": "workstation"},
        0x4C: {"service": "DEC Pathworks TCP/IP Service", "device_type": "server"},
        0x52: {"service": "DEC Pathworks TCP/IP Service", "device_type": "server"},
        0x87: {"service": "Microsoft Exchange MTA", "device_type": "server"},
        0x6A: {"service": "Microsoft Exchange IMC", "device_type": "server"},
        0xBE: {"service": "Network Monitor Agent", "device_type": "server"},
        0xBF: {"service": "Network Monitor Application", "device_type": "server"},
    }
    entry = _NETBIOS_SUFFIXES.get(suffix)
    if entry is None:
        return None
    return {
        "service": entry["service"],
        "device_type": entry["device_type"],
        "os_family": "Windows",
        "confidence": 80,
    }


def match_llmnr_query(query_name: str) -> Dict:
    """Identify a host from an LLMNR query (strong Windows indicator)."""
    return {
        "hostname": query_name,
        "os_family": "Windows",
        "confidence": 75,
    }


# =====================================================================
# ICMPv6 matching
# =====================================================================

def match_ra_fingerprint(
    hop_limit: int,
    managed: int,
    other: int,
    options: dict,
) -> Optional[Dict]:
    """Match ICMPv6 Router Advertisement parameters against known fingerprints."""
    ra_fps = load("icmpv6")

    for fp in ra_fps:
        if (fp["hop_limit"] == hop_limit and
                fp["managed"] == managed and
                fp["other"] == other):
            return {
                "os_family": fp["os_family"],
                "device_type": fp["device_type"],
                "manufacturer": fp["manufacturer"],
                "confidence": fp["confidence"],
                "note": fp["note"],
            }

    # Fallback: hop_limit only
    hop_limit_fallbacks = {
        64: ("Linux/BSD", None, None, 0.40, "Common hop_limit=64 (Linux/BSD/Unix)"),
        128: ("Windows", None, "Microsoft", 0.45, "hop_limit=128 (Windows)"),
        255: ("Cisco IOS/OpenBSD", "router", None, 0.50, "hop_limit=255 (Cisco/OpenBSD)"),
    }

    if hop_limit in hop_limit_fallbacks:
        os_family, device_type, manufacturer, confidence, note = hop_limit_fallbacks[hop_limit]
        return {
            "os_family": os_family, "device_type": device_type,
            "manufacturer": manufacturer, "confidence": confidence,
            "note": note,
        }

    return None


def analyze_slaac_address(ipv6_addr: str, mac: str) -> Dict:
    """Analyze SLAAC address to determine if it uses EUI-64 or privacy extensions."""
    if not ipv6_addr or not mac:
        return {
            "address_type": "unknown",
            "privacy_extensions": None,
            "note": "Insufficient data"
        }

    mac_clean = mac.replace(":", "").upper()
    if len(mac_clean) != 12:
        return {
            "address_type": "unknown",
            "privacy_extensions": None,
            "note": "Invalid MAC address length"
        }

    first_byte = int(mac_clean[0:2], 16)
    flipped_byte = first_byte ^ 0x02

    eui64_iid = (
        f"{flipped_byte:02x}{mac_clean[2:4]}"
        f"{mac_clean[4:6]}ff"
        f"fe{mac_clean[6:8]}"
        f"{mac_clean[8:10]}{mac_clean[10:12]}"
    ).lower()

    import ipaddress
    try:
        addr = ipaddress.IPv6Address(ipv6_addr)
        addr_hex = addr.exploded.replace(":", "")
        iid = addr_hex[16:].lower()
    except ValueError:
        return {
            "address_type": "unknown",
            "privacy_extensions": None,
            "note": "Invalid IPv6 address"
        }

    if iid == eui64_iid:
        return {
            "address_type": "eui64",
            "privacy_extensions": False,
            "note": "EUI-64 SLAAC address (MAC embedded in IPv6)"
        }
    else:
        return {
            "address_type": "privacy",
            "privacy_extensions": True,
            "note": "Privacy extensions or random SLAAC address"
        }


def detect_ra_spoofing(
    hop_limit: int,
    managed: int,
    other: int,
    src_mac: str,
    expected_manufacturer: str = None,
) -> Dict:
    """Detect potential Router Advertisement spoofing attacks."""
    suspicious = False
    reasons = []
    risk_level = "low"

    if hop_limit not in (64, 128, 255):
        suspicious = True
        reasons.append(f"Unusual hop_limit: {hop_limit}")
        risk_level = "medium"

    if expected_manufacturer:
        non_router_vendors = ["Apple", "Samsung", "LG", "Sony", "Google"]
        if any(vendor in expected_manufacturer for vendor in non_router_vendors):
            suspicious = True
            reasons.append(f"RA from consumer device manufacturer: {expected_manufacturer}")
            risk_level = "high"

    return {
        "suspicious": suspicious,
        "reasons": reasons,
        "risk_level": risk_level,
    }


# =====================================================================
# Hostname matching
# =====================================================================

def match_hostname(hostname: str) -> Optional[Dict]:
    """Match a hostname against known device patterns.

    Args:
        hostname: Device hostname string.

    Returns:
        Dict with device_type, manufacturer, os_family, model, confidence
        or None if no match.
    """
    if not hostname:
        return None

    patterns = load("hostname")  # list of dicts
    for entry in patterns:
        regex = entry.get("match", "")
        if regex and re.search(regex, hostname, re.IGNORECASE):
            return {
                "device_type": entry.get("category"),
                "manufacturer": entry.get("vendor"),
                "os_family": entry.get("platform"),
                "model": entry.get("model"),
                "confidence": entry.get("certainty", 50),
            }

    return None


# =====================================================================
# AI Services matching (from legacy ai_services.py)
# =====================================================================

_AI_HTTP_PATTERNS: list[tuple[str | None, str, dict]] = [
    (None, "/api/tags", {"service": "Ollama", "category": "inference", "confidence": 0.90}),
    ("POST", "/api/generate", {"service": "Ollama", "category": "inference", "confidence": 0.90}),
    ("POST", "/api/chat", {"service": "Ollama", "category": "inference", "confidence": 0.90}),
    (None, "/api/show", {"service": "Ollama", "category": "inference", "confidence": 0.85}),
    (None, "/sdapi/v1/", {"service": "Stable Diffusion WebUI", "category": "image_gen", "confidence": 0.90}),
    (None, "/sdapi/v1/options", {"service": "Stable Diffusion WebUI", "category": "image_gen", "confidence": 0.90}),
    (None, "/sdapi/v1/txt2img", {"service": "Stable Diffusion WebUI", "category": "image_gen", "confidence": 0.90}),
    (None, "/system_stats", {"service": "ComfyUI", "category": "image_gen", "confidence": 0.75}),
    (None, "/v2/repository/index", {"service": "Triton/KServe", "category": "inference", "confidence": 0.85}),
    (None, "/v2/models/", {"service": "Triton/KServe", "category": "inference", "confidence": 0.80}),
    (None, "/api/serve/applications", {"service": "Ray Serve", "category": "inference", "confidence": 0.85}),
    (None, "/health/readiness", {"service": "LiteLLM", "category": "gateway", "confidence": 0.75}),
    ("POST", "/v1/chat/completions", {"service": "OpenAI-compatible", "category": "inference", "confidence": 0.80}),
    ("POST", "/v1/completions", {"service": "OpenAI-compatible", "category": "inference", "confidence": 0.80}),
    ("POST", "/v1/embeddings", {"service": "OpenAI-compatible", "category": "inference", "confidence": 0.80}),
    (None, "/v1/models", {"service": "OpenAI-compatible", "category": "inference", "confidence": 0.75}),
]

AI_PORT_HINTS: dict[int, dict] = {
    11434: {"service": "Ollama", "confidence": 0.60},
    7860: {"service": "Gradio/SD WebUI", "confidence": 0.50},
    8188: {"service": "ComfyUI", "confidence": 0.50},
    8265: {"service": "Ray Serve", "confidence": 0.50},
    30000: {"service": "SGLang", "confidence": 0.50},
    4000: {"service": "LiteLLM", "confidence": 0.50},
    3001: {"service": "AnythingLLM", "confidence": 0.50},
    39281: {"service": "Jan", "confidence": 0.50},
}


def match_http_ai_path(method: str, path: str) -> Optional[Dict]:
    """Match an HTTP method+path against known AI service patterns."""
    if not path:
        return None
    path_lower = path.lower()
    for pattern_method, pattern_path, result in _AI_HTTP_PATTERNS:
        if pattern_method and pattern_method != method.upper():
            continue
        if path_lower.startswith(pattern_path.lower()):
            return dict(result)
    return None
