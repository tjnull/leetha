"""Name resolution processor -- DNS, DNS answer, mDNS, NetBIOS, SSDP."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence

# NTP server domains -> (vendor, os_family) hints
_NTP_VENDOR_MAP: dict[str, tuple[str | None, str | None]] = {
    "time.apple.com": ("Apple", "iOS/macOS"),
    "time.euro.apple.com": ("Apple", "iOS/macOS"),
    "time-ios.apple.com": ("Apple", "iOS"),
    "time-macos.apple.com": ("Apple", "macOS"),
    "time.windows.com": ("Microsoft", "Windows"),
    "time.google.com": ("Google", None),
    "time1.google.com": ("Google", None),
    "time2.google.com": ("Google", None),
    "time3.google.com": ("Google", None),
    "time4.google.com": ("Google", None),
    "time.android.com": ("Google", "Android"),
    "ntp.ubuntu.com": (None, "Linux"),
    "time.ui.com": ("Ubiquiti", None),
    "ntp.synology.com": ("Synology", None),
    "ntp.qnap.com": ("QNAP", None),
    "time.cloudflare.com": (None, None),
    "time.facebook.com": (None, None),
}


@register_processor("dns", "dns_answer", "mdns", "netbios", "ssdp", "upnp")
class NameResolutionProcessor(Processor):
    """Handles protocols that reveal hostnames, services, and device names."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "dns":
            return self._analyze_dns(packet)
        elif protocol == "dns_answer":
            return self._analyze_dns_answer(packet)
        elif protocol == "mdns":
            return self._analyze_mdns(packet)
        elif protocol == "netbios":
            return self._analyze_netbios(packet)
        elif protocol == "ssdp":
            return self._analyze_ssdp(packet)
        elif protocol == "upnp":
            return self._analyze_upnp(packet)
        return []

    def _analyze_dns(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        query_name = packet.get("query_name")
        query_type = packet.get("query_type", 1)

        if not query_name:
            return evidence

        evidence.append(Evidence(
            source="dns_query", method="pattern", certainty=0.40,
            raw={"query_name": query_name, "query_type": query_type},
        ))

        try:
            from leetha.patterns.matching import match_dns_query
            match = match_dns_query(query_name, query_type)
            if match and match.get("confidence", 0) >= 0.4:
                vendor = match.get("manufacturer")
                platform = match.get("os_family")
                if vendor or platform:
                    evidence.append(Evidence(
                        source="dns_vendor", method="pattern",
                        certainty=min(match.get("confidence", 0.5), 0.60),
                        vendor=vendor,
                        platform=platform,
                        raw={"query_name": query_name, "match": match.get("note", "")},
                    ))
        except ImportError:
            pass

        # NTP server inference -- detect vendor/OS from time server queries
        query_lower = query_name.lower().rstrip(".")
        ntp_hint = _NTP_VENDOR_MAP.get(query_lower)
        if ntp_hint:
            vendor, platform = ntp_hint
            if vendor or platform:
                evidence.append(Evidence(
                    source="dns_ntp_hint",
                    method="heuristic",
                    certainty=0.55,
                    vendor=vendor,
                    platform=platform,
                    raw={"query": query_name, "type": "ntp_server"},
                ))

        # Feed into behavioral profiler
        try:
            from leetha.rules.behavioral import _shared_tracker
            _shared_tracker.record(packet.hw_addr, query_name, query_type)
        except ImportError:
            pass

        return evidence

    def _analyze_dns_answer(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        hostname = packet.get("hostname")  # Only set by PTR records in DNS parser

        if hostname:
            import re as _re
            from leetha.evidence.hostname import is_valid_hostname
            # Strip mDNS service suffixes from PTR records:
            # "ESDK_7893c366477c._spotify-connect._tcp.local" -> "ESDK_7893c366477c"
            clean = hostname
            if "._" in clean:
                clean = clean.split("._")[0]
            if clean.endswith(".local"):
                clean = clean[:-6]
            clean = _re.sub(r'^[0-9A-Fa-f]{6,12}@', '', clean)
            clean = clean.strip(".-") or hostname

            if is_valid_hostname(clean):
                evidence.append(Evidence(
                    source="dns_answer", method="exact", certainty=0.60,
                    hostname=clean,
                    raw={"query_name": packet.get("query_name"), "hostname": hostname},
                ))
        return evidence

    # Vendor-exclusive mDNS services that DEFINITIVELY identify the vendor.
    # If a device advertises one of these, no OUI guess can override it.
    _EXCLUSIVE_SERVICES: dict[str, dict] = {
        # Apple-exclusive services — only Apple devices advertise these
        "_apple-mobdev2._tcp": {"vendor": "Apple", "category": "phone", "platform": "iOS", "certainty": 0.97},
        "_apple-mobdev._tcp": {"vendor": "Apple", "category": "phone", "platform": "iOS", "certainty": 0.97},
        "_companion-link._tcp": {"vendor": "Apple", "platform": "iOS", "certainty": 0.95},
        "_homekit._tcp": {"vendor": "Apple", "certainty": 0.90},
        "_airplay._tcp": {"vendor": "Apple", "certainty": 0.85},
        "_raop._tcp": {"vendor": "Apple", "certainty": 0.85},
        "_rdlink._tcp": {"vendor": "Apple", "certainty": 0.90},
        "_touch-able._tcp": {"vendor": "Apple", "category": "phone", "platform": "iOS", "certainty": 0.90},
        "_apple-pairable._tcp": {"vendor": "Apple", "certainty": 0.90},
        # Google-exclusive services
        "_googlecast._tcp": {"vendor": "Google", "category": "smart_speaker", "platform": "Cast OS", "certainty": 0.95},
        "_googlerpc._tcp": {"vendor": "Google", "certainty": 0.85},
        "_googlehomedevice._tcp": {"vendor": "Google", "category": "smart_speaker", "certainty": 0.90},
        # Amazon-exclusive
        "_amzn-wplay._tcp": {"vendor": "Amazon", "category": "smart_speaker", "platform": "Fire OS", "certainty": 0.90},
        # Samsung
        "_samsung-osp._tcp": {"vendor": "Samsung", "certainty": 0.90},
        "_samsungtvrc._tcp": {"vendor": "Samsung", "category": "smart_tv", "platform": "Tizen", "certainty": 0.95},
        "_samsung-msn._tcp": {"vendor": "Samsung", "category": "smart_tv", "platform": "Tizen", "certainty": 0.90},
        # Roku
        "_roku-rsp._tcp": {"vendor": "Roku", "category": "streaming_device", "platform": "RokuOS", "certainty": 0.95},
        # Sonos
        "_sonos._tcp": {"vendor": "Sonos", "category": "smart_speaker", "certainty": 0.95},
        # LG TV
        "_lgtvremote._tcp": {"vendor": "LG", "category": "smart_tv", "platform": "webOS", "certainty": 0.95},
    }

    # Regex for AirPlay/RAOP instance names: "<hex_id>@<friendly_name>"
    # The hex_id is the advertising device's MAC or device ID — if it
    # doesn't match the packet source MAC, this mDNS belongs to another device.
    _AIRPLAY_NAME_RE = __import__("re").compile(
        r"^([0-9A-Fa-f]{6,12})@(.+)$"
    )

    def _analyze_mdns(self, packet: CapturedPacket) -> list[Evidence]:
        from leetha.evidence.hostname import is_valid_hostname
        evidence = []
        service_type = packet.get("service_type")
        name = packet.get("name")
        txt_records = packet.get("txt_records", {})

        # Detect AirPlay/RAOP-style names: "<hex_id>@<friendly_name>".
        # If the hex ID doesn't match the source MAC, this mDNS service
        # belongs to a DIFFERENT device (e.g., a HomePod advertising through
        # an iPhone or router).  Flag it so we don't adopt another device's
        # identity, hostname, or category.
        belongs_to_other_device = False
        if name:
            m = self._AIRPLAY_NAME_RE.match(name)
            if m:
                advertised_id = m.group(1).upper()
                src_mac_norm = packet.hw_addr.replace(":", "").upper()
                if advertised_id not in src_mac_norm and src_mac_norm not in advertised_id:
                    belongs_to_other_device = True

        if service_type:
            # Check for vendor-exclusive services FIRST — these are definitive
            exclusive = self._EXCLUSIVE_SERVICES.get(service_type)
            if exclusive:
                # If this mDNS name contains another device's ID, only keep
                # vendor (still useful for vendor identification) but strip
                # category/platform which belong to the other device.
                evidence.append(Evidence(
                    source="mdns_exclusive", method="exact",
                    certainty=exclusive["certainty"] if not belongs_to_other_device else min(exclusive["certainty"], 0.50),
                    vendor=exclusive.get("vendor"),
                    category=None if belongs_to_other_device else exclusive.get("category"),
                    platform=None if belongs_to_other_device else exclusive.get("platform"),
                    raw={"service_type": service_type, "name": name,
                         "exclusive_match": True,
                         "cross_device": belongs_to_other_device},
                ))
            else:
                evidence.append(Evidence(
                    source="mdns_service", method="pattern", certainty=0.70,
                    raw={"service_type": service_type, "name": name},
                ))
                # General mDNS service pattern matching
                from leetha.patterns.matching import match_mdns_service
                mdns_match = match_mdns_service(service_type, name)
                if mdns_match:
                    raw_conf = mdns_match.get("confidence", 70)
                    cert = raw_conf / 100.0 if raw_conf > 1 else raw_conf
                    evidence.append(Evidence(
                        source="mdns_service", method="pattern",
                        certainty=cert,
                        vendor=mdns_match.get("manufacturer"),
                        category=mdns_match.get("device_type"),
                        platform=mdns_match.get("os_family"),
                        raw={"service_type": service_type, "match": mdns_match},
                    ))

        if txt_records:
            model = txt_records.get("model") or txt_records.get("md")
            vendor = txt_records.get("manufacturer") or txt_records.get("vendor")
            friendly_name = txt_records.get("fn")
            validated_fn = friendly_name if is_valid_hostname(friendly_name) else None

            # SYSTYPE/devtype TXT fields — used by Lutron, Belkin, etc. to
            # advertise the device's platform/model (e.g. "SmartBridge").
            systype = txt_records.get("systype") or txt_records.get("devtype")
            if systype:
                model = model or systype

            # AirPlay/HAP TXT records carry rich device metadata:
            #   deviceid  = real device MAC (may differ from Ethernet src)
            #   serialnumber = hardware serial
            #   ci        = HAP category integer (2=bridge, 14=outlet, etc.)
            # Use ci to infer category for HomeKit devices
            hap_ci = txt_records.get("ci")
            hap_category = None
            if hap_ci:
                _HAP_CATEGORIES = {
                    "1": "other", "2": "bridge", "3": "fan",
                    "5": "garage_door", "6": "smart_lighting",
                    "7": "smart_lock", "8": "smart_plug",
                    "9": "smart_plug", "10": "sensor",
                    "11": "smart_plug", "12": "thermostat",
                    "13": "sensor", "14": "security_system",
                    "17": "sensor", "22": "sensor",
                    "28": "sprinkler", "29": "faucet",
                    "30": "smart_display", "31": "smart_speaker",
                    "32": "media_player",
                }
                hap_category = _HAP_CATEGORIES.get(str(hap_ci))

            if model or vendor:
                evidence.append(Evidence(
                    source="mdns_txt", method="exact", certainty=0.80,
                    model=model,
                    vendor=vendor,
                    category=hap_category,
                    hostname=validated_fn,
                    raw={"txt_records": txt_records},
                ))
            elif validated_fn:
                evidence.append(Evidence(
                    source="mdns_txt", method="exact", certainty=0.75,
                    hostname=validated_fn,
                    raw={"txt_records": txt_records},
                ))

        # Apple model code lookup from mDNS TXT 'am' field
        apple_model_code = packet.get("apple_model")
        if apple_model_code:
            try:
                from leetha.fingerprint.lookup import ModelLookup
                amap = ModelLookup.APPLE_MODEL_MAP
                friendly = amap.get(apple_model_code, apple_model_code)
                # Infer category from the model code prefix
                if apple_model_code.startswith("iPhone"):
                    a_cat = "phone"
                elif apple_model_code.startswith("iPad"):
                    a_cat = "tablet"
                elif apple_model_code.startswith("AudioAccessory"):
                    a_cat = "smart_speaker"
                elif apple_model_code.startswith("AppleTV"):
                    a_cat = "media_player"
                elif apple_model_code.startswith("Watch"):
                    a_cat = "wearable"
                elif apple_model_code.startswith("MacBook"):
                    a_cat = "laptop"
                elif apple_model_code.startswith(("iMac", "Mac")):
                    a_cat = "desktop"
                else:
                    a_cat = None
                evidence.append(Evidence(
                    source="mdns_apple_model", method="exact",
                    certainty=0.92,
                    vendor="Apple",
                    model=friendly,
                    category=a_cat,
                    platform="iOS/macOS",
                    raw={"apple_model_code": apple_model_code,
                         "resolved_name": friendly},
                ))
            except (ImportError, AttributeError):
                pass

        # Hostname priority (best to worst):
        # 1. SRV target hostname (e.g. "Lutron-06847038") — the device's
        #    actual .local hostname, most reliable
        # 2. TXT friendly name (fn) — human-readable name from TXT records
        # 3. mDNS instance name — often a service description, not a hostname
        #
        # If the mDNS name belongs to a different device (detected via hex ID
        # mismatch), do NOT use it as this device's hostname.
        srv_target = packet.get("srv_target")
        friendly = txt_records.get("fn") if txt_records else None
        mdns_hostname = None
        if not belongs_to_other_device:
            if srv_target and is_valid_hostname(srv_target):
                mdns_hostname = srv_target
            elif friendly and is_valid_hostname(friendly):
                mdns_hostname = friendly
            elif name and is_valid_hostname(name):
                mdns_hostname = name

        if mdns_hostname:
            # SRV target is the device's actual .local hostname — higher
            # certainty than instance names which are often service descriptions
            if srv_target and mdns_hostname == srv_target:
                hn_certainty = 0.85
                hn_source = "mdns_srv"
            elif friendly and mdns_hostname == friendly:
                hn_certainty = 0.75
                hn_source = "mdns_name"
            else:
                hn_certainty = 0.65
                hn_source = "mdns_name"
            evidence.append(Evidence(
                source=hn_source, method="exact", certainty=hn_certainty,
                hostname=mdns_hostname,
                raw={"name": name, "service_type": service_type,
                     "friendly_name": friendly,
                     "srv_target": srv_target},
            ))

        return evidence

    def _analyze_netbios(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        query_name = packet.get("query_name")
        query_type = packet.get("query_type", "llmnr")
        netbios_suffix = packet.get("netbios_suffix")

        if query_name:
            evidence.append(Evidence(
                source="netbios", method="exact", certainty=0.70,
                hostname=query_name,
                raw={"query_name": query_name, "query_type": query_type,
                     "netbios_suffix": netbios_suffix},
            ))
            # Hostname pattern matching on NetBIOS name
            from leetha.patterns.matching import match_hostname
            host_match = match_hostname(query_name)
            if host_match:
                raw_conf = host_match.get("confidence", 65)
                cert = raw_conf / 100.0 if raw_conf > 1 else raw_conf
                evidence.append(Evidence(
                    source="netbios", method="pattern",
                    certainty=cert,
                    vendor=host_match.get("manufacturer"),
                    category=host_match.get("device_type"),
                    platform=host_match.get("os_family"),
                    hostname=query_name,
                    raw={"query_name": query_name, "match": host_match},
                ))
        return evidence

    def _analyze_upnp(self, packet: CapturedPacket) -> list[Evidence]:
        """UPnP device description — reveals device services."""
        payload = packet.get("payload_preview", "")
        evidence = [Evidence(
            source="upnp", method="pattern", certainty=0.60,
            raw={"dst_port": packet.get("dst_port"), "preview": payload[:100]},
        )]
        # Check for specific UPnP device types
        payload_lower = payload.lower()
        if "mediarenderer" in payload_lower:
            evidence[0].category = "media_player"
        elif "mediaserver" in payload_lower:
            evidence[0].category = "media_server"
        elif "internetgateway" in payload_lower:
            evidence[0].category = "router"
        return evidence

    def _analyze_ssdp(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        server = packet.get("server")
        st = packet.get("st")

        if server:
            evidence.append(Evidence(
                source="ssdp_server", method="pattern", certainty=0.65,
                raw={"server": server, "st": st},
            ))
            # SSDP SERVER header pattern matching
            from leetha.patterns.matching import match_ssdp_server
            ssdp_match = match_ssdp_server(server)
            if ssdp_match:
                raw_conf = ssdp_match.get("confidence", 65)
                cert = raw_conf / 100.0 if raw_conf > 1 else raw_conf
                evidence.append(Evidence(
                    source="ssdp_server", method="pattern",
                    certainty=cert,
                    vendor=ssdp_match.get("manufacturer"),
                    category=ssdp_match.get("device_type"),
                    platform=ssdp_match.get("os_family"),
                    raw={"server": server, "match": ssdp_match},
                ))
        return evidence
