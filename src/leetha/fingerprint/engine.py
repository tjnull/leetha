"""
Core fingerprint engine.

Takes raw parsed packet data (from the capture engine) and produces
FingerprintMatch lists by delegating to the FingerprintLookup module.
"""

from __future__ import annotations

from leetha.fingerprint.lookup import FingerprintLookup
from leetha.fingerprint.evidence import FingerprintMatch


class FingerprintEngine:
    """
    Core fingerprint engine that processes parsed packets into fingerprint matches.

    Each process_* method takes raw fields extracted from a packet and returns
    a list of FingerprintMatch objects from all applicable lookup methods.
    """

    def __init__(self) -> None:
        self.lookup = FingerprintLookup()
        self._oui_seen: set[str] = set()

    def reload(self):
        """Reload all fingerprint lookup data after sync."""
        self.lookup.reload()

    def _lookup_oui_once(self, mac: str) -> list[FingerprintMatch]:
        """Return OUI matches for *mac*, but only the first time per MAC."""
        if mac in self._oui_seen:
            return []
        self._oui_seen.add(mac)
        # Cap the set size to prevent unbounded memory growth
        if len(self._oui_seen) > 50000:
            self._oui_seen.clear()
        return self.lookup.lookup_mac(mac)

    def process_tcp_syn(
        self,
        src_mac: str,
        src_ip: str,
        ttl: int,
        window_size: int,
        mss: int | None = None,
        tcp_options: str = "",
    ) -> list[FingerprintMatch]:
        """Process a TCP SYN packet. Returns matches from OUI + TCP sig + TTL."""
        matches: list[FingerprintMatch] = []

        # OUI lookup from MAC
        matches.extend(self._lookup_oui_once(src_mac))

        # Build p0f-style TCP signature and look it up
        sig = self._build_tcp_signature(ttl, window_size, mss, tcp_options)
        tcp_match = self.lookup.lookup_tcp(sig)
        if tcp_match:
            matches.append(tcp_match)

        # TTL-based OS heuristic (always available)
        ttl_match = self.lookup.lookup_ttl(ttl)
        if ttl_match:
            matches.append(ttl_match)

        return matches

    def process_dhcpv4(
        self,
        client_mac: str,
        opt55: str | None = None,
        opt60: str | None = None,
        hostname: str | None = None,
        client_id: str | None = None,
    ) -> list[FingerprintMatch]:
        """Process DHCPv4 packet. Returns matches from DHCP options + OUI + hostname.

        When the layer-2 MAC is randomized but DHCP Option 61 (Client
        Identifier) contains a real hardware MAC, we use the Option 61 MAC
        for OUI lookup — this recovers manufacturer identity that would
        otherwise be lost to MAC randomization.
        """
        from leetha.fingerprint.mac_intel import is_randomized_mac

        matches: list[FingerprintMatch] = []

        # OUI lookup — try layer-2 MAC first
        oui_matches = self._lookup_oui_once(client_mac)
        matches.extend(oui_matches)

        # If layer-2 MAC is randomized but Option 61 has a real MAC, use it
        if not oui_matches and client_id and is_randomized_mac(client_mac):
            if not is_randomized_mac(client_id) and client_id != client_mac:
                opt61_matches = self._lookup_oui_once(client_id)
                for m in opt61_matches:
                    m.raw_data["via_option61"] = True
                    m.raw_data["option61_mac"] = client_id
                matches.extend(opt61_matches)

        # DHCP options lookup (may return multiple matches)
        dhcp_matches = self.lookup.lookup_dhcp(opt55=opt55, opt60=opt60)
        matches.extend(dhcp_matches)

        # Hostname-based identification (strong signal for IoT devices)
        hostname_match = self.lookup.lookup_hostname(hostname)
        if hostname_match:
            matches.append(hostname_match)

        return matches

    def process_dhcpv6(
        self,
        client_mac: str,
        oro: str | None = None,
        duid: str | None = None,
        vendor_class: str | None = None,
        enterprise_id: int | None = None,
        fqdn: str | None = None,
    ) -> list[FingerprintMatch]:
        """Process DHCPv6 packet. Returns matches from DHCPv6 fields + OUI."""
        matches: list[FingerprintMatch] = []

        # OUI lookup
        matches.extend(self._lookup_oui_once(client_mac))

        # DHCPv6 lookup (returns list of parallel evidence)
        dhcpv6_matches = self.lookup.lookup_dhcpv6(
            oro=oro, vendor_class=vendor_class, enterprise_id=enterprise_id,
        )
        matches.extend(dhcpv6_matches)

        return matches

    def process_mdns(
        self,
        src_mac: str,
        src_ip: str,
        service_type: str,
        name: str | None = None,
        packet_data: dict | None = None,
    ) -> list[FingerprintMatch]:
        """Process mDNS packet. Returns matches from mDNS service + OUI + TXT."""
        matches: list[FingerprintMatch] = []

        # OUI lookup
        matches.extend(self._lookup_oui_once(src_mac))

        # mDNS service lookup (now returns a list and uses TXT record data)
        mdns_matches = self.lookup.lookup_mdns(service_type, name, packet_data)
        matches.extend(mdns_matches)

        return matches

    def process_ssdp(
        self,
        src_mac: str,
        src_ip: str,
        server: str | None = None,
        st: str | None = None,
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        ssdp_match = self.lookup.lookup_ssdp(server=server, st=st)
        if ssdp_match:
            matches.append(ssdp_match)

        # Extract UPnP device type hints from ST (search target) field
        if st:
            st_lower = st.lower()
            upnp_type = None
            if "mediaserver" in st_lower:
                upnp_type = "media_server"
            elif "mediarenderer" in st_lower:
                upnp_type = "media_player"
            elif "internetgateway" in st_lower:
                upnp_type = "router"
            elif "wanconnection" in st_lower:
                upnp_type = "router"
            elif "printer" in st_lower:
                upnp_type = "printer"
            elif "scanner" in st_lower:
                upnp_type = "scanner"
            elif "samsung" in st_lower:
                # Samsung ST alone doesn't imply smart_tv -- could be phone, tablet, etc.
                matches.append(FingerprintMatch(
                    source="ssdp_upnp",
                    match_type="pattern",
                    confidence=0.55,
                    manufacturer="Samsung",
                    raw_data={"st": st},
                ))
                upnp_type = None  # already emitted
            elif "dial" in st_lower:
                # DIAL is used by Chromecasts, Fire TVs, game consoles -- not just smart TVs
                matches.append(FingerprintMatch(
                    source="ssdp_upnp",
                    match_type="pattern",
                    confidence=0.50,
                    device_type="media_device",
                    raw_data={"st": st},
                ))
                upnp_type = None  # already emitted

            if upnp_type:
                matches.append(FingerprintMatch(
                    source="ssdp_upnp",
                    match_type="exact",
                    confidence=0.75,
                    device_type=upnp_type,
                    raw_data={"st": st},
                ))

        return matches

    def process_netbios(self, src_mac: str, src_ip: str, query_name: str, query_type: str = "llmnr", netbios_suffix: int | None = None) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        nb_match = self.lookup.lookup_netbios(query_name=query_name, query_type=query_type, netbios_suffix=netbios_suffix)
        if nb_match:
            matches.append(nb_match)
        return matches

    def process_tls(
        self,
        src_mac: str,
        src_ip: str,
        ja3_hash: str,
        ja4: str,
        sni: str | None = None,
    ) -> list[FingerprintMatch]:
        """Process TLS Client Hello fingerprints."""
        matches: list[FingerprintMatch] = []

        matches.extend(self._lookup_oui_once(src_mac))

        ja3_match = self.lookup.lookup_ja3(ja3_hash)
        if ja3_match:
            matches.append(ja3_match)

        ja4_match = self.lookup.lookup_ja4(ja4)
        if ja4_match:
            matches.append(ja4_match)

        # TLS SNI cloud service pattern matching
        if sni:
            sni_match = self.lookup.lookup_tls_sni(sni)
            if sni_match:
                matches.append(sni_match)

        # SNI vendor hint — correlate destination domains with device vendors
        if sni:
            sni_lower = sni.lower()
            sni_vendor = None
            sni_platform = None

            def _sni_matches_domain(sni_host: str, domain: str) -> bool:
                return sni_host == domain or sni_host.endswith("." + domain)

            if any(_sni_matches_domain(sni_lower, d) for d in ("apple.com", "icloud.com", "mzstatic.com")):
                sni_vendor, sni_platform = "Apple", "iOS/macOS"
            elif any(_sni_matches_domain(sni_lower, d) for d in ("google.com", "googleapis.com", "gstatic.com", "android.com")):
                sni_vendor = "Google"
            elif any(_sni_matches_domain(sni_lower, d) for d in ("microsoft.com", "windows.com", "msftconnecttest.com", "live.com", "office.com")):
                sni_vendor, sni_platform = "Microsoft", "Windows"
            elif any(_sni_matches_domain(sni_lower, d) for d in ("samsung.com", "samsungcloud.com")):
                sni_vendor = "Samsung"
            elif any(_sni_matches_domain(sni_lower, d) for d in ("amazon.com", "amazonaws.com", "alexa.amazon.com")):
                sni_vendor = "Amazon"
            elif _sni_matches_domain(sni_lower, "roku.com"):
                sni_vendor, sni_platform = "Roku", "RokuOS"

            if sni_vendor:
                matches.append(FingerprintMatch(
                    source="tls_sni",
                    match_type="pattern",
                    confidence=0.45,
                    manufacturer=sni_vendor,
                    os_family=sni_platform,
                    raw_data={"sni": sni},
                ))

        return matches

    def process_arp(
        self,
        src_mac: str,
        src_ip: str,
    ) -> list[FingerprintMatch]:
        """Process ARP packet. Returns OUI match only."""
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        return matches

    def process_dns(
        self,
        src_mac: str,
        src_ip: str,
        query_name: str,
        query_type: int,
        query_type_name: str | None = None,  # Informational, not used for fingerprinting
    ) -> list[FingerprintMatch]:
        """Process DNS query packet."""
        matches = []

        # OUI lookup
        matches.extend(self._lookup_oui_once(src_mac))

        # DNS domain pattern
        dns_match = self.lookup.lookup_dns(query_name, query_type)
        if dns_match:
            matches.append(dns_match)

        return matches

    def process_icmpv6(
        self,
        src_mac: str,
        src_ip: str,
        icmpv6_type: str,
        hop_limit: int = None,
        managed: int = None,
        other: int = None,
        options: dict = None,
        **kwargs,
    ) -> list[FingerprintMatch]:
        """Process ICMPv6 Neighbor Discovery packet."""
        matches = []

        # OUI lookup
        matches.extend(self._lookup_oui_once(src_mac))

        # ICMPv6 RA fingerprint
        if icmpv6_type == "router_advertisement" and hop_limit is not None:
            icmpv6_match = self.lookup.lookup_icmpv6(
                icmpv6_type, hop_limit, managed or 0, other or 0, options or {}
            )
            if icmpv6_match:
                matches.append(icmpv6_match)

        return matches

    def process_ip_observed(
        self, src_mac: str, src_ip: str, ttl: int, ttl_os_hint: str,
    ) -> list[FingerprintMatch]:
        """Process an ip_observed event. Returns OUI + TTL heuristic matches."""
        matches = []
        matches.extend(self._lookup_oui_once(src_mac))
        ttl_match = self.lookup.lookup_ttl(ttl)
        if ttl_match:
            matches.append(ttl_match)
        return matches

    def process_dns_answer(
        self, query_name: str, hostname: str | None = None,
    ) -> list[FingerprintMatch]:
        """Process a dns_answer event. Returns hostname-based matches."""
        matches = []
        name = hostname or query_name
        if name:
            hn = self.lookup.lookup_hostname(name)
            if hn:
                matches.append(hn)
        return matches

    def process_http_useragent(
        self, src_mac: str, user_agent: str, host: str | None = None,
    ) -> list[FingerprintMatch]:
        """Process an http_useragent event. Returns OUI + UA + host matches."""
        matches = []
        matches.extend(self._lookup_oui_once(src_mac))
        ua_match = self.lookup.lookup_useragent(user_agent)
        if ua_match:
            matches.append(ua_match)
        # HTTP Host header cloud service pattern matching
        if host:
            host_match = self.lookup.lookup_http_host(host)
            if host_match:
                matches.append(host_match)
        return matches

    def process_lldp(self, src_mac: str, system_name: str = "",
                     system_description: str = "", capabilities: list[str] | None = None,
                     management_ip: str | None = None) -> list[FingerprintMatch]:
        """Extract device identity from LLDP TLVs."""
        matches = []
        capabilities = capabilities or []

        _CAP_MAP = {
            "router": "router",
            "bridge": "switch",
            "wlan_ap": "access_point",
            "station": "workstation",
            "telephone": "voip_phone",
            "docsis": "cable_modem",
            "repeater": "switch",
        }

        device_type = None
        for cap in capabilities:
            if cap in _CAP_MAP:
                device_type = _CAP_MAP[cap]
                break

        os_family = None
        manufacturer = None
        desc_lower = system_description.lower() if system_description else ""
        if "cisco ios" in desc_lower or "cisco nx-os" in desc_lower:
            manufacturer = "Cisco"
            os_family = "NX-OS" if "nx-os" in desc_lower else "IOS"
        elif "junos" in desc_lower:
            manufacturer = "Juniper"
            os_family = "Junos"
        elif "linux" in desc_lower:
            os_family = "Linux"
        elif "windows" in desc_lower:
            os_family = "Windows"
        elif "aruba" in desc_lower:
            manufacturer = "Aruba"
            os_family = "ArubaOS"
        elif "extreme" in desc_lower:
            manufacturer = "Extreme"
        elif "fortinet" in desc_lower or "fortigate" in desc_lower:
            manufacturer = "Fortinet"
            os_family = "FortiOS"
        elif "mikrotik" in desc_lower or "routeros" in desc_lower:
            manufacturer = "MikroTik"
            os_family = "RouterOS"

        # Only emit a high-confidence match if we extracted useful identity info
        has_identity = any(v is not None for v in (device_type, manufacturer, os_family))
        if has_identity:
            match = FingerprintMatch(
                source="lldp",
                match_type="exact",
                confidence=0.90,
                device_type=device_type,
                manufacturer=manufacturer,
                os_family=os_family,
                model=system_name or None,
                raw_data={
                    "system_name": system_name,
                    "system_description": system_description,
                    "capabilities": capabilities,
                    "management_ip": management_ip,
                },
            )
            matches.append(match)
        elif system_name or system_description:
            # We have some raw data but couldn't parse identity -- low confidence
            match = FingerprintMatch(
                source="lldp",
                match_type="heuristic",
                confidence=0.10,
                model=system_name or None,
                raw_data={
                    "system_name": system_name,
                    "system_description": system_description,
                    "capabilities": capabilities,
                    "management_ip": management_ip,
                },
            )
            matches.append(match)
        return matches

    def process_cdp(self, src_mac: str, device_id: str = "",
                    platform: str = "", software_version: str = "",
                    capabilities: list[str] | None = None,
                    management_ip: str | None = None) -> list[FingerprintMatch]:
        """Extract device identity from CDP fields."""
        import re
        matches = []
        capabilities = capabilities or []

        _CAP_MAP = {
            "router": "router",
            "switch": "switch",
            "host": "workstation",
            "phone": "voip_phone",
            "igmp": "router",
        }

        device_type = None
        for cap in capabilities:
            cap_lower = cap.lower()
            if cap_lower in _CAP_MAP:
                device_type = _CAP_MAP[cap_lower]
                break

        manufacturer = None
        model = None
        if platform:
            platform_lower = platform.lower()
            if "cisco" in platform_lower:
                manufacturer = "Cisco"
                for prefix in ("cisco ", "Cisco "):
                    if platform.startswith(prefix):
                        model = platform[len(prefix):].strip()
                        break
                if not model:
                    model = platform
            else:
                model = platform

        os_family = None
        os_version = None
        ver_lower = software_version.lower() if software_version else ""
        if "ios-xe" in ver_lower:
            os_family = "IOS-XE"
        elif "ios" in ver_lower and "cisco" in ver_lower:
            os_family = "IOS"
        elif "nx-os" in ver_lower:
            os_family = "NX-OS"
        elif "adaptive security" in ver_lower or "asa" in ver_lower:
            os_family = "ASA"

        ver_match = re.search(r'Version\s+([\d.()A-Za-z]+)', software_version)
        if ver_match:
            os_version = ver_match.group(1)

        match = FingerprintMatch(
            source="cdp",
            match_type="exact",
            confidence=0.92,
            device_type=device_type,
            manufacturer=manufacturer,
            os_family=os_family,
            os_version=os_version,
            model=model,
            raw_data={
                "device_id": device_id,
                "platform": platform,
                "software_version": software_version,
                "capabilities": capabilities,
                "management_ip": management_ip,
            },
        )
        matches.append(match)
        return matches

    def process_stp(self, src_mac: str, bridge_priority: int = 32768,
                    bridge_mac: str = "", is_root: bool = False) -> list[FingerprintMatch]:
        """Extract device type from STP bridge parameters."""
        if bridge_priority < 8192:
            confidence = 0.60
        elif bridge_priority < 32768:
            confidence = 0.50
        else:
            confidence = 0.15

        if is_root:
            confidence = min(confidence + 0.10, 0.70)

        return [FingerprintMatch(
            source="stp",
            match_type="heuristic",
            confidence=confidence,
            device_type="switch",
            raw_data={
                "bridge_priority": bridge_priority,
                "bridge_mac": bridge_mac,
                "is_root": is_root,
            },
        )]

    def process_snmp(self, src_mac: str, version: str = "", community: str = "",
                     pdu_type: str = "", sys_descr: str = "",
                     sys_name: str = "", sys_object_id: str = "") -> list[FingerprintMatch]:
        """Extract device identity from SNMP fields."""
        import re

        os_family = None
        os_version = None
        manufacturer = None
        device_type = None

        if sys_descr:
            descr_lower = sys_descr.lower()
            if "cisco ios" in descr_lower or "cisco nx-os" in descr_lower:
                manufacturer = "Cisco"
                os_family = "NX-OS" if "nx-os" in descr_lower else "IOS"
                device_type = "switch"
            elif "junos" in descr_lower:
                manufacturer = "Juniper"
                os_family = "Junos"
            elif "linux" in descr_lower:
                os_family = "Linux"
                ver_match = re.search(r'Linux\s+\S+\s+([\d.]+)', sys_descr)
                if ver_match:
                    os_version = ver_match.group(1)
            elif "windows" in descr_lower:
                os_family = "Windows"
            elif "freebsd" in descr_lower:
                os_family = "FreeBSD"
            elif "net-snmp" in descr_lower:
                os_family = "Linux"
            elif "arista" in descr_lower:
                manufacturer = "Arista"
                os_family = "EOS"
            elif "hp" in descr_lower or "procurve" in descr_lower:
                manufacturer = "HP"
                device_type = "switch"
            elif "ubiquiti" in descr_lower or "unifi" in descr_lower:
                manufacturer = "Ubiquiti"
            elif "fortinet" in descr_lower:
                manufacturer = "Fortinet"
                os_family = "FortiOS"

        confidence = 0.85 if sys_descr else 0.30

        return [FingerprintMatch(
            source="snmp",
            match_type="exact" if sys_descr else "heuristic",
            confidence=confidence,
            device_type=device_type,
            manufacturer=manufacturer,
            os_family=os_family,
            os_version=os_version,
            raw_data={
                "version": version,
                "community": community,
                "pdu_type": pdu_type,
                "sys_descr": sys_descr,
                "sys_name": sys_name,
                "sys_object_id": sys_object_id,
            },
        )]

    def process_ws_discovery(
        self,
        src_mac: str,
        device_types: list[str] | None = None,
        manufacturer: str | None = None,
        model: str | None = None,
        firmware: str | None = None,
    ) -> list[FingerprintMatch]:
        """Process WS-Discovery announcement."""
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        if manufacturer or model:
            device_type = device_types[0] if device_types else None
            matches.append(FingerprintMatch(
                source="ws_discovery",
                match_type="exact",
                confidence=0.85,
                manufacturer=manufacturer,
                model=model,
                device_type=device_type,
                raw_data={
                    "device_types": device_types or [],
                    "firmware": firmware,
                },
            ))
        return matches

    def process_ntp(
        self,
        src_mac: str,
        mode: str,
        stratum: int = 0,
        reference_id: str = "",
    ) -> list[FingerprintMatch]:
        """Process NTP packet."""
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        if mode in ("server", "broadcast"):
            matches.append(FingerprintMatch(
                source="ntp",
                match_type="heuristic",
                confidence=0.55,
                device_type="network_device",
                raw_data={"ntp_role": mode, "stratum": stratum, "reference_id": reference_id},
            ))
        return matches

    def process_service_banner(
        self, src_mac: str, service: str, software: str | None = None,
        version: str | None = None, server_port: int | None = None, **kwargs
    ) -> list[FingerprintMatch]:
        """Process a passively captured service banner."""
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))

        device_type = None
        if service in ("ipp", "jetdirect", "lpd"):
            device_type = "printer"
        elif service in ("mysql", "postgresql", "mssql", "mongodb", "redis",
                         "cassandra", "elasticsearch"):
            device_type = "server"
        elif service == "rdp":
            device_type = "workstation"
        elif service in ("rtsp", "unifiprotect"):
            device_type = "ip_camera"
        elif service == "sip":
            device_type = "voip_phone"

        os_family = None
        if service == "rdp":
            os_family = "Windows"
        elif service == "mssql":
            os_family = "Windows"

        if software or version or device_type:
            matches.append(FingerprintMatch(
                source="passive_banner",
                match_type="pattern",
                confidence=0.85,
                manufacturer=None,
                device_type=device_type,
                os_family=os_family,
                os_version=version,
                raw_data={
                    "service": service, "software": software,
                    "version": version, "server_port": server_port,
                },
            ))
        return matches

    def process_iot_scada(
        self, src_mac: str, protocol: str, **fields
    ) -> list[FingerprintMatch]:
        """Process an IoT/SCADA protocol packet (Modbus, BACnet, CoAP, MQTT, EtherNet/IP)."""
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))

        device_type_map = {
            "modbus": "ics_device",
            "bacnet": "building_automation",
            "coap": "iot_device",
            "mqtt": "iot_device",
            "enip": "ics_device",
        }
        device_type = device_type_map.get(protocol, "iot_device")

        matches.append(FingerprintMatch(
            source=protocol,
            match_type="pattern",
            confidence=0.60,
            device_type=device_type,
            raw_data=fields,
        ))
        return matches

    @staticmethod
    def _build_tcp_signature(
        ttl: int, window_size: int, mss: int | None, tcp_options: str
    ) -> str:
        """Build a p0f-style TCP signature string for lookup."""
        # p0f signature format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
        # Simplified: we use "ttl:window:mss:options"
        mss_str = str(mss) if mss else "*"
        return f"{ttl}:{window_size}:{mss_str}:{tcp_options}"
