"""Packet processing pipeline.

Receives CapturedPackets from the capture engine, routes them through
registered processors, computes verdicts, stores results, and evaluates
finding rules. Designed for concurrent execution.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone

from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence, Verdict
from leetha.evidence.engine import VerdictEngine
from leetha.fingerprint.lookup import FingerprintLookup
from leetha.processors.registry import get_processor, get_all_processors
from leetha.rules.registry import get_all_rules
from leetha.store.models import Host, Sighting

import ipaddress as _ipaddress


def _is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is RFC1918 private or link-local."""
    try:
        return _ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


import re as _re
_VALID_MAC_RE = _re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def _is_valid_mac(mac: str) -> bool:
    """Return True if *mac* is a valid unicast Ethernet MAC address.

    Rejects IPs misidentified as MACs (from TUN interfaces), broadcast
    addresses, and empty/malformed strings.
    """
    if not mac or not _VALID_MAC_RE.match(mac):
        return False
    # Reject broadcast (ff:ff:ff:ff:ff:ff) and all-zeros
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    return True

logger = logging.getLogger(__name__)


class Pipeline:
    """Main packet processing pipeline.

    Flow: CapturedPacket -> Processors -> Evidence -> VerdictEngine ->
          Store (batch) -> FindingRules -> Findings
    """

    def __init__(self, store, verdict_engine: VerdictEngine | None = None,
                 on_verdict=None, on_arp=None, on_dhcp=None, on_gateway_hint=None,
                 is_local_mac=None, on_new_host=None):
        self.store = store
        self.verdict_engine = verdict_engine or VerdictEngine()
        self._on_verdict = on_verdict          # async(hw_addr, verdict, packet)
        self._on_arp = on_arp                  # async(packet)
        self._on_dhcp = on_dhcp                # callable(packet) -- sync fire-and-forget
        self._on_gateway_hint = on_gateway_hint  # async(mac, ip, source, interface)
        self._is_local_mac = is_local_mac      # callable(mac) -> bool
        self._on_new_host = on_new_host        # async(hw_addr, host, packet)
        self._lookup = FingerprintLookup()
        self._evidence_buffer: dict[str, list[Evidence]] = defaultdict(list)
        self._oui_vendors: dict[str, str] = {}  # MAC -> OUI vendor name
        self._oui_device_types: dict[str, str] = {}  # MAC -> OUI device type
        self._gateway_macs: set[str] = set()  # MACs known to be gateways/routers
        self._lookup_done: set = set()  # (MAC, protocol) pairs already looked up
        self._batch_queue: list = []
        self._last_seen: dict[str, float] = {}  # MAC -> monotonic timestamp (for LRU)
        self._max_tracked_macs = 20_000  # cleanup threshold
        self._processor_instances: dict[str, object] = {}
        self._rule_instances: list = []
        self._running = False

        # Instantiate all registered processors
        for proto, cls in get_all_processors().items():
            if cls not in [type(p) for p in self._processor_instances.values()]:
                instance = cls()
                self._processor_instances[proto] = instance
            else:
                # Reuse existing instance for same class (multi-protocol processors)
                for existing in self._processor_instances.values():
                    if isinstance(existing, cls):
                        self._processor_instances[proto] = existing
                        break

        # Instantiate all registered rules
        for name, cls in get_all_rules().items():
            self._rule_instances.append(cls())

    # Evidence sources that can carry forwarded/reflected traffic from other
    # devices. Routers relay mDNS multicast AND respond to mDNS-related DNS
    # queries (PTR records), so dns_answer is included here.
    _FORWARDED_EVIDENCE_SOURCES = frozenset((
        "mdns_service", "mdns_exclusive", "mdns",
        "mdns_txt", "mdns_name", "mdns_srv", "mdns_apple_model",
        "dns_answer",
    ))

    def _scrub_infra_mdns(self, hw_addr: str) -> None:
        """Retroactively strip mDNS hostnames/vendors from evidence buffer
        for a device that was just identified as infrastructure.

        Routers/APs forward multicast, so mDNS evidence attributed to their
        MAC likely belongs to a different device (e.g., Lutron bridge hostname
        on a Ubiquiti router).
        """
        buf = self._evidence_buffer.get(hw_addr)
        if not buf:
            return
        ref_vendor = self._oui_vendors.get(hw_addr)
        for ev in buf:
            if ev.source not in self._FORWARDED_EVIDENCE_SOURCES:
                continue
            # Keep mDNS evidence that matches the device's own vendor
            if ref_vendor and ev.vendor:
                if (ev.vendor == ref_vendor
                        or ref_vendor.lower() in ev.vendor.lower()
                        or ev.vendor.lower() in ref_vendor.lower()):
                    continue
            # Strip everything else
            ev.certainty = 0.0
            ev.vendor = None
            ev.category = None
            ev.platform = None
            ev.platform_version = None
            ev.model = None
            ev.hostname = None

    def _evict_stale_macs(self) -> None:
        """Remove the oldest half of tracked MACs when the cache exceeds the
        threshold.  Keeps memory bounded on long-running deployments with
        large networks."""
        import time as _time
        if len(self._evidence_buffer) <= self._max_tracked_macs:
            return
        # Sort by last-seen time, evict oldest half
        sorted_macs = sorted(self._last_seen, key=self._last_seen.get)
        evict = sorted_macs[:len(sorted_macs) // 2]
        for mac in evict:
            self._evidence_buffer.pop(mac, None)
            self._oui_vendors.pop(mac, None)
            self._oui_device_types.pop(mac, None)
            self._last_seen.pop(mac, None)
            # Remove all (mac, proto) tuples from _lookup_done
            self._lookup_done -= {k for k in self._lookup_done if k[0] == mac}
        # Don't evict _gateway_macs — those are small and important
        logger.info("Evicted %d stale MACs from pipeline cache (%d remaining)",
                     len(evict), len(self._evidence_buffer))

    async def process(self, packet: CapturedPacket) -> None:
        """Process a single captured packet through the full pipeline."""
        # Reject packets with invalid MAC addresses (e.g. TUN interfaces
        # where scapy returns the IP as packet.src instead of a MAC)
        if not _is_valid_mac(packet.hw_addr):
            return

        protocol = packet.protocol

        # Side effects: fire before main processing
        if packet.protocol == "arp" and self._on_arp:
            try:
                await self._on_arp(packet)
            except Exception:
                logger.debug("ARP side effect failed", exc_info=True)

        if packet.protocol == "dhcpv4" and self._on_dhcp:
            try:
                self._on_dhcp(packet)
            except Exception:
                logger.debug("DHCP side effect failed", exc_info=True)

        # Gateway learning from DHCP OFFER/ACK or ICMPv6 RA
        if packet.protocol == "dhcpv4":
            raw_opts = packet.fields.get("raw_options", {})
            msg_type = raw_opts.get("message-type")
            if msg_type in (2, 5) and packet.ip_addr:
                self._gateway_macs.add(packet.hw_addr)
                self._scrub_infra_mdns(packet.hw_addr)
                if self._on_gateway_hint:
                    try:
                        await self._on_gateway_hint(
                            packet.hw_addr, packet.ip_addr, "dhcp_server",
                            packet.interface or "")
                    except Exception:
                        logger.debug("Gateway hint callback failed for %s", packet.hw_addr, exc_info=True)
        elif packet.protocol == "icmpv6":
            if packet.fields.get("icmpv6_type") == "router_advertisement" and packet.ip_addr:
                self._gateway_macs.add(packet.hw_addr)
                self._scrub_infra_mdns(packet.hw_addr)
                if self._on_gateway_hint:
                    try:
                        await self._on_gateway_hint(
                            packet.hw_addr, packet.ip_addr, "auto_gateway",
                            packet.interface or "")
                    except Exception:
                        logger.debug("Gateway RA hint callback failed for %s", packet.hw_addr, exc_info=True)

        # 1. Find and run the registered processor.
        # NEVER return early here — the host upsert and sighting record
        # below must run for every packet so every MAC we see appears in
        # the devices list, even when the processor is missing or crashes.
        evidence_list = []
        processor = self._processor_instances.get(protocol)
        if processor is None:
            logger.debug("No processor for protocol: %s", protocol)
        else:
            try:
                evidence_list = processor.analyze(packet) or []
            except Exception:
                logger.debug("Processor failed for %s", protocol, exc_info=True)

        hw_addr = packet.hw_addr

        # Sanitize packet fields: scapy can produce bytes objects (e.g.
        # mDNS SRV target) that crash JSON serialization downstream.
        def _sanitize_fields(obj):
            if isinstance(obj, bytes):
                return obj.decode("utf-8", errors="replace")
            if isinstance(obj, dict):
                return {k: _sanitize_fields(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_sanitize_fields(v) for v in obj]
            return obj
        packet.fields = _sanitize_fields(packet.fields)

        # Track last-seen for LRU eviction and periodically clean up
        import time as _time
        self._last_seen[hw_addr] = _time.monotonic()
        self._evict_stale_macs()

        # Enrich with MAC OUI lookup (only on first sighting per MAC)
        if hw_addr not in self._evidence_buffer:
            mac_matches = self._lookup.match_mac(hw_addr)
            for match in mac_matches:
                evidence_list.append(self._match_to_evidence(match))
            # Cache OUI vendor and device type for cross-validation
            oui_hit = next((m for m in mac_matches if m.source == "oui"), None)
            if oui_hit and oui_hit.manufacturer:
                self._oui_vendors[hw_addr] = oui_hit.manufacturer
            if oui_hit:
                oui_dtype = oui_hit.device_type or oui_hit.category or ""
                self._oui_device_types[hw_addr] = oui_dtype.lower()
                # Auto-flag infrastructure devices as gateways so their
                # forwarded mDNS traffic doesn't poison their identity.
                if oui_dtype.lower() in (
                    "router", "switch", "gateway", "firewall",
                    "access_point", "ap", "bridge", "mesh_router",
                ):
                    self._gateway_macs.add(hw_addr)
                    self._scrub_infra_mdns(hw_addr)

        # Protocol-specific fingerprint lookups (once per protocol per MAC)
        lookup_key = (hw_addr, protocol)
        if lookup_key not in self._lookup_done:
            self._lookup_done.add(lookup_key)
            try:
                fp_matches = self._fingerprint_lookup(protocol, packet)
                for match in fp_matches:
                    evidence_list.append(self._match_to_evidence(match))
            except Exception:
                logger.debug("Fingerprint lookup failed for %s", protocol, exc_info=True)

        # Cross-validate: mDNS traffic is unreliable for source attribution
        # because routers/gateways/APs forward multicast, rewriting the
        # Ethernet source MAC. When OUI says "Ubiquiti router" but mDNS says
        # "Apple smart speaker" or "Lutron bridge", the mDNS evidence is
        # from a forwarded packet — not this device.
        #
        # For randomized MACs (no OUI), we use the dominant vendor from
        # accumulated evidence (e.g. Apple from _apple-mobdev2._tcp) as the
        # reference vendor to catch conflicting mDNS from other devices.
        oui_vendor = self._oui_vendors.get(hw_addr)
        is_infra = hw_addr in self._gateway_macs

        # Determine the reference vendor: OUI if available, otherwise the
        # dominant vendor from all accumulated + current evidence.
        ref_vendor = oui_vendor
        if not ref_vendor:
            vendor_votes: dict[str, float] = {}
            for ev in list(self._evidence_buffer.get(hw_addr, [])) + evidence_list:
                if ev.vendor:
                    vendor_votes[ev.vendor] = vendor_votes.get(ev.vendor, 0) + ev.certainty
            if vendor_votes:
                ref_vendor = max(vendor_votes, key=vendor_votes.get)

        if ref_vendor:
            for ev in evidence_list:
                if ev.source not in self._FORWARDED_EVIDENCE_SOURCES:
                    continue

                def _vendors_match(a: str | None, b: str) -> bool:
                    if not a:
                        return False
                    return (a == b
                            or b.lower() in a.lower()
                            or a.lower() in b.lower())

                if is_infra:
                    # Gateway/router/AP: ALL mDNS is suspect because these
                    # devices forward/reflect multicast traffic. Only keep
                    # mDNS evidence whose vendor matches the reference vendor
                    # (e.g., Ubiquiti mDNS on a Ubiquiti router is real).
                    if not _vendors_match(ev.vendor, ref_vendor):
                        ev.certainty = 0.0
                        ev.vendor = None
                        ev.category = None
                        ev.platform = None
                        ev.platform_version = None
                        ev.model = None
                        ev.hostname = None
                else:
                    # Non-infrastructure device: suppress mDNS evidence when
                    # vendor conflicts OR when vendor is unset (forwarded
                    # multicast from a different device type).
                    if ev.vendor and not _vendors_match(ev.vendor, ref_vendor):
                        # Explicit vendor conflict — lower certainty,
                        # strip category and hostname.
                        ev.certainty = min(ev.certainty, 0.15)
                        ev.category = None
                        ev.hostname = None
                    elif not ev.vendor and ev.hostname:
                        # mDNS hostname with no vendor attribution is suspect
                        # on a device whose identity is already established.
                        # Only keep it if no better hostname exists.
                        has_better_hostname = any(
                            e.hostname and e.vendor and _vendors_match(e.vendor, ref_vendor)
                            for e in list(self._evidence_buffer.get(hw_addr, [])) + evidence_list
                            if e is not ev
                        )
                        if has_better_hostname:
                            ev.hostname = None

        # 2. Record sighting (non-fatal if it fails) — always record
        # regardless of evidence so protocol coverage stats are accurate
        try:
            sighting = Sighting(
                hw_addr=hw_addr,
                source=protocol,
                payload=packet.fields,
                analysis={"evidence_count": len(evidence_list)},
                certainty=max((e.certainty for e in evidence_list), default=0.0),
                interface=packet.interface,
                network=packet.network,
            )
            await self.store.sightings.record(sighting)
        except Exception:
            logger.debug("Sighting record failed", exc_info=True)

        # 3. ALWAYS upsert host so every MAC we see appears in the devices
        # list, even if no processor generated evidence for this packet.
        #
        # IP assignment rules:
        # - Only trust MAC-IP bindings from ARP or DHCP (layer 2/3 binding)
        # - For forwarded protocols (mDNS, DNS), the source IP belongs to the
        #   original sender, not the forwarding router. Skip IP update for
        #   infrastructure devices receiving these protocols.
        # - Never overwrite a private IP with a public one (NAT traffic)
        raw_ip = packet.ip_addr
        ip_v4 = None
        ip_v6 = None
        if raw_ip and raw_ip != "0.0.0.0":
            if ":" in raw_ip:
                ip_v6 = raw_ip
            else:
                ip_v4 = raw_ip

        # Infrastructure devices (routers/APs) forward multicast — the IP in
        # those packets belongs to the original device, not the router.
        # Only trust ARP/DHCP for IP assignment on infrastructure MACs.
        # Also: once a gateway has an IP, don't overwrite with a different
        # subnet (routers have IPs on multiple VLANs — keep the first one).
        _TRUSTED_IP_PROTOCOLS = ("arp", "dhcpv4", "dhcpv6", "icmpv6")
        if ip_v4 and hw_addr in self._gateway_macs:
            if protocol not in _TRUSTED_IP_PROTOCOLS:
                ip_v4 = None  # don't overwrite gateway IP with forwarded traffic
            else:
                # Even for trusted protocols, don't overwrite an existing
                # gateway IP with a different subnet's IP
                try:
                    existing = await self.store.hosts.find_by_addr(hw_addr)
                    if existing and existing.ip_addr and existing.ip_addr != ip_v4:
                        ip_v4 = None  # keep existing gateway IP
                except Exception:
                    pass

        # Don't overwrite a private IP with a public one — the public IP
        # is likely from NAT'd traffic (e.g., router forwarding DNS responses
        # from Cloudflare 162.x.x.x). Keep the device's real LAN address.
        if ip_v4 and not _is_private_ip(ip_v4):
            try:
                existing = await self.store.hosts.find_by_addr(hw_addr)
                if existing and existing.ip_addr and _is_private_ip(existing.ip_addr):
                    ip_v4 = None  # keep existing private IP
            except Exception:
                logger.debug("IP overwrite check failed for %s", hw_addr, exc_info=True)

        # Guard IPv6 against public overwrite too
        if ip_v6 and not _is_private_ip(ip_v6):
            try:
                existing = await self.store.hosts.find_by_addr(hw_addr)
                if existing and existing.ip_v6 and _is_private_ip(existing.ip_v6):
                    ip_v6 = existing.ip_v6
            except Exception:
                logger.debug("IPv6 overwrite check failed for %s", hw_addr, exc_info=True)

        # MAC randomization detection
        from leetha.fingerprint.mac_intel import is_randomized_mac
        mac_random = is_randomized_mac(hw_addr)
        real_mac = None
        if mac_random and protocol == "dhcpv4":
            # Option 61 may contain the real (non-randomized) MAC.
            # Modern iOS sends the randomized MAC in Option 61 too,
            # so only accept it if it's actually different AND not
            # itself a randomized MAC.
            client_id = packet.fields.get("client_id", "")
            if (len(client_id) == 17 and client_id.count(":") == 5
                    and client_id.lower() != hw_addr.lower()
                    and not is_randomized_mac(client_id)):
                real_mac = client_id

        # Preserve existing disposition so we don't reset "known" back to "new"
        # Auto-tag local device MACs as "self"
        is_new_host = False
        try:
            existing_host = await self.store.hosts.find_by_addr(hw_addr)
            disposition = existing_host.disposition if existing_host else "new"
            is_new_host = existing_host is None
        except Exception:
            disposition = "new"
            is_new_host = True
        if disposition != "self" and self._is_local_mac and self._is_local_mac(hw_addr):
            disposition = "self"

        host = Host(
            hw_addr=hw_addr,
            ip_addr=ip_v4,
            ip_v6=ip_v6,
            last_active=datetime.now(timezone.utc),
            mac_randomized=mac_random,
            real_hw_addr=real_mac,
            disposition=disposition,
        )
        try:
            await self.store.hosts.upsert(host)
        except Exception:
            logger.debug("Host upsert failed for %s", hw_addr, exc_info=True)

        # Notify subscribers immediately when a new device is first discovered
        # so the UI updates without waiting for verdict computation.
        if is_new_host and self._on_new_host:
            try:
                await self._on_new_host(hw_addr, host, packet)
            except Exception:
                logger.debug("New host callback failed for %s", hw_addr, exc_info=True)

        if not evidence_list:
            return

        # 5. Accumulate evidence and compute verdict
        self._evidence_buffer[hw_addr].extend(evidence_list)
        verdict = self.verdict_engine.compute(hw_addr, self._evidence_buffer[hw_addr])
        # Write capped evidence back to prevent unbounded growth
        self._evidence_buffer[hw_addr] = list(verdict.evidence_chain)

        # 6. Evaluate finding rules BEFORE storing verdict
        #    so identity_shift can compare old vs new verdict
        for rule in self._rule_instances:
            try:
                finding = await rule.evaluate(host, verdict, self.store)
                if finding:
                    await self.store.findings.add(finding)
            except Exception:
                logger.debug("Rule %s failed", type(rule).__name__, exc_info=True)

        # 7. Transition disposition from "new" to "known" after rules
        if host.disposition == "new":
            host.disposition = "known"
            try:
                await self.store.hosts.upsert(host)
            except Exception:
                logger.debug("Disposition update failed for %s", hw_addr, exc_info=True)

        # 8. Store verdict AFTER rules (so identity_shift sees the old verdict)
        try:
            await self.store.verdicts.upsert(verdict)
        except Exception:
            logger.debug("Verdict upsert failed for %s", hw_addr, exc_info=True)

        # 9. Resolve device identity
        try:
            await self._resolve_identity(hw_addr, verdict, host)
        except Exception:
            logger.debug("Identity resolution failed for %s", hw_addr, exc_info=True)

        if self._on_verdict:
            try:
                await self._on_verdict(hw_addr, verdict, packet)
            except Exception:
                logger.debug("Verdict callback failed", exc_info=True)

    def _fingerprint_lookup(self, protocol: str, packet: CapturedPacket) -> list:
        """Run protocol-specific fingerprint database lookups.

        These supplement the processor's raw evidence with identifications
        from the 11.5M signature databases (IEEE OUI, Huginn, p0f, etc.).
        """
        data = packet.fields
        hits: list = []

        if protocol == "dhcpv4":
            hits.extend(self._lookup.match_dhcp(
                opt55=data.get("opt55"),
                opt60=data.get("opt60"),
            ))
            # Satori annotated DHCP fingerprints (device attribution)
            opt55 = data.get("opt55")
            if opt55:
                m = self._lookup.match_satori_dhcp(opt55)
                if m:
                    hits.append(m)
            hostname = data.get("hostname")
            if hostname:
                m = self._lookup.match_hostname(hostname)
                if m:
                    hits.append(m)

        elif protocol == "dhcpv6":
            hits.extend(self._lookup.match_dhcpv6(
                oro=data.get("oro"),
                vendor_class=data.get("vendor_class"),
                enterprise_id=data.get("enterprise_id"),
            ))

        elif protocol == "mdns":
            hits.extend(self._lookup.match_mdns_service(
                service_type=data.get("service_type", ""),
                name=data.get("name"),
                packet_data=data,
            ))

        elif protocol == "ssdp":
            m = self._lookup.match_ssdp_server(
                server=data.get("server"),
                st=data.get("st"),
            )
            if m:
                hits.append(m)

        elif protocol == "http_useragent":
            ua = data.get("user_agent", "")
            if ua:
                m = self._lookup.match_user_agent(ua)
                if m:
                    hits.append(m)
                m = self._lookup.match_satori_useragent(ua)
                if m:
                    hits.append(m)

        elif protocol == "tcp_syn":
            ttl = data.get("ttl", 0)
            if ttl:
                m = self._lookup.match_ttl(ttl)
                if m:
                    hits.append(m)
            sig = f"{data.get('ttl', 0)}:{data.get('window_size', 0)}:{data.get('mss', '*')}:{data.get('tcp_options', '')}"
            m = self._lookup.match_tcp_signature(sig)
            if m:
                hits.append(m)

        elif protocol == "dns":
            qname = data.get("query_name", "")
            if qname:
                m = self._lookup.match_dns_query(qname, data.get("query_type", 1))
                if m:
                    hits.append(m)

        elif protocol == "netbios":
            m = self._lookup.match_netbios(
                query_name=data.get("query_name", ""),
                query_type=data.get("query_type", "llmnr"),
                netbios_suffix=data.get("netbios_suffix"),
            )
            if m:
                hits.append(m)

        elif protocol == "service_banner":
            service = data.get("service", "")
            banner = data.get("raw_banner", "")
            if service and banner:
                m = self._lookup.match_banner(protocol=service, banner_text=banner)
                if m:
                    hits.append(m)
                # Satori protocol-specific banner matching
                if service == "ssh":
                    m = self._lookup.match_satori_ssh(banner)
                    if m:
                        hits.append(m)
                elif service in ("http", "https"):
                    server = data.get("server", banner)
                    m = self._lookup.match_satori_web(server)
                    if m:
                        hits.append(m)

        elif protocol == "tls":
            ja3 = data.get("ja3_hash")
            if ja3:
                m = self._lookup.match_ja3(ja3)
                if m:
                    hits.append(m)
            ja4 = data.get("ja4")
            if ja4:
                m = self._lookup.match_ja4(ja4)
                if m:
                    hits.append(m)
            sni = data.get("sni")
            if sni:
                m = self._lookup.lookup_tls_sni(sni)
                if m:
                    hits.append(m)

        return hits

    @staticmethod
    def _match_to_evidence(match) -> Evidence:
        """Convert a FingerprintMatch to an Evidence object."""
        return Evidence(
            source=match.source,
            method=match.match_type,
            certainty=match.confidence,
            category=match.device_type or match.category,
            vendor=match.manufacturer or match.vendor,
            platform=match.os_family,
            platform_version=match.os_version,
            model=match.model,
            raw=match.raw_data,
        )

    async def _resolve_identity(self, hw_addr: str, verdict, host) -> None:
        """Resolve or correlate a device identity for the given MAC."""
        from leetha.fingerprint.mac_intel import (
            is_randomized_mac, compute_correlation_score, CORRELATION_THRESHOLD,
        )

        if not is_randomized_mac(hw_addr):
            identity = await self.store.identities.find_or_create(hw_addr)
        elif host.real_hw_addr:
            identity = await self.store.identities.find_or_create(host.real_hw_addr)
        else:
            signals = self._build_correlation_signals(hw_addr, verdict=verdict)
            identity = await self._correlate_or_create(hw_addr, signals)

        # Update identity metadata from verdict
        if verdict.vendor:
            identity.manufacturer = verdict.vendor
        if verdict.category:
            identity.device_type = verdict.category
        if verdict.platform:
            identity.os_family = verdict.platform
        if verdict.platform_version:
            identity.os_version = verdict.platform_version
        if verdict.hostname:
            identity.hostname = verdict.hostname
        if verdict.certainty:
            identity.confidence = max(identity.confidence, verdict.certainty)
        identity.last_seen = datetime.now(timezone.utc)

        # Keep correlation fingerprint up-to-date so future randomized
        # MACs can match against this identity's signals.
        if is_randomized_mac(hw_addr):
            signals = self._build_correlation_signals(hw_addr, verdict=verdict)
            if signals:
                merged = dict(identity.fingerprint or {})
                merged.update(signals)
                identity.fingerprint = merged

        await self.store.identities.update(identity)

        # Link host to identity if changed
        if identity.id is not None and identity.id != host.identity_id:
            try:
                await self.store._conn.execute(
                    "UPDATE hosts SET identity_id = ? WHERE hw_addr = ?",
                    (identity.id, hw_addr),
                )
                await self.store._conn.commit()
            except Exception:
                logger.debug("Failed to link host %s to identity %s",
                             hw_addr, identity.id, exc_info=True)

    def _build_correlation_signals(self, hw_addr: str, verdict=None) -> dict:
        """Extract correlation signals from accumulated evidence and verdict.

        Signals are used to correlate randomized MACs to a persistent
        device identity across MAC rotations.
        """
        signals: dict[str, str] = {}

        # 1. Pull from the verdict's resolved hostname (most reliable)
        if verdict and verdict.hostname:
            signals["hostname"] = verdict.hostname.lower()

        # 2. Scan evidence for DHCP and mDNS signals
        for ev in self._evidence_buffer.get(hw_addr, []):
            if not signals.get("hostname") and getattr(ev, "hostname", None):
                signals["hostname"] = ev.hostname.lower()
            raw = getattr(ev, "raw", None) or {}
            if not signals.get("dhcp_opt60") and raw.get("opt60"):
                signals["dhcp_opt60"] = str(raw["opt60"]).lower()
            if not signals.get("dhcp_opt55") and raw.get("opt55"):
                signals["dhcp_opt55"] = str(raw["opt55"]).lower()
            # mDNS names: check both "name" and "friendly_name"
            if not signals.get("mdns_name"):
                name = raw.get("friendly_name") or raw.get("name")
                if name and "@" not in str(name):  # skip AirPlay hex@name format
                    signals["mdns_name"] = str(name).lower()
            # DHCP hostname from raw fields
            if not signals.get("hostname") and raw.get("hostname"):
                signals["hostname"] = str(raw["hostname"]).lower()
        return signals

    async def _correlate_or_create(self, hw_addr: str, signals: dict):
        """Find an existing identity matching signals, or create a new one."""
        from leetha.fingerprint.mac_intel import (
            compute_correlation_score, CORRELATION_THRESHOLD,
        )

        if not signals:
            return await self.store.identities.find_or_create(hw_addr)

        all_identities = await self.store.identities.find_all(limit=1000)
        best_score = 0.0
        best_identity = None
        for ident in all_identities:
            score = compute_correlation_score(signals, ident.fingerprint)
            if score > best_score:
                best_score = score
                best_identity = ident

        if best_score >= CORRELATION_THRESHOLD and best_identity is not None:
            return best_identity

        identity = await self.store.identities.find_or_create(hw_addr)
        identity.fingerprint = signals
        return identity

    async def process_batch(self, packets: list[CapturedPacket]) -> None:
        """Process multiple packets. Can be parallelized in future."""
        for packet in packets:
            await self.process(packet)
