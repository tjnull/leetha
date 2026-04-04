"""
LeethaApp — central application orchestrator.

Wires the capture engine, fingerprint engine, evidence aggregation,
device store, and alert engine into a single processing pipeline.
UI frontends (web, live CLI) subscribe to real-time events.

When ``config.worker_count > 1`` the pipeline is sharded:
  CaptureEngine → PacketRouter (MAC hash) → N worker tasks → BatchWriter → DB
When ``config.worker_count == 1`` (default) the original single-loop path
is used for backward compatibility.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor

from leetha.capture.engine import CaptureEngine
from leetha.capture.protocols import ParsedPacket
from leetha.fingerprint.engine import FingerprintEngine
from leetha.fingerprint.evidence import FingerprintMatch, aggregate_evidence
from leetha.pipeline import PacketRouter, BatchWriter, AddObservation, UpsertDevice
from leetha.store.database import Database
from leetha.store.models import Device, DeviceIdentity, Observation
from leetha.alerts.engine import AlertEngine
from leetha.config import get_config
from leetha.probe.scheduler import ProbeScheduler
from leetha.probe.engine import ProbeEngine
from leetha.analysis.dhcp_anomaly import analyze_dhcp_options
from leetha.analysis.spoofing import SpoofingDetector
from leetha.fingerprint.mac_intel import (
    is_randomized_mac,
    build_correlation_fingerprint,
    score_correlation,
    CORRELATION_THRESHOLD,
)

logger = logging.getLogger(__name__)


def _is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is private (RFC 1918 / link-local)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _clean_hostname(raw: str | None) -> str | None:
    """Clean and normalize a hostname from any protocol source.

    Strips mDNS service instance suffixes and trailing hex hashes:
      "Google-Home-Mini-d9d314d5..._googlecast._tcp.local" → "Google-Home-Mini"
      "Home._home-assistant._tcp.local" → "home-assistant"
      "Beccas-Iphone.local" → "Beccas-Iphone"
      "Office speaker._airplay._tcp.local." → "Office speaker"
    """
    if not raw:
        return None
    import re
    name = raw.rstrip(".")

    if "._tcp." in name or "._udp." in name:
        parts = name.split("._")
        instance = parts[0]  # e.g. "Home", "Office speaker", "Google-Home-Mini-..."
        service = parts[1] if len(parts) > 1 else ""  # e.g. "home-assistant", "googlecast"

        # Strip hex hash from instance (Google Cast device IDs)
        instance = re.sub(r'-[0-9a-f]{12,}$', '', instance, flags=re.IGNORECASE)

        # For generic/short instance names, prefer the service name
        # "Home" → "home-assistant", "Office speaker" stays as is
        if len(instance) <= 5 and service and service not in ("tcp", "udp"):
            name = service
        else:
            name = instance

    # Strip .local suffix
    if name.endswith(".local"):
        name = name[:-6]

    name = name.rstrip(".")
    return name if name else None


def _prefer_ip(existing_ip: str | None, new_ip: str | None) -> str | None:
    """Choose the best IP: prefer private over public, newer over older.

    On a network assessment, internal/private IPs are what matter for
    device identification. Public IPs (from DNS responses, transit traffic)
    should never overwrite a known private IP.
    """
    if not new_ip:
        return existing_ip
    if not existing_ip:
        return new_ip

    existing_private = _is_private_ip(existing_ip)
    new_private = _is_private_ip(new_ip)

    # Private always wins over public
    if existing_private and not new_private:
        return existing_ip
    if new_private and not existing_private:
        return new_ip

    # Both same class — prefer the newer one
    return new_ip


def _json_default(obj):
    """Handle non-serializable types in packet data (e.g. bytes from DHCP)."""
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class LeethaApp:
    """Central application that orchestrates all subsystems."""

    def __init__(self, interface: str | None = None,
                 interfaces: list | None = None):
        from leetha.capture.interfaces import InterfaceConfig

        self.config = get_config()
        self.db = Database(self.config.db_path)
        self.fingerprint_engine = FingerprintEngine()
        self.alert_engine = AlertEngine(self.db)
        self.spoofing_detector = SpoofingDetector(self.db)

        # Build interface configs: explicit list > single string > config >
        # saved config > none (user selects via UI)
        if interfaces:
            iface_configs = interfaces
        elif interface:
            iface_configs = [InterfaceConfig(name=interface)]
        elif self.config.interfaces:
            iface_configs = self.config.interfaces
        else:
            # Try saved interface config; if none, start without capture
            from leetha.capture.interfaces import load_interface_config
            iface_configs = load_interface_config(self.config.data_dir)
            if not iface_configs:
                logger.info(
                    "No interfaces configured — select interfaces via "
                    "web UI or use -i to specify"
                )

        # Store resolved interfaces on config for API/UI access
        if iface_configs and not self.config.interfaces:
            self.config.interfaces = iface_configs

        self.capture_engine = CaptureEngine(interfaces=iface_configs)
        self.packet_queue: asyncio.Queue[ParsedPacket] = asyncio.Queue()
        self.event_subscribers: list[asyncio.Queue] = []
        self._running = False
        # Local device MACs — populated at start() for self-identification
        self._local_macs: set[str] = set()
        self._analysis_executor = ThreadPoolExecutor(max_workers=1)
        self.probe_scheduler: ProbeScheduler | None = None

        # Sharded pipeline (only when worker_count > 1)
        self._router: PacketRouter | None = None
        self._writer: BatchWriter | None = None
        self._tasks: list[asyncio.Task] = []

    async def start(self):
        """Initialize DB and start capture."""
        self.config.cache_dir.mkdir(parents=True, exist_ok=True)
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        await self.db.initialize()
        await self.spoofing_detector.initialize()
        loop = asyncio.get_running_loop()
        # Load custom patterns from user data directory
        self.fingerprint_engine.lookup.load_custom_patterns(self.config.data_dir)
        self.capture_engine.start(self.packet_queue, loop)
        self._running = True

        # Detect local MACs from capture interfaces for self-identification
        self._detect_local_macs()
        # Preload Huginn caches synchronously during startup.
        # This blocks for a few seconds but guarantees the caches are
        # available before the first packet arrives.
        self._preload_caches()
        if self.config.probe_enabled:
            probe_engine = ProbeEngine()
            probe_engine.load_plugins()
            self.probe_scheduler = ProbeScheduler(
                db=self.db,
                engine=probe_engine,
                max_concurrent=self.config.probe_max_concurrent,
                cooldown_seconds=self.config.probe_cooldown_seconds,
            )

        # Start periodic analysis loop (stale source checks, etc.)
        self._tasks.append(asyncio.create_task(self._analysis_loop()))

        # Re-evaluate unknown devices 60s after startup (after Huginn loads)
        self._tasks.append(asyncio.create_task(self._reevaluate_unknown_devices()))

        if self.config.worker_count > 1:
            # Sharded pipeline: dispatch → router → N workers → batch writer
            self._router = PacketRouter(num_workers=self.config.worker_count)
            self._writer = BatchWriter(
                db=self.db,
                flush_interval=self.config.db_flush_interval,
                max_batch=self.config.db_batch_size,
            )
            self._tasks.append(asyncio.create_task(self._dispatch_loop()))
            self._tasks.append(asyncio.create_task(self._writer.run()))
            for shard_id in range(self.config.worker_count):
                self._tasks.append(asyncio.create_task(
                    self._worker_loop(shard_id, self._router.workers[shard_id])
                ))
        else:
            # Single-worker fallback (backward compat)
            self._tasks.append(asyncio.create_task(self._process_loop()))

    def _preload_caches(self):
        """Preload large Huginn JSON caches in a background thread.

        This runs outside the event loop so blocking I/O is safe.
        Loads directly into the cache dict, bypassing the _PRELOAD_ONLY guard.
        """
        import json as _json
        import time as _time

        lookup = self.fingerprint_engine.lookup
        cache_dir = lookup._cache_dir
        t0 = _time.monotonic()

        for name in (
            "huginn_combinations", "huginn_dhcpv6",  # small files first
            "huginn_dhcp_vendor", "huginn_dhcpv6_enterprise",
            "huginn_devices", "huginn_dhcp",
            "huginn_mac_vendors",  # largest last
        ):
            if name in lookup._json_cache:
                continue
            path = cache_dir / f"{name}.json"
            if not path.is_file():
                lookup._json_cache[name] = None
                continue
            try:
                t1 = _time.monotonic()
                with open(path, "r", encoding="utf-8") as fh:
                    data = _json.load(fh)
                lookup._json_cache[name] = data
                elapsed = _time.monotonic() - t1
                logger.debug("Preloaded %s (%.1fs)", name, elapsed)
            except Exception as exc:
                logger.warning("Failed to preload %s: %s", name, exc)
                lookup._json_cache[name] = None

        total = _time.monotonic() - t0
        logger.info("Huginn cache preload complete (%.1fs)", total)

    def _detect_local_macs(self):
        """Detect MAC addresses of local capture interfaces for self-tagging."""
        from leetha.capture.interfaces import detect_interfaces

        try:
            detected = detect_interfaces(include_down=True)
            capture_names = set(self.capture_engine.interfaces.keys())
            for iface in detected:
                if iface.name in capture_names and iface.mac:
                    mac = iface.mac.upper()
                    self._local_macs.add(mac)
                    logger.info(
                        "Local device: %s (%s) — will auto-tag as 'self'",
                        mac, iface.name,
                    )
        except Exception as exc:
            logger.warning("Failed to detect local MACs: %s", exc)

    def is_local_device(self, mac: str) -> bool:
        """Check if a MAC address belongs to this machine."""
        return mac.upper() in self._local_macs

    async def stop(self):
        """Stop capture and close DB. Designed for fast shutdown."""
        self._running = False
        self.capture_engine.stop()
        self._analysis_executor.shutdown(wait=False, cancel_futures=True)
        if self.probe_scheduler:
            try:
                self.probe_scheduler.shutdown()
            except Exception:
                pass
        # Cancel all background tasks with timeout
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._tasks, return_exceptions=True),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                pass
        self._tasks.clear()
        # Best-effort flush
        if self._writer:
            try:
                await asyncio.wait_for(self._writer.flush(), timeout=1.0)
            except Exception:
                pass
        try:
            await self.db.close()
        except Exception:
            pass

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to real-time device/alert events. Returns an event queue."""
        q: asyncio.Queue = asyncio.Queue()
        self.event_subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """Unsubscribe from events."""
        if q in self.event_subscribers:
            self.event_subscribers.remove(q)

    async def _process_loop(self):
        """Main loop: dequeue packets, fingerprint, store, alert, notify."""
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                try:
                    # Step 0: Submit DHCP anomaly analysis to background thread
                    if packet.protocol == "dhcpv4" and packet.data.get("raw_options"):
                        future = self._analysis_executor.submit(
                            analyze_dhcp_options,
                            packet.data["raw_options"],
                            packet.src_mac,
                            packet.src_ip or "",
                            self.config.data_dir,
                        )
                        future.add_done_callback(
                            lambda f: self._handle_dhcp_anomalies(f)
                        )

                    # Step 0a: ARP spoofing detection (runs on ALL ARP
                    # packets, even those with no OUI/fingerprint match)
                    spoofing_alerts: list = []
                    if packet.protocol == "arp":
                        spoofing_alerts = await self.spoofing_detector.process_arp(
                            src_mac=packet.src_mac,
                            src_ip=packet.src_ip or "",
                            dst_mac=packet.dst_mac or "ff:ff:ff:ff:ff:ff",
                            dst_ip=packet.dst_ip or "",
                            op=packet.data.get("op", 0),
                            interface=packet.interface or "unknown",
                        )
                        for alert in spoofing_alerts:
                            await self.db.add_alert(alert)

                        # Learn hosts from ARP replies — when we see an ARP
                        # reply, the sender reveals its MAC+IP binding.
                        # This helps discover cross-VLAN devices whose
                        # replies we can observe.
                        arp_op = packet.data.get("op", 0)
                        if arp_op == 2:
                            # ARP reply source = the device that answered
                            arp_src_mac = packet.data.get("src_mac", packet.src_mac)
                            arp_src_ip = packet.data.get("src_ip", packet.src_ip)
                            if arp_src_mac and arp_src_ip:
                                from leetha.store.models import Device
                                arp_device = Device(
                                    mac=arp_src_mac,
                                    ip_v4=arp_src_ip,
                                )
                                await self.db.upsert_device(arp_device)

                    # Step 0b: Auto-learn DHCP server as gateway
                    if packet.protocol == "dhcpv4":
                        raw_opts = packet.data.get("raw_options", {})
                        msg_type = raw_opts.get("message-type")
                        if msg_type in (2, 5) and packet.src_ip:
                            await self.spoofing_detector.learn_gateway(
                                mac=packet.src_mac,
                                ip=packet.src_ip,
                                source="dhcp_server",
                                interface=packet.interface or "unknown",
                            )

                    # Step 0c: Auto-learn router from ICMPv6 RA
                    if packet.protocol == "icmpv6":
                        if packet.data.get("type") == 134 and packet.src_ip:
                            await self.spoofing_detector.learn_gateway(
                                mac=packet.src_mac,
                                ip=packet.src_ip,
                                source="auto_gateway",
                                interface=packet.interface or "unknown",
                            )

                    # Step 0d: DNS behavioral tracking + vendor evidence
                    if packet.protocol == "dns":
                        query_name = packet.data.get("query_name", "")
                        query_type = packet.data.get("query_type", 1)
                        if query_name:
                            # Feed behavioral profiler
                            try:
                                from leetha.rules.behavioral import _shared_tracker
                                _shared_tracker.record(packet.src_mac, query_name, query_type)
                            except Exception:
                                logger.debug("Behavioral tracker record failed", exc_info=True)

                    # Step 0e: DHCP client-ID correlation for randomized MACs
                    if packet.protocol == "dhcpv4":
                        client_id = packet.data.get("client_id")
                        if client_id and client_id != packet.src_mac:
                            # Option 61 contains the REAL hardware MAC
                            from leetha.fingerprint.mac_intel import detect_randomised_mac
                            if detect_randomised_mac(packet.src_mac):
                                # Update device with real MAC correlation
                                existing_dev = await self.db.get_device(packet.src_mac)
                                if existing_dev and not existing_dev.correlated_mac:
                                    existing_dev.correlated_mac = client_id
                                    existing_dev.is_randomized_mac = True
                                    await self.db.upsert_device(existing_dev)

                    # Step 1: Fingerprint the packet
                    matches = self._fingerprint_packet(packet)

                    # Step 1a: Enrich with DNS vendor evidence
                    if packet.protocol == "dns" and packet.data.get("query_name"):
                        try:
                            from leetha.patterns.matching import match_dns_query
                            dns_hit = match_dns_query(
                                packet.data["query_name"],
                                packet.data.get("query_type", 1),
                            )
                            if dns_hit and dns_hit.get("confidence", 0) >= 0.5:
                                matches.append(FingerprintMatch(
                                    source="dns_vendor",
                                    match_type="pattern",
                                    confidence=min(dns_hit["confidence"], 0.60),
                                    manufacturer=dns_hit.get("manufacturer"),
                                    os_family=dns_hit.get("os_family"),
                                    raw_data={"query": packet.data["query_name"],
                                              "service_type": dns_hit.get("note", "")},
                                ))
                        except Exception:
                            logger.debug("DNS vendor enrichment failed", exc_info=True)

                    # Step 1b: Hostname-based vendor inference for randomized MACs
                    hostname = (packet.data.get("hostname")
                                or packet.data.get("fqdn")
                                or packet.data.get("name"))
                    if hostname and not any(m.source == "hostname" for m in matches):
                        hn_match = self.fingerprint_engine.lookup.lookup_hostname(hostname)
                        if hn_match:
                            matches.append(hn_match)

                    if not matches:
                        await self._persist_packet_metadata(packet)
                        if spoofing_alerts:
                            event = {
                                "type": "device_update",
                                "device": None,
                                "alerts": spoofing_alerts,
                                "packet": packet,
                                "matches": [],
                                "evidence": {},
                            }
                            for sub in self.event_subscribers:
                                try:
                                    sub.put_nowait(event)
                                except asyncio.QueueFull:
                                    pass
                        continue

                    # Step 2: Aggregate evidence into a device profile
                    evidence = aggregate_evidence(matches)

                    # Step 3: Build the device model
                    device = self._evidence_to_device(packet, evidence)

                    # Step 3a: Merge with existing device data so we don't
                    # clobber IPs, hostnames, etc. that came from earlier packets.
                    existing = await self.db.get_device(device.mac)
                    if existing is not None:
                        device = self._merge_device(existing, device)

                    # Auto-tag local device MACs as "self"
                    if self.is_local_device(device.mac):
                        device.alert_status = "self"

                    # Step 3b: Identity assignment
                    fingerprint = build_correlation_fingerprint(packet.data, packet.protocol)
                    await self._assign_identity(device, fingerprint)

                    # Step 4: Evaluate alert rules (this also upserts the device)
                    alerts = await self.alert_engine.evaluate(device)
                    alerts.extend(spoofing_alerts)

                    # Step 4a: Identity shift detection (new rules engine)
                    try:
                        from leetha.rules.registry import get_all_rules
                        from leetha.store.models import Host
                        from leetha.evidence.models import Verdict
                        host = Host(
                            hw_addr=device.mac,
                            ip_addr=device.ip_v4,
                            discovered_at=device.first_seen,
                            last_active=device.last_seen,
                            mac_randomized=device.is_randomized_mac,
                            real_hw_addr=device.correlated_mac,
                            disposition=device.alert_status or "new",
                        )
                        verdict = Verdict(
                            hw_addr=device.mac,
                            category=device.device_type,
                            vendor=device.manufacturer,
                            platform=device.os_family,
                            platform_version=device.os_version,
                            hostname=device.hostname,
                            certainty=device.confidence,
                        )
                        for rule_name, rule_cls in get_all_rules().items():
                            try:
                                rule = rule_cls()
                                finding = await rule.evaluate(host, verdict, self.db)
                                if finding:
                                    from leetha.store.models import Alert, AlertType, AlertSeverity
                                    alert = Alert(
                                        device_mac=device.mac,
                                        alert_type=AlertType(finding.rule.value) if finding.rule.value in [e.value for e in AlertType] else AlertType.UNCLASSIFIED,
                                        severity=finding.severity,
                                        message=finding.message,
                                    )
                                    await self.db.add_alert(alert)
                                    alerts.append(alert)
                            except Exception:
                                logger.warning(
                                    "Rule %s evaluation failed for %s",
                                    rule_name, device.mac, exc_info=True,
                                )
                    except Exception:
                        logger.debug("Identity shift / rule evaluation setup failed", exc_info=True)

                    # Step 4b: Fingerprint drift / clone detection
                    oui_vendor = None
                    for m in matches:
                        if getattr(m, "source", None) == "oui":
                            oui_vendor = m.manufacturer
                            break
                    clone_alerts = await self.spoofing_detector.process_device_update(
                        device, oui_vendor=oui_vendor,
                    )
                    for alert in clone_alerts:
                        await self.db.add_alert(alert)
                    alerts.extend(clone_alerts)

                    # Step 5: Record the observation
                    observation = self._packet_to_observation(packet, matches)
                    await self.db.add_observation(observation)

                    # Step 5a: Schedule probe if enabled and packet has port info
                    if self.probe_scheduler and packet.data.get("dst_port"):
                        try:
                            await self.probe_scheduler.schedule(
                                mac=packet.src_mac,
                                ip=packet.src_ip or "",
                                port=packet.data["dst_port"],
                                on_result=self._probe_result_callback,
                            )
                        except Exception as exc:
                            logger.debug("Probe scheduling failed: %s", exc)

                    # Step 6: Notify subscribers
                    event = {
                        "type": "device_update",
                        "device": device,
                        "alerts": alerts,
                        "packet": packet,
                        "matches": matches,
                        "evidence": evidence,
                    }
                    for sub in self.event_subscribers:
                        try:
                            sub.put_nowait(event)
                        except asyncio.QueueFull:
                            pass  # drop event if subscriber is too slow

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Error processing packet: {e}", exc_info=True)
        except asyncio.CancelledError:
            return

    async def _reevaluate_unknown_devices(self):
        """Re-fingerprint devices that were classified before Huginn loaded.

        Runs once, 60 seconds after startup, to fix early classifications
        that missed the Huginn MAC vendor database.
        """
        await asyncio.sleep(60)
        try:
            devices = await self.db.list_devices()
            reclassified = 0
            for dev in devices:
                needs_reeval = (
                    dev.device_type in (None, "unknown", "Unknown")
                    or dev.manufacturer is None
                    or dev.confidence < 50
                )
                if not needs_reeval:
                    continue

                # Re-run OUI + Huginn lookup with now-loaded data
                matches = self.fingerprint_engine.lookup.lookup_mac(dev.mac)

                # Also try hostname lookup if hostname is set
                if dev.hostname:
                    hn_match = self.fingerprint_engine.lookup.lookup_hostname(dev.hostname)
                    if hn_match:
                        matches.append(hn_match)

                if not matches:
                    continue

                evidence = aggregate_evidence(matches)
                new_mfr = evidence.get("manufacturer")
                new_type = evidence.get("device_type")
                new_os = evidence.get("os_family")
                changed = False

                if new_mfr and not dev.manufacturer:
                    dev.manufacturer = new_mfr
                    changed = True
                if new_type and new_type != "Unknown" and dev.device_type in (None, "unknown", "Unknown"):
                    dev.device_type = new_type
                    changed = True
                if new_os and not dev.os_family:
                    dev.os_family = new_os
                    changed = True
                if changed:
                    new_conf = int(evidence.get("confidence", 0) * 100)
                    if new_conf > dev.confidence:
                        dev.confidence = new_conf
                    await self.db.upsert_device(dev)
                    reclassified += 1

            if reclassified:
                logger.info("Re-evaluated %d devices with updated fingerprint data", reclassified)
        except Exception:
            logger.debug("Device re-evaluation failed", exc_info=True)

    async def _analysis_loop(self):
        """Periodic analysis: stale source checks, infra offline, etc. Runs every 30 seconds."""
        try:
            while self._running:
                await asyncio.sleep(30)
                # Check for stale fingerprint sources
                try:
                    await self.alert_engine.check_stale_sources(
                        self.config.data_dir, max_age_days=self.config.sync_interval_days * 4
                    )
                except Exception:
                    logger.debug("Stale source check failed", exc_info=True)
                # Check for infrastructure devices gone offline
                try:
                    await self.alert_engine.check_infra_offline(offline_minutes=5)
                except Exception:
                    logger.debug("Infra offline check failed", exc_info=True)
        except asyncio.CancelledError:
            return

    def _handle_dhcp_anomalies(self, future):
        """Process DHCP anomaly results from background thread."""
        try:
            anomalies = future.result()
            if anomalies:
                loop = asyncio.get_event_loop()
                asyncio.run_coroutine_threadsafe(
                    self.alert_engine.process_dhcp_anomalies(anomalies),
                    loop,
                )
        except Exception:
            logger.debug("DHCP anomaly processing failed", exc_info=True)

    # Sharded pipeline (worker_count > 1)

    async def _dispatch_loop(self):
        """Read from main queue and route packets to worker shards."""
        assert self._router is not None
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                self._router.route(packet)
        except asyncio.CancelledError:
            return

    async def _worker_loop(self, shard_id: int, queue: asyncio.Queue[ParsedPacket]):
        """Process packets from a shard queue, sending writes via BatchWriter."""
        assert self._writer is not None
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                try:
                    # DHCP anomaly analysis (fire-and-forget)
                    if packet.protocol == "dhcpv4" and packet.data.get("raw_options"):
                        future = self._analysis_executor.submit(
                            analyze_dhcp_options,
                            packet.data["raw_options"],
                            packet.src_mac,
                            packet.src_ip or "",
                            self.config.data_dir,
                        )
                        future.add_done_callback(
                            lambda f: self._handle_dhcp_anomalies(f)
                        )

                    # ARP spoofing detection (before fingerprint gate)
                    spoofing_alerts: list = []
                    if packet.protocol == "arp":
                        spoofing_alerts = await self.spoofing_detector.process_arp(
                            src_mac=packet.src_mac,
                            src_ip=packet.src_ip or "",
                            dst_mac=packet.dst_mac or "ff:ff:ff:ff:ff:ff",
                            dst_ip=packet.dst_ip or "",
                            op=packet.data.get("op", 0),
                            interface=packet.interface or "unknown",
                        )
                        for alert in spoofing_alerts:
                            await self.db.add_alert(alert)

                    # Auto-learn DHCP server as gateway
                    if packet.protocol == "dhcpv4":
                        raw_opts = packet.data.get("raw_options", {})
                        msg_type = raw_opts.get("message-type")
                        if msg_type in (2, 5) and packet.src_ip:
                            await self.spoofing_detector.learn_gateway(
                                mac=packet.src_mac,
                                ip=packet.src_ip,
                                source="dhcp_server",
                                interface=packet.interface or "unknown",
                            )

                    # Auto-learn router from ICMPv6 RA
                    if packet.protocol == "icmpv6":
                        if packet.data.get("type") == 134 and packet.src_ip:
                            await self.spoofing_detector.learn_gateway(
                                mac=packet.src_mac,
                                ip=packet.src_ip,
                                source="auto_gateway",
                                interface=packet.interface or "unknown",
                            )

                    matches = self._fingerprint_packet(packet)
                    if not matches:
                        await self._persist_packet_metadata(packet)
                        if spoofing_alerts:
                            event = {
                                "type": "device_update",
                                "device": None,
                                "alerts": spoofing_alerts,
                                "packet": packet,
                                "matches": [],
                                "evidence": {},
                            }
                            for sub in self.event_subscribers:
                                try:
                                    sub.put_nowait(event)
                                except asyncio.QueueFull:
                                    pass
                        continue

                    evidence = aggregate_evidence(matches)
                    device = self._evidence_to_device(packet, evidence)

                    existing = await self.db.get_device(device.mac)
                    if existing is not None:
                        device = self._merge_device(existing, device)

                    # Auto-tag local device MACs as "self"
                    if self.is_local_device(device.mac):
                        device.alert_status = "self"

                    fingerprint = build_correlation_fingerprint(packet.data, packet.protocol)
                    await self._assign_identity(device, fingerprint)

                    # evaluate() upserts the device and persists alerts directly
                    alerts = await self.alert_engine.evaluate(device)
                    alerts.extend(spoofing_alerts)

                    # Fingerprint drift / clone detection
                    oui_vendor = None
                    for m in matches:
                        if getattr(m, "source", None) == "oui":
                            oui_vendor = m.manufacturer
                            break
                    clone_alerts = await self.spoofing_detector.process_device_update(
                        device, oui_vendor=oui_vendor,
                    )
                    for alert in clone_alerts:
                        await self.db.add_alert(alert)
                    alerts.extend(clone_alerts)

                    observation = self._packet_to_observation(packet, matches)

                    # Batch observation writes through BatchWriter
                    self._writer.enqueue(AddObservation(observation))

                    # Probe scheduling
                    if self.probe_scheduler and packet.data.get("dst_port"):
                        try:
                            await self.probe_scheduler.schedule(
                                mac=packet.src_mac,
                                ip=packet.src_ip or "",
                                port=packet.data["dst_port"],
                                on_result=self._probe_result_callback,
                            )
                        except Exception as exc:
                            logger.debug("Probe scheduling failed: %s", exc)

                    # Notify subscribers
                    event = {
                        "type": "device_update",
                        "device": device,
                        "alerts": alerts,
                        "packet": packet,
                        "matches": matches,
                        "evidence": evidence,
                    }
                    for sub in self.event_subscribers:
                        try:
                            sub.put_nowait(event)
                        except asyncio.QueueFull:
                            pass

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Worker {shard_id} error: {e}", exc_info=True)
        except asyncio.CancelledError:
            return

    async def _probe_result_callback(self, mac: str, match):
        """Feed probe results back into device fingerprinting."""
        from leetha.fingerprint.evidence import FingerprintMatch
        if not isinstance(match, FingerprintMatch):
            return
        from leetha.capture.protocols import ParsedPacket
        from datetime import datetime
        device = self._evidence_to_device(
            ParsedPacket(protocol="probe", src_mac=mac, src_ip="",
                         timestamp=datetime.now()),
            {"matches": [match], "device_type": match.device_type,
             "manufacturer": match.manufacturer, "os_family": match.os_family,
             "os_version": match.os_version,
             "confidence": int(match.confidence * 100)},
        )
        if device:
            await self.db.upsert_device(device)

    def _fingerprint_packet(self, packet: ParsedPacket) -> list[FingerprintMatch]:
        """Route packet to appropriate fingerprint method.

        Each protocol parser may include extra fields in packet.data that the
        fingerprint engine method does not accept (e.g. ``window_scale`` for
        TCP SYN, ``message_type`` for DHCPv4).  We extract only the parameters
        each method expects rather than spreading the full data dict.
        """
        engine = self.fingerprint_engine
        data = packet.data

        if packet.protocol == "tcp_syn":
            return engine.process_tcp_syn(
                src_mac=packet.src_mac,
                src_ip=packet.src_ip,
                ttl=data["ttl"],
                window_size=data["window_size"],
                mss=data.get("mss"),
                tcp_options=data.get("tcp_options", ""),
            )
        elif packet.protocol == "dhcpv4":
            return engine.process_dhcpv4(
                client_mac=packet.src_mac,
                opt55=data.get("opt55"),
                opt60=data.get("opt60"),
                hostname=data.get("hostname"),
                client_id=data.get("client_id"),
            )
        elif packet.protocol == "dhcpv6":
            return engine.process_dhcpv6(
                client_mac=packet.src_mac,
                oro=data.get("oro"),
                duid=data.get("duid"),
                vendor_class=data.get("vendor_class"),
                enterprise_id=data.get("enterprise_id"),
                fqdn=data.get("fqdn"),
            )
        elif packet.protocol == "mdns":
            return engine.process_mdns(
                src_mac=packet.src_mac,
                src_ip=packet.src_ip,
                service_type=data["service_type"],
                name=data.get("name"),
                packet_data=data,
            )
        elif packet.protocol == "ssdp":
            return engine.process_ssdp(
                src_mac=packet.src_mac, src_ip=packet.src_ip,
                server=data.get("server"), st=data.get("st"),
            )
        elif packet.protocol == "netbios":
            return engine.process_netbios(
                src_mac=packet.src_mac, src_ip=packet.src_ip,
                query_name=data["query_name"], query_type=data.get("query_type", "llmnr"),
                netbios_suffix=data.get("netbios_suffix"),
            )
        elif packet.protocol == "tls":
            return engine.process_tls(
                src_mac=packet.src_mac,
                src_ip=packet.src_ip,
                ja3_hash=data["ja3_hash"],
                ja4=data["ja4"],
                sni=data.get("sni"),
            )
        elif packet.protocol == "arp":
            return engine.process_arp(
                src_mac=packet.src_mac,
                src_ip=packet.src_ip,
            )
        elif packet.protocol == "dns":
            return engine.process_dns(
                src_mac=packet.src_mac, src_ip=packet.src_ip, **packet.data
            )
        elif packet.protocol == "icmpv6":
            return engine.process_icmpv6(
                src_mac=packet.src_mac, src_ip=packet.src_ip, **packet.data
            )
        elif packet.protocol == "ip_observed":
            return engine.process_ip_observed(
                src_mac=packet.src_mac,
                src_ip=packet.src_ip,
                ttl=data.get("ttl", 0),
                ttl_os_hint=data.get("ttl_os_hint", ""),
            )
        elif packet.protocol == "dns_answer":
            return engine.process_dns_answer(
                query_name=data.get("query_name", ""),
                hostname=data.get("hostname"),
            )
        elif packet.protocol == "http_useragent":
            return engine.process_http_useragent(
                src_mac=packet.src_mac,
                user_agent=data.get("user_agent", ""),
                host=data.get("host"),
            )
        elif packet.protocol == "lldp":
            return engine.process_lldp(
                src_mac=packet.src_mac,
                system_name=data.get("system_name", ""),
                system_description=data.get("system_description", ""),
                capabilities=data.get("capabilities", []),
                management_ip=data.get("management_ip"),
            )
        elif packet.protocol == "cdp":
            return engine.process_cdp(
                src_mac=packet.src_mac,
                device_id=data.get("device_id", ""),
                platform=data.get("platform", ""),
                software_version=data.get("software_version", ""),
                capabilities=data.get("capabilities", []),
                management_ip=data.get("management_ip"),
            )
        elif packet.protocol == "stp":
            return engine.process_stp(
                src_mac=packet.src_mac,
                bridge_priority=data.get("bridge_priority", 32768),
                bridge_mac=data.get("bridge_mac", ""),
                is_root=data.get("is_root", False),
            )
        elif packet.protocol == "snmp":
            return engine.process_snmp(
                src_mac=packet.src_mac,
                version=data.get("version", ""),
                community=data.get("community", ""),
                pdu_type=data.get("pdu_type", ""),
                sys_descr=data.get("sys_descr", ""),
                sys_name=data.get("sys_name", ""),
                sys_object_id=data.get("sys_object_id", ""),
            )
        elif packet.protocol == "service_banner":
            return engine.process_service_banner(
                src_mac=packet.src_mac,
                service=data.get("service", ""),
                software=data.get("software"),
                version=data.get("version"),
                server_port=data.get("server_port"),
            )
        elif packet.protocol == "ws_discovery":
            return engine.process_ws_discovery(
                src_mac=packet.src_mac,
                device_types=data.get("device_types"),
                manufacturer=data.get("manufacturer"),
                model=data.get("model"),
                firmware=data.get("firmware"),
            )
        elif packet.protocol == "ntp":
            return engine.process_ntp(
                src_mac=packet.src_mac,
                mode=data.get("mode", ""),
                stratum=data.get("stratum", 0),
                reference_id=data.get("reference_id", ""),
            )
        elif packet.protocol in ("modbus", "bacnet", "coap", "mqtt", "enip"):
            return engine.process_iot_scada(
                src_mac=packet.src_mac,
                protocol=packet.protocol,
                **data,
            )
        return []

    async def _persist_packet_metadata(self, packet: ParsedPacket) -> None:
        """Save hostname / IP from a packet even when no fingerprint matched.

        Many protocols (NetBIOS, LLMNR, mDNS, DHCP) carry the device hostname
        but may not match any fingerprint pattern.  Without this, the hostname
        is silently discarded on the ``if not matches: continue`` path.

        For dns_answer PTR records the hostname belongs to the *queried* device
        (identified by answer_ip), not the DNS server that sent the response.

        Reads are direct (safe under WAL); writes go through the BatchWriter
        to avoid contention with other workers.
        """
        assert self._writer is not None
        data = packet.data

        if packet.protocol == "dns_answer":
            # PTR records: associate hostname with the device at answer_ip
            answer_ip = data.get("answer_ip")
            ptr_hostname = data.get("hostname")
            if answer_ip and ptr_hostname:
                existing = await self.db.get_device_by_ip(answer_ip)
                ptr_clean = _clean_hostname(ptr_hostname)
                if existing and ptr_clean and (not existing.hostname or len(ptr_clean) < len(existing.hostname)):
                    existing.hostname = ptr_clean
                    self._writer.enqueue(UpsertDevice(existing))
            return

        hostname = (
            data.get("hostname")
            or data.get("fqdn")
            or data.get("friendly_name")
            or data.get("name")
        )
        # query_name is a hostname for NetBIOS/LLMNR, but NOT for DNS queries
        if not hostname and packet.protocol != "dns":
            hostname = data.get("query_name")

        hostname = _clean_hostname(hostname)

        # Extract valid IPs from the packet
        src_ip = packet.src_ip
        ip_v4 = src_ip if (src_ip and "." in src_ip and src_ip != "0.0.0.0") else None
        ip_v6 = src_ip if (src_ip and ":" in src_ip and src_ip != "::") else None

        if not hostname and not ip_v4 and not ip_v6:
            return

        existing = await self.db.get_device(packet.src_mac)
        if existing is not None:
            changed = False
            # Update hostname — prefer a cleaner/shorter name over a longer one
            if hostname and (not existing.hostname or len(hostname) < len(existing.hostname)):
                existing.hostname = hostname
                changed = True
            # Use IP preference: private always wins over public
            better_v4 = _prefer_ip(existing.ip_v4, ip_v4)
            if better_v4 != existing.ip_v4:
                existing.ip_v4 = better_v4
                changed = True
            if ip_v6 and not existing.ip_v6:
                existing.ip_v6 = ip_v6
                changed = True
            if changed:
                self._writer.enqueue(UpsertDevice(existing))
        else:
            # Device not yet in DB — create a minimal record so the IP
            # is captured even without a fingerprint match
            from leetha.fingerprint.mac_intel import is_randomized_mac
            device = Device(
                mac=packet.src_mac,
                ip_v4=ip_v4,
                ip_v6=ip_v6,
                hostname=hostname,
                is_randomized_mac=is_randomized_mac(packet.src_mac),
            )
            if self.is_local_device(device.mac):
                device.alert_status = "self"
            self._writer.enqueue(UpsertDevice(device))

    def _evidence_to_device(self, packet: ParsedPacket, evidence: dict) -> Device:
        """Convert aggregated evidence to a Device model."""
        mac = packet.src_mac
        hostname = (
            packet.data.get("hostname")
            or packet.data.get("fqdn")
            or packet.data.get("friendly_name")  # mDNS TXT fn= field
            or packet.data.get("name")
        )
        # query_name is a hostname for NetBIOS/LLMNR, but NOT for DNS queries
        if not hostname and packet.protocol != "dns":
            hostname = packet.data.get("query_name")

        hostname = _clean_hostname(hostname)

        # Only store real IPs — 0.0.0.0 and :: are meaningless placeholders
        src_ip = packet.src_ip
        ip_v4 = src_ip if ("." in src_ip and src_ip != "0.0.0.0") else None
        ip_v6 = src_ip if (":" in src_ip and src_ip != "::") else None

        # Use model hint for more specific device identification when available
        # e.g. "Google Home" instead of "smart_speaker", "Chromecast" instead of "media_player"
        # BUT only when the OS hasn't been confirmed as a general-purpose OS by
        # TCP/p0f/banner — a Linux box with a Google MAC is NOT a Google Home.
        device_type = evidence.get("device_type")
        model = evidence.get("model")
        os_confirmed = evidence.get("os_confirmed", False)

        if model and not os_confirmed and device_type in (
            "smart_speaker", "media_player", "smart_tv", "phone",
            "router", "switch", "access_point", "iot", "thermostat",
            "ip_camera", "doorbell", "smart_display", "game_console",
        ):
            device_type = model

        return Device(
            mac=mac,
            ip_v4=ip_v4,
            ip_v6=ip_v6,
            manufacturer=evidence.get("manufacturer"),
            device_type=device_type,
            os_family=evidence.get("os_family"),
            os_version=evidence.get("os_version"),
            hostname=hostname,
            confidence=int(evidence.get("confidence", 0) * 100),
            raw_evidence=evidence.get("evidence", []),
            is_randomized_mac=is_randomized_mac(mac),
        )

    @staticmethod
    def _merge_device(existing: Device, new: Device) -> Device:
        """Merge new packet-derived device data with existing DB record.

        When new evidence has HIGHER confidence, its classifications win.
        This ensures that a device initially classified from weak evidence
        (ARP at 10%) gets properly reclassified when strong evidence arrives
        (mDNS at 90%).
        """
        # Prefer private IPs over public; within same class prefer newer
        new.ip_v4 = _prefer_ip(existing.ip_v4, new.ip_v4)
        new.ip_v6 = new.ip_v6 or existing.ip_v6

        # For classification fields: if new evidence is stronger, use it.
        # If new is weaker or empty, keep existing.
        stronger = new.confidence >= existing.confidence

        if stronger and new.manufacturer:
            pass  # keep new.manufacturer
        else:
            new.manufacturer = new.manufacturer or existing.manufacturer

        if stronger and new.device_type and new.device_type != "Unknown":
            pass  # keep new.device_type
        elif new.device_type == "Unknown" and existing.device_type:
            # New evidence says "Unknown" — this often means a multi-product
            # vendor filter dropped an unreliable OUI type.  Keep existing
            # ONLY if it came from protocol-level evidence (mDNS, SSDP, etc.),
            # not from a previous OUI/Huginn guess.
            # For simplicity: keep existing if confidence is high (>70%)
            # meaning protocol evidence confirmed it.
            if existing.confidence >= 70:
                new.device_type = existing.device_type
            else:
                new.device_type = "Unknown"
        else:
            new.device_type = (
                new.device_type if new.device_type and new.device_type != "Unknown"
                else existing.device_type
            )

        if stronger and new.os_family:
            pass  # keep new.os_family
        else:
            new.os_family = new.os_family or existing.os_family

        new.os_version = new.os_version or existing.os_version

        # Hostname: prefer shorter (cleaner) name or newer non-empty name
        if new.hostname and existing.hostname:
            new.hostname = new.hostname if len(new.hostname) <= len(existing.hostname) else existing.hostname
        else:
            new.hostname = new.hostname or existing.hostname

        new.confidence = max(new.confidence, existing.confidence)
        new.alert_status = existing.alert_status  # preserve admin status
        new.correlated_mac = new.correlated_mac or existing.correlated_mac
        new.identity_id = new.identity_id or existing.identity_id

        # Preserve manual override from existing device
        new.manual_override = new.manual_override or existing.manual_override

        # Apply manual override — overrides always win over automated fingerprinting
        if new.manual_override:
            for field in ("device_type", "manufacturer", "os_family", "os_version"):
                val = new.manual_override.get(field)
                if val is not None:
                    setattr(new, field, val)

        return new

    async def _assign_identity(self, device: Device, fingerprint: dict) -> None:
        """Find or create an identity for this device.

        For randomized MACs: score against existing identities and join if above
        threshold. For real MACs: find existing identity or create one.
        """
        # Check if device already has an identity
        if device.identity_id is not None:
            # Update identity with latest data
            identity = await self.db.get_identity(device.identity_id)
            if identity:
                self._update_identity_from_device(identity, device, fingerprint)
                await self.db.upsert_identity(identity)
            return

        if device.is_randomized_mac:
            # Try to correlate with existing identities
            identities = await self.db.get_all_identities_with_fingerprints()
            best_identity: DeviceIdentity | None = None
            best_score = 0.0

            for identity in identities:
                s = score_correlation(fingerprint, identity.correlation_fingerprint)
                if s > best_score:
                    best_score = s
                    best_identity = identity

            if best_identity and best_score >= CORRELATION_THRESHOLD:
                # Join existing identity
                device.identity_id = best_identity.id
                device.correlated_mac = best_identity.primary_mac
                self._update_identity_from_device(best_identity, device, fingerprint)
                await self.db.upsert_identity(best_identity)
                logger.info(
                    f"Correlated {device.mac} -> identity {best_identity.id} "
                    f"(primary={best_identity.primary_mac}, score={best_score:.2f})"
                )
                return

        # No correlation found (or real MAC) — create new identity
        identity = DeviceIdentity(
            primary_mac=device.mac,
            manufacturer=device.manufacturer,
            device_type=device.device_type,
            os_family=device.os_family,
            os_version=device.os_version,
            hostname=device.hostname,
            confidence=device.confidence,
            correlation_fingerprint=fingerprint,
        )
        identity_id = await self.db.upsert_identity(identity)
        device.identity_id = identity_id

    @staticmethod
    def _update_identity_from_device(
        identity: DeviceIdentity, device: Device, fingerprint: dict
    ) -> None:
        """Merge device data into identity, keeping best values."""
        identity.manufacturer = device.manufacturer or identity.manufacturer
        if device.device_type and device.device_type != "Unknown":
            identity.device_type = device.device_type
        identity.os_family = device.os_family or identity.os_family
        identity.os_version = device.os_version or identity.os_version
        identity.hostname = _clean_hostname(device.hostname) or _clean_hostname(identity.hostname)
        identity.confidence = max(device.confidence, identity.confidence)
        identity.last_seen = device.last_seen

        # Prefer real MAC as primary
        if not is_randomized_mac(device.mac):
            identity.primary_mac = device.mac

        # Accumulate fingerprint signals
        for key, value in fingerprint.items():
            if value and key not in identity.correlation_fingerprint:
                identity.correlation_fingerprint[key] = value

    def _packet_to_observation(
        self, packet: ParsedPacket, matches: list[FingerprintMatch]
    ) -> Observation:
        """Convert packet + matches to an Observation model."""
        return Observation(
            device_mac=packet.src_mac,
            source_type=packet.protocol,
            raw_data=json.dumps(packet.data, default=_json_default),
            match_result=json.dumps([
                {"source": m.source, "confidence": m.confidence}
                for m in matches
            ]),
            confidence=int(max((m.confidence for m in matches), default=0) * 100),
            interface=packet.interface,
            network=packet.network,
        )
