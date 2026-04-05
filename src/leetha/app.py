"""
LeethaApp — central application orchestrator.

Wires the capture engine, fingerprint engine, evidence aggregation,
device store, and alert engine into a single processing pipeline.
UI frontends (web, live CLI) subscribe to real-time events.

When ``config.worker_count > 1`` the pipeline is sharded:
  CaptureEngine → PacketRouter (MAC hash) → N worker tasks → Pipeline → Store
When ``config.worker_count == 1`` (default) the original single-loop path
is used for backward compatibility.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from leetha.capture.engine import CaptureEngine
from leetha.capture.protocols import ParsedPacket
from leetha.core.pipeline import Pipeline
from leetha.fingerprint.engine import FingerprintEngine
from leetha.pipeline import PacketRouter
from leetha.store.database import Database
from leetha.store.store import Store
from leetha.store.models import Device, DeviceIdentity
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


class LeethaApp:
    """Central application that orchestrates all subsystems."""

    def __init__(self, interface: str | None = None,
                 interfaces: list | None = None):
        from leetha.capture.interfaces import InterfaceConfig

        self.config = get_config()
        self.db = Database(self.config.db_path)
        self.store = Store(self.config.db_path)
        self.pipeline: Pipeline | None = None  # initialized in start()
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
        self._tasks: list[asyncio.Task] = []

    async def start(self):
        """Initialize DB, pipeline, and pattern caches.

        Capture does NOT start here — call :meth:`start_capture` after the
        user selects an interface (via CLI ``-i`` flag or the web UI).
        This allows leetha to run the dashboard and DB without root.
        """
        from leetha.platform import fix_ownership_recursive
        self.config.cache_dir.mkdir(parents=True, exist_ok=True)
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        await self.db.initialize()
        await self.store.initialize()
        # When running under sudo, fix ownership so the real user
        # can access the DB and data files without sudo next time.
        fix_ownership_recursive(self.config.cache_dir)
        fix_ownership_recursive(self.config.data_dir)
        await self.spoofing_detector.initialize()

        # Re-import admin token if the file exists but the DB has no tokens
        # (happens when DB is deleted/recreated but token file persists).
        await self._restore_admin_token()

        # Trigger processor auto-discovery so Pipeline sees all protocols
        import leetha.processors  # noqa: F401

        self.pipeline = Pipeline(
            store=self.store,
            on_verdict=self._on_verdict_event,
            on_arp=self._on_arp_packet,
            on_dhcp=self._on_dhcp_packet,
            on_gateway_hint=self._on_gateway_hint,
        )

        self._running = True

        # Preload smaller Huginn caches in a background thread so the
        # event loop stays responsive.  The massive huginn_mac_vendors
        # file (667 MB) is NOT preloaded — it's accessed on-demand via
        # the OUI index which is already built at import time.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._preload_caches)

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

        # If interfaces were provided at construction time, start capture
        # immediately (CLI mode with -i flag).
        if self.config.interfaces:
            await self.start_capture()

    async def start_capture(self, interfaces=None):
        """Begin packet capture on the configured (or provided) interfaces.

        Can be called at any time — on startup if ``-i`` was given, or later
        when the user selects an interface via the web UI or console.
        Requires capture privileges (root, sudo, or CAP_NET_RAW).
        """
        from leetha.platform import has_capture_privilege
        if not has_capture_privilege():
            logger.debug(
                "Cannot start capture — insufficient privileges."
            )
            return False

        if interfaces:
            from leetha.capture.interfaces import InterfaceConfig
            if isinstance(interfaces[0], str):
                interfaces = [InterfaceConfig(name=n) for n in interfaces]
            self.config.interfaces = interfaces
            self.capture_engine = CaptureEngine(interfaces=interfaces)

        if not self.config.interfaces:
            logger.warning("No interfaces configured — cannot start capture")
            return False

        loop = asyncio.get_running_loop()
        self.capture_engine.start(self.packet_queue, loop)

        # Detect local MACs from capture interfaces for self-identification
        self._detect_local_macs()

        # Re-evaluate unknown devices 60s after capture starts
        self._tasks.append(asyncio.create_task(self._reevaluate_unknown_devices()))

        if self.config.worker_count > 1:
            self._router = PacketRouter(num_workers=self.config.worker_count)
            self._tasks.append(asyncio.create_task(self._dispatch_loop()))
            for shard_id in range(self.config.worker_count):
                self._tasks.append(asyncio.create_task(
                    self._worker_loop(shard_id, self._router.workers[shard_id])
                ))
        else:
            self._tasks.append(asyncio.create_task(self._process_loop()))

        logger.info("Capture started on %s",
                     ", ".join(i.name for i in self.config.interfaces))
        return True

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
            # NOTE: huginn_mac_vendors (667 MB) is NOT preloaded.
            # The OUI index (75K prefixes) handles MAC lookups.
            # The full file is loaded on-demand only when needed.
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
        try:
            await self.store.close()
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
        """Single-worker packet processing loop using new Pipeline."""
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                try:
                    await self.pipeline.process(packet)
                except Exception:
                    logger.debug("Pipeline processing failed", exc_info=True)
        except asyncio.CancelledError:
            return

    async def _reevaluate_unknown_devices(self):
        """Re-evaluate devices with low confidence after fingerprint databases load."""
        await asyncio.sleep(60)
        if not self.pipeline:
            return
        try:
            verdicts = await self.store.verdicts.find_all(limit=1000)
            low_confidence = [v for v in verdicts if v.certainty < 50]
            for v in low_confidence:
                # Recompute with existing evidence
                new_verdict = self.pipeline.verdict_engine.compute(
                    v.hw_addr, v.evidence_chain)
                if new_verdict.certainty != v.certainty:
                    await self.store.verdicts.upsert(new_verdict)
                    logger.info("Re-evaluated %s: %d%% -> %d%%",
                               v.hw_addr, v.certainty, new_verdict.certainty)
        except Exception:
            logger.debug("Re-evaluation failed", exc_info=True)

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

    async def _worker_loop(self, shard_id: int, queue):
        """Process packets from a shard queue using new Pipeline."""
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                try:
                    await self.pipeline.process(packet)
                except Exception:
                    logger.debug("Worker %d pipeline failed", shard_id, exc_info=True)
        except asyncio.CancelledError:
            return

    async def _restore_admin_token(self):
        """Re-import admin token from file if DB has none (e.g., after DB reset)."""
        try:
            count = await self.db.count_active_admin_tokens()
            if count > 0:
                return  # DB already has tokens
            from leetha.auth.tokens import load_admin_token, hash_token
            raw = load_admin_token()
            if not raw:
                return  # No token file either
            await self.db.create_auth_token(
                hash_token(raw), role="admin", label="restored-from-file")
            logger.info("Restored admin token from ~/.leetha/admin-token")
        except Exception:
            logger.debug("Admin token restore failed", exc_info=True)

    # -- Pipeline side-effect callbacks ----------------------------------

    async def _on_verdict_event(self, hw_addr, verdict, packet):
        """Emit WebSocket event after verdict computed."""
        # Include packet info for the console live stream
        packet_info = None
        if packet:
            packet_info = {
                "protocol": packet.protocol,
                "src_mac": packet.hw_addr,
                "src_ip": packet.ip_addr,
                "dst_ip": getattr(packet, "target_ip", None),
                "fields": packet.fields,
                "interface": packet.interface,
            }
        event = {
            "type": "device_update",
            "mac": hw_addr,
            "verdict": verdict.to_dict() if hasattr(verdict, "to_dict") else {},
            "packet": packet_info,
        }
        for sub in self.event_subscribers:
            try:
                sub.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def _on_arp_packet(self, packet):
        """Run spoofing detection on ARP packets."""
        try:
            alerts = await self.spoofing_detector.process_arp(
                src_mac=packet.hw_addr,
                src_ip=packet.ip_addr or "",
                dst_mac=packet.target_hw or "ff:ff:ff:ff:ff:ff",
                dst_ip=packet.target_ip or "",
                op=packet.fields.get("op", 0),
                interface=packet.interface or "unknown",
            )
            for alert in alerts:
                await self.db.add_alert(alert)
        except Exception:
            logger.debug("ARP spoofing check failed", exc_info=True)

    def _on_dhcp_packet(self, packet):
        """Submit DHCP options for anomaly analysis."""
        raw_opts = packet.fields.get("raw_options")
        if raw_opts:
            future = self._analysis_executor.submit(
                analyze_dhcp_options,
                raw_opts,
                packet.hw_addr,
                packet.ip_addr or "",
                self.config.data_dir,
            )
            future.add_done_callback(lambda f: self._handle_dhcp_anomalies(f))

    async def _on_gateway_hint(self, mac, ip, source, interface):
        """Auto-learn gateway from DHCP/RA."""
        await self.spoofing_detector.learn_gateway(
            mac=mac, ip=ip, source=source, interface=interface)

    async def _probe_result_callback(self, mac, match):
        """Feed probe results into the pipeline as Evidence."""
        if not self.pipeline:
            return
        from leetha.evidence.models import Evidence
        evidence = Evidence(
            source="probe",
            method="active",
            certainty=0.85,
            vendor=getattr(match, 'manufacturer', None),
            platform=getattr(match, 'os_family', None),
            platform_version=getattr(match, 'os_version', None),
            model=getattr(match, 'model', None),
            category=getattr(match, 'device_type', None),
            raw={"probe_result": str(match)},
        )
        self.pipeline._evidence_buffer[mac].append(evidence)
        verdict = self.pipeline.verdict_engine.compute(
            mac, self.pipeline._evidence_buffer[mac])
        await self.store.verdicts.upsert(verdict)

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

