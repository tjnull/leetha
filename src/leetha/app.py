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
from leetha.pipeline import PacketRouter
from leetha.store.database import Database
from leetha.store.store import Store
from leetha.alerts.engine import AlertEngine
from leetha.config import get_config
from leetha.probe.scheduler import ProbeScheduler
from leetha.probe.engine import ProbeEngine
from leetha.analysis.dhcp_anomaly import analyze_dhcp_options
from leetha.analysis.spoofing import SpoofingDetector

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
        import queue as _queue_mod
        self.packet_queue: _queue_mod.Queue = _queue_mod.Queue()
        self.event_subscribers: list[asyncio.Queue] = []
        try:
            from leetha.notifications import NotificationDispatcher
            self._notifier = NotificationDispatcher(
                urls=self.config.notification_urls,
                min_severity=self.config.notification_min_severity,
            )
        except ImportError:
            self._notifier = None
            logger.debug("apprise not installed — notifications disabled")
        self._running = False
        # Local device MACs — populated at start() for self-identification
        self._local_macs: set[str] = set()
        self._analysis_executor = ThreadPoolExecutor(max_workers=1)
        self.probe_scheduler: ProbeScheduler | None = None

        # Remote sensor management
        from leetha.capture.remote.server import RemoteSensorManager
        self._remote_sensor_manager = RemoteSensorManager()

        # Sharded pipeline (only when worker_count > 1)
        self._router: PacketRouter | None = None
        self._worker_pipelines: list[Pipeline] = []  # per-worker pipeline instances
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
            is_local_mac=self.is_local_device,
            on_new_host=self._on_new_host_discovered,
        )

        self._running = True
        self._app_loop = asyncio.get_running_loop()

        # Fire-and-forget: preload smaller Huginn caches in a background
        # thread.  Not awaited so the pipeline starts immediately.
        # huginn_dhcp (138 MB) and huginn_mac_vendors (667 MB) are NOT
        # preloaded — loaded on-demand only when needed.
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, self._preload_caches)

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

        # Watchdog: monitor the process loop and restart it if it dies
        self._tasks.append(asyncio.create_task(self._watchdog()))

        # Start Unix socket server if configured
        if self.config.socket_path:
            self._tasks.append(asyncio.create_task(
                self.start_unix_socket(self.config.socket_path)))

        # Start the packet processing thread — needed for both local capture
        # and remote sensor packets.  Must start before capture or sensor
        # listener so nothing is lost.
        if not getattr(self, "_drain_thread", None) or not self._drain_thread.is_alive():
            import threading
            self._drain_thread = threading.Thread(
                target=self._process_thread, daemon=True,
                name="process-thread")
            self._drain_thread.start()

        # Start remote sensor listener (all modes — console, live, web)
        from leetha.capture.remote.listener import start_sensor_listener
        await start_sensor_listener(self, port=8443)

        # Periodic flush of custom pattern hit counters
        async def _flush_hits_loop():
            from leetha.fingerprint.lookup import flush_pattern_hits
            while self._running:
                await asyncio.sleep(60)
                flush_pattern_hits(self.config.data_dir)

        self._tasks.append(asyncio.create_task(_flush_hits_loop()))

        # Periodic unsnooze of expired snoozed findings
        async def _unsnooze_loop():
            while self._running:
                await asyncio.sleep(30)
                try:
                    count = await self.store.findings.unsnooze_expired()
                    if count > 0:
                        logger.info("Unsnoozed %d expired findings", count)
                except Exception as e:
                    logger.debug("Unsnooze check failed: %s", e)

        self._tasks.append(asyncio.create_task(_unsnooze_loop()))

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
            logger.error(
                "Cannot start capture — insufficient privileges. "
                "Run as root, with sudo, or grant CAP_NET_RAW."
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

        loop = getattr(self, "_app_loop", None) or asyncio.get_running_loop()
        self.capture_engine.start(self.packet_queue, loop)  # loop kept for compat

        # Detect local MACs from capture interfaces for self-identification
        self._detect_local_macs()

        # Re-evaluate unknown devices 60s after capture starts
        self._tasks.append(asyncio.create_task(self._reevaluate_unknown_devices()))

        # Ensure the process thread is running (may already be started by
        # app.start() for remote sensor support).
        if not getattr(self, "_drain_thread", None) or not self._drain_thread.is_alive():
            import threading
            self._drain_thread = threading.Thread(
                target=self._process_thread, daemon=True,
                name="process-thread")
            self._drain_thread.start()

        logger.info("Capture started on %s",
                     ", ".join(i.name for i in self.config.interfaces))
        return True

    def _on_task_done(self, task: asyncio.Task) -> None:
        """Callback when a background task finishes — log if it crashed."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            logger.error("Background task %s crashed: %s",
                         task.get_name(), exc, exc_info=exc)

    @staticmethod
    def _broadcast_finding_threadsafe(finding, subscribers, main_loop):
        """Push a finding_created event to WS subscribers from the process thread."""
        if not subscribers or not main_loop:
            return
        event = {
            "type": "finding_created",
            "finding": {
                "hw_addr": finding.hw_addr,
                "rule": finding.rule.value if hasattr(finding.rule, "value") else str(finding.rule),
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "message": finding.message,
                "timestamp": finding.timestamp.isoformat() if finding.timestamp else None,
            },
        }
        for sub in list(subscribers):
            try:
                main_loop.call_soon_threadsafe(sub.put_nowait, event)
            except (RuntimeError, asyncio.QueueFull):
                pass

    def _process_thread(self):
        """Dedicated thread for packet processing with its own event loop
        and its own database connection.

        Completely independent of the main background event loop — can't be
        frozen by DB contention, analysis tasks, or WebSocket handlers.
        """
        import asyncio as _aio
        import queue as _queue_mod
        import traceback as _tb

        try:
            loop = _aio.new_event_loop()
            _aio.set_event_loop(loop)

            from leetha.store.store import Store
            from leetha.core.pipeline import Pipeline
            thread_store = Store(self.config.db_path)
            loop.run_until_complete(thread_store.initialize())
            logger.info("Process thread initialized (db=%s)", self.config.db_path)
        except Exception as e:
            logger.error("Process thread init failed: %s", e, exc_info=True)
            return

        import leetha.processors  # noqa: F401  — ensure all processors registered

        # Initialize a thread-local spoofing detector with its own DB
        # connection so security callbacks can run in this thread.
        from leetha.store.database import Database as _LegacyDB
        from leetha.analysis.spoofing import SpoofingDetector as _SD
        thread_legacy_db = _LegacyDB(self.config.db_path)
        loop.run_until_complete(thread_legacy_db.initialize())
        thread_spoof = _SD(thread_legacy_db)
        loop.run_until_complete(thread_spoof.initialize())

        thread_pipeline = Pipeline(
            store=thread_store,
            is_local_mac=self.is_local_device,
        )

        # Reference to the main event loop for thread-safe event dispatch
        main_loop = getattr(self, "_app_loop", None)

        def _sanitize(obj):
            """Convert bytes to str for JSON serialization."""
            if isinstance(obj, bytes):
                return obj.decode("utf-8", errors="replace")
            if isinstance(obj, dict):
                return {k: _sanitize(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_sanitize(v) for v in obj]
            return obj

        def _push_event(pkt, verdict=None):
            """Thread-safe push of a packet event to WebSocket subscribers."""
            if not self.event_subscribers or main_loop is None:
                return
            packet_info = {
                "protocol": pkt.protocol,
                "src_mac": pkt.hw_addr,
                "src_ip": pkt.ip_addr,
                "dst_ip": getattr(pkt, "target_ip", None),
                "fields": _sanitize(pkt.fields),
                "interface": pkt.interface,
                "timestamp": pkt.captured_at.isoformat() if hasattr(pkt, "captured_at") and pkt.captured_at else None,
            }
            verdict_data = verdict.to_dict() if verdict and hasattr(verdict, "to_dict") else {}
            event = {
                "type": "device_update",
                "mac": pkt.hw_addr,
                "verdict": verdict_data,
                "packet": packet_info,
            }
            for sub in list(self.event_subscribers):
                try:
                    main_loop.call_soon_threadsafe(sub.put_nowait, event)
                except (RuntimeError, asyncio.QueueFull):
                    pass

        def _run_arp_security(ev_loop, pkt, spoof_det, store):
            """Run ARP spoofing detection synchronously in the process thread."""
            from leetha.store.models import Finding, FindingRule, AlertSeverity, AlertType
            alerts = ev_loop.run_until_complete(spoof_det.process_arp(
                src_mac=pkt.hw_addr,
                src_ip=pkt.ip_addr or "",
                dst_mac=getattr(pkt, "target_hw", None) or "ff:ff:ff:ff:ff:ff",
                dst_ip=getattr(pkt, "target_ip", None) or "",
                op=pkt.fields.get("op", 0),
                interface=pkt.interface or "unknown",
            ))
            _MAP = {
                AlertType.SPOOFING: FindingRule.IDENTITY_SHIFT,
                AlertType.MAC_SPOOFING: FindingRule.IDENTITY_SHIFT,
            }
            for alert in alerts:
                finding = Finding(
                    hw_addr=alert.device_mac,
                    rule=_MAP.get(alert.alert_type, FindingRule.IDENTITY_SHIFT),
                    severity=AlertSeverity(alert.severity.value),
                    message=alert.message,
                )
                ev_loop.run_until_complete(store.findings.add(finding))
                self._broadcast_finding_threadsafe(
                    finding, self.event_subscribers, main_loop)

        def _run_device_security(ev_loop, hw_addr, verdict, spoof_det, store, pipeline):
            """Run device spoofing / fingerprint drift checks in process thread."""
            from leetha.store.models import Device, Finding, FindingRule, AlertSeverity, AlertType
            host = ev_loop.run_until_complete(store.hosts.find_by_addr(hw_addr))
            if not host:
                return
            device = Device(
                mac=hw_addr,
                ip_v4=host.ip_addr,
                ip_v6=host.ip_v6,
                manufacturer=verdict.vendor,
                device_type=verdict.category,
                os_family=verdict.platform,
                os_version=verdict.platform_version,
                hostname=verdict.hostname,
                confidence=verdict.certainty,
                is_randomized_mac=host.mac_randomized,
            )
            oui_vendor = pipeline._oui_vendors.get(hw_addr)

            async def _snap_read(mac, limit=1):
                return await store.snapshots.get_latest(mac, limit)
            async def _snap_write(hw_addr, **kw):
                await store.snapshots.add(hw_addr=hw_addr, **kw)

            alerts = ev_loop.run_until_complete(
                spoof_det.process_device_update(
                    device, oui_vendor=oui_vendor,
                    snapshot_reader=_snap_read,
                    snapshot_writer=_snap_write))
            _MAP = {
                AlertType.SPOOFING: FindingRule.IDENTITY_SHIFT,
                AlertType.MAC_SPOOFING: FindingRule.IDENTITY_SHIFT,
            }
            for alert in alerts:
                finding = Finding(
                    hw_addr=alert.device_mac,
                    rule=_MAP.get(alert.alert_type, FindingRule.IDENTITY_SHIFT),
                    severity=AlertSeverity(alert.severity.value),
                    message=alert.message,
                )
                ev_loop.run_until_complete(store.findings.add(finding))
                self._broadcast_finding_threadsafe(
                    finding, self.event_subscribers, main_loop)

        processed = 0
        errors = 0
        try:
            while self._running:
                try:
                    pkt = self.packet_queue.get(timeout=0.25)
                except _queue_mod.Empty:
                    continue
                except Exception:
                    continue

                try:
                    loop.run_until_complete(thread_pipeline.process(pkt))
                    processed += 1

                    # Fetch verdict for WS event and security checks
                    verdict = None
                    try:
                        verdict = loop.run_until_complete(
                            thread_store.verdicts.find_by_addr(pkt.hw_addr))
                        _push_event(pkt, verdict)
                    except Exception:
                        _push_event(pkt)

                    # --- Security callbacks (run in process thread) ---

                    # ARP spoofing detection
                    if pkt.protocol == "arp":
                        try:
                            _run_arp_security(loop, pkt, thread_spoof, thread_store)
                        except Exception:
                            logger.debug("Thread ARP check failed", exc_info=True)

                    # Device spoofing / fingerprint drift (on every verdict)
                    if verdict and verdict.certainty > 0:
                        try:
                            _run_device_security(
                                loop, pkt.hw_addr, verdict,
                                thread_spoof, thread_store, thread_pipeline)
                        except Exception:
                            logger.debug("Thread spoofing check failed", exc_info=True)

                    # Gateway learning from DHCP/RA
                    if pkt.protocol == "dhcpv4":
                        raw_opts = pkt.fields.get("raw_options", {})
                        msg_type = raw_opts.get("message-type")
                        if msg_type in (2, 5) and pkt.ip_addr:
                            try:
                                loop.run_until_complete(
                                    thread_spoof.learn_gateway(
                                        pkt.hw_addr, pkt.ip_addr, "dhcp_server",
                                        pkt.interface or ""))
                            except Exception:
                                pass
                except Exception:
                    errors += 1
                    if errors <= 5 or errors % 100 == 0:
                        logger.warning("Process thread error #%d", errors, exc_info=True)
        except Exception:
            logger.error("Process thread crashed", exc_info=True)
        finally:
            try:
                loop.run_until_complete(thread_store.close())
                loop.run_until_complete(thread_legacy_db.close())
                loop.close()
            except Exception:
                pass

    async def _watchdog(self):
        """Monitor the process thread and restart it if it dies.

        The process thread is the critical path for all packet processing.
        If it dies for any reason, no new devices appear in the inventory.
        This watchdog checks every 10 seconds and restarts it.
        """
        await asyncio.sleep(5)  # let everything initialize

        try:
            while self._running:
                await asyncio.sleep(10)
                thread = getattr(self, "_drain_thread", None)
                if thread is None or not thread.is_alive():
                    with open("/tmp/leetha_watchdog.txt", "a") as f:
                        import datetime as _dt
                        f.write(f"{_dt.datetime.now().isoformat()} Process thread DEAD, restarting\n")
                    import threading
                    self._drain_thread = threading.Thread(
                        target=self._process_thread, daemon=True,
                        name="process-thread")
                    self._drain_thread.start()
                    with open("/tmp/leetha_watchdog.txt", "a") as f:
                        import datetime as _dt
                        f.write(f"{_dt.datetime.now().isoformat()} Process thread RESTARTED\n")
        except asyncio.CancelledError:
            return

    def _preload_caches(self):
        """Preload large Huginn JSON caches in a background thread.

        This runs outside the event loop so blocking I/O is safe.
        Loads directly into the cache dict, bypassing the _PRELOAD_ONLY guard.
        """
        import json as _json
        import time as _time

        from leetha.fingerprint.lookup import FingerprintLookup
        lookup = self.pipeline._lookup if self.pipeline else FingerprintLookup()
        cache_dir = lookup._cache_dir
        t0 = _time.monotonic()

        for name in (
            "p0f", "ja3", "ja4", "iana_enterprise",  # tiny files first
            "satori_dhcp", "satori_useragent", "satori_tcp",  # Satori (all <1MB)
            "satori_smb", "satori_ssh", "satori_web",
            "satori_sip", "satori_ntp",
            "huginn_combinations", "huginn_dhcpv6",
            "huginn_dhcp_vendor", "huginn_dhcpv6_enterprise",
            "huginn_devices",
            # huginn_dhcp (138 MB) loaded on-demand only
            # huginn_mac_vendors (667 MB) NOT preloaded — OUI index handles MAC lookups
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
                from leetha.fingerprint.lookup import SignatureMatcher
                data = SignatureMatcher._compact_cache(name, data)
                lookup._json_cache[name] = data
                elapsed = _time.monotonic() - t1
                logger.debug("Preloaded %s (%.1fs)", name, elapsed)
                _time.sleep(0.1)  # Yield GIL so event loop can make progress
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
        """Stop capture and close DB. Designed for immediate shutdown."""
        self._running = False

        # 1. Stop capture threads first (signals halt flags)
        self.capture_engine.stop()

        # 2. Cancel all async tasks immediately
        for task in self._tasks:
            task.cancel()

        # 3. Stop remote sensor listener
        try:
            from leetha.capture.remote.listener import stop_sensor_listener
            await asyncio.wait_for(stop_sensor_listener(), timeout=1.0)
        except (asyncio.TimeoutError, Exception):
            pass

        # 4. Shutdown executors without waiting
        self._analysis_executor.shutdown(wait=False, cancel_futures=True)
        if self.probe_scheduler:
            try:
                self.probe_scheduler.shutdown()
            except Exception:
                pass

        # 5. Wait briefly for tasks to acknowledge cancellation
        if self._tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._tasks, return_exceptions=True),
                    timeout=0.5,
                )
            except asyncio.TimeoutError:
                pass
        self._tasks.clear()

        # 6. Close DB connections
        for closeable in (self.store, self.db):
            try:
                await asyncio.wait_for(closeable.close(), timeout=0.5)
            except (asyncio.TimeoutError, Exception):
                pass

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to real-time device/alert events. Returns a bounded event queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.event_subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """Unsubscribe from events."""
        if q in self.event_subscribers:
            self.event_subscribers.remove(q)

    # ------------------------------------------------------------------
    # Unix socket event server
    # ------------------------------------------------------------------

    async def start_unix_socket(self, socket_path: str = "/tmp/leetha.sock"):
        """Start a Unix domain socket server that streams events as newline-delimited JSON.

        Clients connect and receive the same real-time events as the WebSocket
        endpoints. Each event is a JSON object followed by a newline.

        Usage:
            socat - UNIX-CONNECT:/tmp/leetha.sock
            nc -U /tmp/leetha.sock
            python: sock.connect("/tmp/leetha.sock"); for line in sock.makefile(): ...
        """
        import json
        import os

        # Remove stale socket file from previous run
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass

        async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            """Stream events to a single connected client."""
            queue = self.subscribe()
            peer = writer.get_extra_info("peername") or socket_path
            logger.info("Unix socket client connected: %s", peer)
            try:
                while self._running:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue
                    try:
                        line = json.dumps(event, default=str) + "\n"
                        writer.write(line.encode())
                        await writer.drain()
                    except (ConnectionError, BrokenPipeError, OSError):
                        break
            except asyncio.CancelledError:
                pass
            finally:
                self.unsubscribe(queue)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                logger.info("Unix socket client disconnected: %s", peer)

        try:
            server = await asyncio.start_unix_server(_handle_client, path=socket_path)
            # Make socket world-readable so non-root clients can connect
            os.chmod(socket_path, 0o660)
            logger.info("Unix socket listening on %s", socket_path)
            self._unix_socket_server = server
            self._unix_socket_path = socket_path
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.warning("Unix socket server failed", exc_info=True)
        finally:
            try:
                os.unlink(socket_path)
            except FileNotFoundError:
                pass

    async def _process_loop(self):
        """Placeholder — kept for backward compatibility.
        The actual processing now happens in _process_thread().
        """
        # Just keep this task alive so the watchdog doesn't restart it
        try:
            while self._running:
                await asyncio.sleep(10)
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
        """Periodic analysis: stale sources, infra offline, data pruning. Runs every 30s."""
        from leetha.store.models import Finding, FindingRule, AlertSeverity
        try:
            cycle = 0
            while self._running:
                await asyncio.sleep(30)
                cycle += 1

                # Check for stale fingerprint sources → write to new findings
                try:
                    await self._check_stale_sources()
                except Exception:
                    logger.debug("Stale source check failed", exc_info=True)

                # Check for infrastructure devices gone offline → write to new findings
                try:
                    await self._check_infra_offline()
                except Exception:
                    logger.debug("Infra offline check failed", exc_info=True)

                # Update Prometheus metrics
                try:
                    from leetha.metrics import update_metrics
                    from datetime import datetime, timedelta, timezone
                    device_count = await self.store.hosts.count()
                    alert_count = await self.store.findings.count_active()
                    threshold = datetime.now(timezone.utc) - timedelta(minutes=5)
                    all_hosts = await self.store.hosts.find_all()
                    def _aware(dt):
                        return dt.replace(tzinfo=timezone.utc) if dt and dt.tzinfo is None else dt
                    online = sum(1 for h in all_hosts if h.last_active and _aware(h.last_active) >= threshold)
                    capture_count = len(self.capture_engine.interfaces)
                    await update_metrics(device_count, online, alert_count, capture_count, 0)
                except Exception:
                    logger.debug("Metrics update failed", exc_info=True)

                # WAL checkpoint every 5 minutes (cycle 10 × 30s) to prevent
                # unbounded WAL growth when the process thread writes continuously.
                if cycle % 10 == 0:
                    try:
                        await self.store.connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
                    except Exception:
                        logger.debug("WAL checkpoint failed", exc_info=True)

                # Prune old sightings every 10 minutes (cycle 20 × 30s)
                if cycle % 20 == 0:
                    try:
                        await self._prune_sightings()
                    except Exception:
                        logger.debug("Sightings pruning failed", exc_info=True)
                    # Prune old fingerprint snapshots
                    try:
                        await self.store.snapshots.prune(max_per_mac=50)
                    except Exception:
                        logger.debug("Snapshot pruning failed", exc_info=True)
        except asyncio.CancelledError:
            return

    async def _check_stale_sources(self):
        """Check fingerprint source files for staleness, write findings to new Store."""
        import time as _time
        from pathlib import Path
        from leetha.store.models import Finding, FindingRule, AlertSeverity

        data_dir = Path(self.config.data_dir)
        if not data_dir.exists():
            return
        max_age_days = self.config.sync_interval_days * 4
        max_age_seconds = max_age_days * 86400
        now = _time.time()

        for filepath in data_dir.iterdir():
            if not filepath.suffix == ".json":
                continue
            age = now - filepath.stat().st_mtime
            if age > max_age_seconds:
                days_old = int(age / 86400)
                # Rate-limit: check if we already have an active stale_source finding
                try:
                    existing = await self.store.connection.execute(
                        "SELECT id FROM findings WHERE rule = ? AND resolved = 0 "
                        "AND message LIKE ? LIMIT 1",
                        (FindingRule.STALE_SOURCE.value, f"%{filepath.name}%"),
                    )
                    if await existing.fetchone():
                        continue
                except Exception:
                    pass
                finding = Finding(
                    hw_addr="00:00:00:00:00:00",
                    rule=FindingRule.STALE_SOURCE,
                    severity=AlertSeverity.WARNING,
                    message=f"Fingerprint source {filepath.name} is {days_old} days old "
                            f"(threshold: {max_age_days}d). Run 'leetha sync' to update.",
                )
                await self.store.findings.add(finding)
                self._broadcast_finding(finding)

    async def _check_infra_offline(self):
        """Check for infrastructure devices gone offline using new Store."""
        from datetime import datetime, timedelta, timezone
        from leetha.store.models import Finding, FindingRule, AlertSeverity
        from leetha.topology import _normalize_device_type, _INFRA_TYPES

        threshold = datetime.now(timezone.utc) - timedelta(minutes=5)
        verdicts = await self.store.verdicts.find_all(limit=1000)

        for v in verdicts:
            if not v.category:
                continue
            normalized = _normalize_device_type(v.category)
            if normalized not in _INFRA_TYPES:
                continue

            host = await self.store.hosts.find_by_addr(v.hw_addr)
            if not host:
                continue
            if host.disposition == "self":
                continue

            last_seen = host.last_active
            if last_seen is not None and last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            if last_seen is None or last_seen >= threshold:
                continue

            # Rate-limit: don't re-alert for same device
            try:
                existing = await self.store.connection.execute(
                    "SELECT id FROM findings WHERE hw_addr = ? AND rule = ? "
                    "AND resolved = 0 LIMIT 1",
                    (v.hw_addr, FindingRule.IDENTITY_SHIFT.value),
                )
                # Use a distinct message prefix to identify infra_offline findings
                existing2 = await self.store.connection.execute(
                    "SELECT id FROM findings WHERE hw_addr = ? AND resolved = 0 "
                    "AND message LIKE '%offline%' LIMIT 1",
                    (v.hw_addr,),
                )
                if await existing2.fetchone():
                    continue
            except Exception:
                pass

            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            minutes_ago = int((datetime.now(timezone.utc) - last_seen).total_seconds() / 60)
            is_gateway = normalized in ("router", "gateway", "firewall")
            severity = AlertSeverity.CRITICAL if is_gateway else AlertSeverity.WARNING
            label = v.hostname or v.vendor or v.hw_addr

            finding = Finding(
                hw_addr=v.hw_addr,
                rule=FindingRule.IDENTITY_SHIFT,
                severity=severity,
                message=(
                    f"{'Gateway' if is_gateway else 'Infrastructure device'} offline: "
                    f"{label} ({v.hw_addr}) — last seen {minutes_ago} minutes ago"
                ),
            )
            await self.store.findings.add(finding)
            self._broadcast_finding(finding)

    async def _prune_sightings(self, retention_days: int = 7):
        """Delete sightings older than retention_days to prevent DB bloat."""
        try:
            cursor = await self.store.connection.execute(
                "DELETE FROM sightings WHERE timestamp < datetime('now', ?)",
                (f"-{retention_days} days",),
            )
            await self.store.connection.commit()
            if cursor.rowcount > 0:
                logger.info("Pruned %d sightings older than %d days",
                           cursor.rowcount, retention_days)
                await self.store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            logger.debug("Sighting prune failed", exc_info=True)

    def _handle_dhcp_anomalies(self, future, loop):
        """Process DHCP anomaly results from background thread."""
        try:
            anomalies = future.result()
            if anomalies:
                asyncio.run_coroutine_threadsafe(
                    self._write_dhcp_anomaly_findings(anomalies),
                    loop,
                )
        except Exception:
            logger.debug("DHCP anomaly processing failed", exc_info=True)

    async def _write_dhcp_anomaly_findings(self, anomalies: list[dict]):
        """Convert DHCP anomalies to findings and write to store."""
        from leetha.store.models import Finding, FindingRule, AlertSeverity
        for anomaly in anomalies:
            finding = Finding(
                hw_addr=anomaly.get("src_mac", "00:00:00:00:00:00"),
                rule=FindingRule.DHCP_ANOMALY,
                severity=AlertSeverity.WARNING,
                message=f"DHCP anomaly on option '{anomaly.get('option', '?')}': {anomaly.get('reason', 'unknown')}",
            )
            await self.store.findings.add(finding)
            self._broadcast_finding(finding)

    def _broadcast_finding(self, finding):
        """Push a finding_created event to all websocket subscribers."""
        event = {
            "type": "finding_created",
            "finding": {
                "hw_addr": finding.hw_addr,
                "rule": finding.rule.value if hasattr(finding.rule, "value") else str(finding.rule),
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "message": finding.message,
                "timestamp": finding.timestamp.isoformat() if hasattr(finding, "timestamp") and finding.timestamp else None,
            },
        }
        stale = []
        for sub in self.event_subscribers:
            try:
                sub.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    sub.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    sub.put_nowait(event)
                except asyncio.QueueFull:
                    stale.append(sub)
        for sub in stale:
            self.event_subscribers.remove(sub)

        # Fire-and-forget notification to external services
        notifier = getattr(self, "_notifier", None)
        if notifier:
            asyncio.ensure_future(notifier.send(finding))

        # Increment Prometheus finding counter
        try:
            from leetha.metrics import record_finding
            rule = finding.rule.value if hasattr(finding.rule, "value") else str(finding.rule)
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            record_finding(rule, sev)
        except Exception:
            pass

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
        """Process packets from a shard queue using per-worker Pipeline."""
        worker_pipeline = self._worker_pipelines[shard_id]
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                try:
                    await worker_pipeline.process(packet)
                except Exception:
                    logger.debug("Worker %d pipeline failed", shard_id, exc_info=True)
        except asyncio.CancelledError:
            return

    async def _restore_admin_token(self):
        """Ensure an admin token always exists — restore from file or generate new."""
        try:
            count = await self.db.count_active_admin_tokens()
            if count > 0:
                return  # DB already has tokens

            from leetha.auth.tokens import (
                load_admin_token, save_admin_token,
                generate_token, hash_token,
            )

            raw = load_admin_token()
            if raw:
                # Token file exists but DB is empty — re-import it
                await self.db.create_auth_token(
                    hash_token(raw), role="admin", label="restored-from-file")
                logger.info("Restored admin token from ~/.leetha/admin-token")
                return

            # Neither DB nor file has a token — generate a fresh one
            raw = generate_token()
            await self.db.create_auth_token(
                hash_token(raw), role="admin", label="auto-generated")
            save_admin_token(raw)
            logger.info("Generated new admin token → ~/.leetha/admin-token")
        except Exception:
            logger.debug("Admin token restore failed", exc_info=True)

    # -- Pipeline side-effect callbacks ----------------------------------

    async def _on_new_host_discovered(self, hw_addr, host, packet):
        """Emit WebSocket event when a new device is first discovered.

        This fires immediately on first sighting — before any verdict is
        computed — so the UI updates in real time for every new MAC.
        """
        event = {
            "type": "device_discovered",
            "mac": hw_addr,
            "device": {
                "mac": hw_addr,
                "ip_v4": host.ip_addr,
                "ip_v6": host.ip_v6,
                "alert_status": host.disposition,
                "is_randomized_mac": host.mac_randomized,
            },
        }
        for sub in self.event_subscribers:
            try:
                sub.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    sub.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    sub.put_nowait(event)
                except asyncio.QueueFull:
                    pass

    async def _on_verdict_event(self, hw_addr, verdict, packet):
        """Emit WebSocket event after verdict computed, run spoofing checks."""
        # Run MAC spoofing / fingerprint drift detection on every verdict
        await self._check_device_spoofing(hw_addr, verdict)

        # Include packet info for the console live stream.
        # Sanitize fields: convert bytes to strings so JSON serialization
        # doesn't crash the WebSocket handler.
        packet_info = None
        if packet:
            def _sanitize(obj):
                if isinstance(obj, bytes):
                    return obj.decode("utf-8", errors="replace")
                if isinstance(obj, dict):
                    return {k: _sanitize(v) for k, v in obj.items()}
                if isinstance(obj, (list, tuple)):
                    return [_sanitize(v) for v in obj]
                return obj

            packet_info = {
                "protocol": packet.protocol,
                "src_mac": packet.hw_addr,
                "src_ip": packet.ip_addr,
                "dst_ip": getattr(packet, "target_ip", None),
                "fields": _sanitize(packet.fields),
                "interface": packet.interface,
                "timestamp": packet.captured_at.isoformat() if hasattr(packet, "captured_at") and packet.captured_at else None,
            }
        event = {
            "type": "device_update",
            "mac": hw_addr,
            "verdict": verdict.to_dict() if hasattr(verdict, "to_dict") else {},
            "packet": packet_info,
        }
        stale = []
        for sub in self.event_subscribers:
            try:
                sub.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest event to make room, preventing unbounded backlog
                try:
                    sub.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    sub.put_nowait(event)
                except asyncio.QueueFull:
                    stale.append(sub)
        # Remove subscribers that can't keep up
        for sub in stale:
            logger.warning("Removing stale WebSocket subscriber (queue full)")
            self.event_subscribers.remove(sub)

    async def _on_arp_packet(self, packet):
        """Run spoofing detection on ARP packets."""
        from leetha.store.models import Finding, FindingRule, AlertSeverity, AlertType
        try:
            alerts = await self.spoofing_detector.process_arp(
                src_mac=packet.hw_addr,
                src_ip=packet.ip_addr or "",
                dst_mac=packet.target_hw or "ff:ff:ff:ff:ff:ff",
                dst_ip=packet.target_ip or "",
                op=packet.fields.get("op", 0),
                interface=packet.interface or "unknown",
            )
            # Map old AlertType to new FindingRule
            _ALERT_TO_FINDING = {
                AlertType.SPOOFING: FindingRule.IDENTITY_SHIFT,
                AlertType.MAC_SPOOFING: FindingRule.IDENTITY_SHIFT,
            }
            for alert in alerts:
                rule = _ALERT_TO_FINDING.get(alert.alert_type, FindingRule.IDENTITY_SHIFT)
                finding = Finding(
                    hw_addr=alert.device_mac,
                    rule=rule,
                    severity=AlertSeverity(alert.severity.value),
                    message=alert.message,
                )
                await self.store.findings.add(finding)
                self._broadcast_finding(finding)
        except Exception:
            logger.debug("ARP spoofing check failed", exc_info=True)

    async def _check_device_spoofing(self, hw_addr, verdict):
        """Run MAC spoofing / fingerprint drift checks after verdict update.

        Calls the SpoofingDetector.process_device_update() which compares
        the current device fingerprint against historical snapshots to
        detect identity shifts, OUI mismatches, and MAC spoofing.
        """
        from leetha.store.models import (
            Device, Finding, FindingRule, AlertSeverity, AlertType,
        )
        try:
            # Build a Device object from verdict + host for the spoofing detector
            host = await self.store.hosts.find_by_addr(hw_addr)
            device = Device(
                mac=hw_addr,
                ip_v4=host.ip_addr if host else None,
                ip_v6=host.ip_v6 if host else None,
                manufacturer=verdict.vendor,
                device_type=verdict.category,
                os_family=verdict.platform,
                os_version=verdict.platform_version,
                hostname=verdict.hostname,
                confidence=verdict.certainty,
                is_randomized_mac=host.mac_randomized if host else False,
            )

            # Get OUI vendor from pipeline evidence buffer
            oui_vendor = None
            if self.pipeline:
                oui_vendor = self.pipeline._oui_vendors.get(hw_addr)

            async def _snapshot_reader(mac, limit=1):
                return await self.store.snapshots.get_latest(mac, limit)

            async def _snapshot_writer(hw_addr, os_family=None, manufacturer=None,
                                       device_type=None, hostname=None, oui_vendor=None):
                await self.store.snapshots.add(
                    hw_addr=hw_addr, os_family=os_family, manufacturer=manufacturer,
                    device_type=device_type, hostname=hostname, oui_vendor=oui_vendor)

            alerts = await self.spoofing_detector.process_device_update(
                device, oui_vendor=oui_vendor,
                snapshot_reader=_snapshot_reader,
                snapshot_writer=_snapshot_writer)

            _ALERT_TO_FINDING = {
                AlertType.SPOOFING: FindingRule.IDENTITY_SHIFT,
                AlertType.MAC_SPOOFING: FindingRule.IDENTITY_SHIFT,
            }
            for alert in alerts:
                rule = _ALERT_TO_FINDING.get(alert.alert_type, FindingRule.IDENTITY_SHIFT)
                finding = Finding(
                    hw_addr=alert.device_mac,
                    rule=rule,
                    severity=AlertSeverity(alert.severity.value),
                    message=alert.message,
                )
                await self.store.findings.add(finding)
                self._broadcast_finding(finding)
        except Exception:
            logger.debug("Device spoofing check failed", exc_info=True)

    def _on_dhcp_packet(self, packet):
        """Submit DHCP options for anomaly analysis."""
        raw_opts = packet.fields.get("raw_options")
        if raw_opts:
            loop = asyncio.get_running_loop()
            future = self._analysis_executor.submit(
                analyze_dhcp_options,
                raw_opts,
                packet.hw_addr,
                packet.ip_addr or "",
                self.config.data_dir,
            )
            future.add_done_callback(lambda f: self._handle_dhcp_anomalies(f, loop))

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


