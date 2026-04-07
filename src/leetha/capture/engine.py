"""Packet capture orchestrator -- sniffs network traffic via scapy worker threads.

Provides the PacketCapture class which manages one sniffing thread per network
interface. Incoming frames are run through the PARSER_CHAIN to produce
CapturedPacket objects, then forwarded to an asyncio queue for downstream
processing.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from typing import TYPE_CHECKING

from leetha.capture.dedup import TTLDedup
from leetha.capture.interfaces import InterfaceConfig

if TYPE_CHECKING:
    from leetha.capture.packets import CapturedPacket

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BPF filter fragments -- assembled at runtime based on interface type
# ---------------------------------------------------------------------------

_BPF_L2_PROTOS = "ether proto 0x88cc"                        # LLDP
_BPF_SNMP = "udp port 161 or udp port 162"
_BPF_TCP_SYN = "tcp[tcpflags] & tcp-syn != 0"
_BPF_TLS = "tcp port 443"
_BPF_HTTP = "tcp port 80"
_BPF_AI_PORTS = "tcp port 11434 or tcp port 7860 or tcp port 8188"
_BPF_BANNER_PORTS = "tcp port 22 or tcp port 21 or tcp port 23 or tcp port 25 or tcp port 465 or tcp port 587 or tcp port 110 or tcp port 995 or tcp port 143 or tcp port 993 or tcp port 5900 or tcp port 5901 or tcp port 5902 or tcp port 5903 or tcp port 6667 or tcp port 6697 or tcp port 3306 or tcp port 5432 or tcp port 1433 or tcp port 27017 or tcp port 6379 or tcp port 445 or tcp port 139 or tcp port 3389 or tcp port 631 or tcp port 9100 or tcp port 515 or tcp port 1883 or tcp port 8883 or tcp port 5672 or tcp port 5060 or tcp port 5061 or tcp port 554 or tcp port 7447 or tcp port 8554 or tcp port 389 or tcp port 636 or tcp port 9042 or tcp port 9200 or tcp port 2375 or tcp port 2376 or tcp port 6443 or tcp port 1080 or tcp port 1081 or tcp port 179 or tcp port 1723 or tcp port 7443 or tcp port 7444"
_BPF_DHCP4 = "udp port 67 or udp port 68"
_BPF_DHCP6 = "udp port 546 or udp port 547"
_BPF_MDNS = "udp port 5353"
_BPF_SSDP = "udp port 1900"
_BPF_NAME_SVC = "udp port 5355 or udp port 137"
_BPF_DNS = "udp port 53"
_BPF_ICMP6 = "icmp6"
_BPF_ARP = "arp"
_BPF_IOT_SCADA = "udp port 502 or udp port 47808 or udp port 5683 or tcp port 44818 or udp port 44818"
_BPF_STUN = "udp port 3478 or udp port 5349 or udp port 19302"
_BPF_RADIUS = "udp port 1812 or udp port 1813"
_BPF_EAP = "ether proto 0x888e"
_BPF_IGMP = "igmp"
_BPF_UPNP = "tcp port 2869 or tcp port 5000"

_FULL_BPF = " or ".join([
    _BPF_L2_PROTOS, _BPF_EAP, _BPF_SNMP, _BPF_TCP_SYN, _BPF_TLS, _BPF_HTTP,
    _BPF_AI_PORTS, _BPF_BANNER_PORTS, _BPF_DHCP4, _BPF_DHCP6, _BPF_MDNS, _BPF_SSDP,
    _BPF_NAME_SVC, _BPF_DNS, _BPF_ICMP6, _BPF_IGMP, _BPF_ARP, _BPF_IOT_SCADA,
    _BPF_STUN, _BPF_RADIUS, _BPF_UPNP,
])


def _bpf_for_mode(mode: str) -> str:
    """Return a BPF expression appropriate for the interface capture mode.

    Ethernet and tap interfaces get a broad filter that captures all IP,
    ARP, and L2 protocol traffic — essential for passive fingerprinting
    across VLANs. TUN interfaces only see layer 3.
    """
    if mode == "tun":
        return "ip or ip6"
    # Broad filter for ethernet/tap/bridge — capture everything useful
    # including broadcast traffic from other VLANs visible on the wire
    return "ip or ip6 or arp or " + _BPF_L2_PROTOS + " or ether proto 0x888e or igmp"


# ---------------------------------------------------------------------------
# Main capture class
# ---------------------------------------------------------------------------

class PacketCapture:
    """Manages per-interface scapy sniff workers and feeds parsed packets
    into an asyncio queue consumed by the analysis pipeline.

    Lifecycle: construct -> activate() -> [attach/detach] -> shutdown()
    """

    def __init__(
        self,
        interface: str | None = None,
        interfaces: list[InterfaceConfig] | None = None,
        bpf_filter: str = "",
    ):
        self._global_filter = bpf_filter
        self.bpf_filter = bpf_filter  # backward compat alias
        self._output: asyncio.Queue | None = None
        self._event_loop: asyncio.AbstractEventLoop | None = None

        # ring buffer of raw bytes for PCAP export
        self._packet_buffer: deque = deque(maxlen=2_000)

        # TTL-based dedup caches (replace old class-level sets)
        self._ip_observed_dedup = TTLDedup(max_entries=50_000, ttl_seconds=300.0)
        self._banner_dedup = TTLDedup(max_entries=50_000, ttl_seconds=300.0)

        # registered interfaces keyed by device name
        self.interfaces: dict[str, InterfaceConfig] = {}
        if interfaces:
            for cfg in interfaces:
                self.interfaces[cfg.name] = cfg
        elif interface:
            self.interfaces[interface] = InterfaceConfig(name=interface)

        # per-interface concurrency primitives
        self._workers: dict[str, threading.Thread] = {}
        self._halt_flags: dict[str, threading.Event] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def activate(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        """Begin sniffing on every registered interface."""
        self._output = queue
        self._event_loop = loop
        for dev_name, cfg in self.interfaces.items():
            self._spawn_worker(dev_name, cfg)

    def shutdown(self) -> None:
        """Signal all workers to stop and wait for them to finish."""
        # raise halt flags first so workers notice promptly
        for flag in self._halt_flags.values():
            flag.set()
        # drop event-loop ref so no further enqueue attempts succeed
        self._event_loop = None
        for worker in self._workers.values():
            worker.join(timeout=2)
        self._workers.clear()
        self._halt_flags.clear()

    def attach(self, config: InterfaceConfig) -> None:
        """Register a new interface at runtime and start sniffing it."""
        self.interfaces[config.name] = config
        if self._output is not None and self._event_loop is not None:
            self._spawn_worker(config.name, config)

    def detach(self, name: str) -> None:
        """Unregister an interface and tear down its worker thread."""
        flag = self._halt_flags.pop(name, None)
        if flag is not None:
            flag.set()
        worker = self._workers.pop(name, None)
        if worker is not None:
            worker.join(timeout=5)
        self.interfaces.pop(name, None)

    @property
    def is_running(self) -> bool:
        """True when at least one sniff worker is alive."""
        return any(w.is_alive() for w in self._workers.values())

    # ------------------------------------------------------------------
    # Backward-compatible aliases so callers using the old API keep working
    # ------------------------------------------------------------------

    def start(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        """Alias for activate() -- old CaptureEngine API."""
        self.activate(queue, loop)

    def stop(self) -> None:
        """Alias for shutdown() -- old CaptureEngine API."""
        self.shutdown()

    def add_interface(self, config: InterfaceConfig) -> None:
        """Alias for attach() -- old CaptureEngine API."""
        self.attach(config)

    def remove_interface(self, name: str) -> None:
        """Alias for detach() -- old CaptureEngine API."""
        self.detach(name)

    # ------------------------------------------------------------------
    # Worker management
    # ------------------------------------------------------------------

    def _spawn_worker(self, dev_name: str, cfg: InterfaceConfig) -> None:
        """Create and start a daemon thread running the sniff loop."""
        halt = threading.Event()
        self._halt_flags[dev_name] = halt

        t = threading.Thread(
            target=self._sniff_loop,
            args=(dev_name, cfg, halt),
            daemon=True,
            name=f"sniff-{dev_name}",
        )
        self._workers[dev_name] = t
        t.start()

    # ------------------------------------------------------------------
    # Per-interface sniff loop (runs in its own thread)
    # ------------------------------------------------------------------

    def _sniff_loop(
        self,
        dev_name: str,
        cfg: InterfaceConfig,
        halt: threading.Event,
    ) -> None:
        """Continuously capture frames on *dev_name* until *halt* is set."""
        try:
            from scapy.all import sniff, conf
            conf.verb = 0
        except ImportError:
            log.error("scapy is required for packet capture but is not installed")
            return

        from leetha.capture.interfaces import classify_capture_mode

        cap_mode = classify_capture_mode(dev_name)

        # Filter priority: per-interface > global > auto-detect from mode
        if cfg.bpf_filter:
            active_bpf = cfg.bpf_filter
        elif self._global_filter:
            active_bpf = self._global_filter
        else:
            active_bpf = _bpf_for_mode(cap_mode)

        # Promiscuous mode on ALL interface types — a passive fingerprinting
        # tool must see all traffic on the wire, not just frames addressed
        # to our MAC.  Only TUN interfaces (layer 3 only) skip promisc.
        use_promisc = cap_mode != "tun"

        # Force promiscuous mode at the OS level for maximum visibility.
        # scapy's promisc flag only sets SO_PROMISC on the socket; setting
        # it on the interface ensures the NIC driver forwards all frames.
        if use_promisc:
            from leetha.platform import set_promiscuous
            if set_promiscuous(dev_name):
                log.debug("Set %s to promiscuous mode at OS level", dev_name)
            else:
                log.debug("Could not set promisc on %s (platform may handle it)", dev_name)

        log.info(
            "Sniffing %s  mode=%s  promisc=%s  bpf=%s",
            dev_name, cap_mode, use_promisc, active_bpf,
        )

        try:
            sniff(
                iface=dev_name,
                filter=active_bpf,
                prn=lambda frame, _dn=dev_name: self._ingest(frame, _dn),
                stop_filter=lambda _: halt.is_set(),
                store=0,
                promisc=use_promisc,
            )
        except Exception as exc:
            log.error("Sniff failure on %s: %s", dev_name, exc)

    # ------------------------------------------------------------------
    # Packet ingestion -- called once per captured frame
    # ------------------------------------------------------------------

    def _ingest(self, frame, dev_name: str = "") -> None:
        """Buffer raw bytes, classify the frame, and push to async queue."""
        self._packet_buffer.append(bytes(frame))

        result = self._classify(frame)
        if result is None:
            return

        # Suppress duplicate service banners -- only enqueue the first
        # banner per server MAC + server port combo.
        if result.protocol == "service_banner":
            server_port = result.fields.get("server_port", 0)
            if self._banner_dedup.seen(result.hw_addr, server_port):
                return

        # Suppress duplicate ip_observed — only enqueue the first
        # observation per MAC+dst_port pair. Other protocols always pass.
        if result.protocol == "ip_observed":
            dst_port = result.fields.get("dst_port")
            if self._ip_observed_dedup.seen(result.hw_addr, dst_port):
                return

        # Stamp with originating interface
        result.interface = dev_name

        self._enqueue(result)

    # ------------------------------------------------------------------
    # Classifier -- iterate PARSER_CHAIN for the first match
    # ------------------------------------------------------------------

    def _classify(self, frame) -> CapturedPacket | None:
        """Walk the ordered parser chain and return the first successful parse.

        Each parser in PARSER_CHAIN inspects the packet and returns a
        CapturedPacket (or list thereof for DNS answers) if it recognises
        the traffic, or None to pass to the next parser.  This replaces
        the old monolithic if/elif dispatch.
        """
        from leetha.capture.protocols import PARSER_CHAIN

        for parser_fn in PARSER_CHAIN:
            try:
                outcome = parser_fn(frame)
            except Exception:
                continue

            if outcome is None:
                continue

            # dns_answer returns a list -- enqueue extras, return the first
            if isinstance(outcome, list):
                if not outcome:
                    continue
                for extra in outcome[1:]:
                    extra.interface = ""
                    self._enqueue(extra)
                return outcome[0]

            # AI service enrichment for HTTP on known ports
            if outcome.protocol == "http_useragent":
                self._enrich_ai_hints(frame, outcome)

            return outcome

        return None

    # ------------------------------------------------------------------
    # AI-service enrichment (mirrors old HTTP + AI port logic)
    # ------------------------------------------------------------------

    @staticmethod
    def _enrich_ai_hints(frame, parsed: CapturedPacket) -> None:
        """Annotate an HTTP result with AI-service metadata when applicable."""
        try:
            from scapy.layers.inet import TCP
            from leetha.patterns.matching import match_http_ai_path, AI_PORT_HINTS
        except ImportError:
            return

        if TCP not in frame:
            return

        method = parsed.fields.get("method", "")
        path = parsed.fields.get("path", "")

        ai_match = match_http_ai_path(method, path)
        if ai_match:
            parsed.fields["ai_service"] = ai_match
            return

        # No path match -- fall back to port-based hints
        dport, sport = frame[TCP].dport, frame[TCP].sport
        known_ports = set(AI_PORT_HINTS.keys())
        if dport in known_ports:
            parsed.fields["ai_service"] = dict(AI_PORT_HINTS[dport])
        elif sport in known_ports:
            parsed.fields["ai_service"] = dict(AI_PORT_HINTS[sport])

    # ------------------------------------------------------------------
    # Async queue helper
    # ------------------------------------------------------------------

    def _enqueue(self, item: CapturedPacket) -> None:
        """Thread-safe push of a parsed packet into the asyncio queue."""
        loop = self._event_loop
        if loop is None or not loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(self._output.put(item), loop)
        except RuntimeError:
            pass  # event loop was closed during shutdown


# Backward-compatible alias so ``from leetha.capture.engine import CaptureEngine``
# keeps working throughout the migration period.
CaptureEngine = PacketCapture
