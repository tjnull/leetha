"""Remote sensor session management and frame ingestion."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from leetha.capture.remote.protocol import (
    FRAME_HEADER_SIZE,
    RemotePacketFrame,
    deserialize_frame,
)
import struct


@dataclass
class SensorSession:
    name: str
    remote_ip: str
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float | None = field(default=None)
    _buffer: bytearray = field(default_factory=bytearray, repr=False)
    _packet_count: int = 0
    _byte_count: int = 0
    # Discovered interfaces on the remote device
    remote_interfaces: list[dict] = field(default_factory=list)
    # Currently selected capture interfaces
    selected_interfaces: list[str] = field(default_factory=list)
    # Current state: "idle" or "capturing"
    state: str = "idle"
    # Per-interface packet/byte stats from heartbeats
    interface_stats: dict[str, dict] = field(default_factory=dict)
    # Per-interface errors
    interface_errors: dict[str, str] = field(default_factory=dict)
    # WebSocket reference for sending control messages (set by listener)
    websocket: object | None = field(default=None, repr=False)

    def feed(self, data: bytes) -> list[RemotePacketFrame]:
        self._buffer.extend(data)
        frames: list[RemotePacketFrame] = []
        while len(self._buffer) >= FRAME_HEADER_SIZE:
            pkt_len = struct.unpack_from("!I", self._buffer, 0)[0]
            total = FRAME_HEADER_SIZE + pkt_len
            if len(self._buffer) < total:
                break
            frame = deserialize_frame(bytes(self._buffer[:total]))
            frames.append(frame)
            self._buffer = self._buffer[total:]
            self._packet_count += 1
            self._byte_count += pkt_len
        return frames

    def set_discovered_interfaces(self, interfaces: list[dict]) -> None:
        self.remote_interfaces = interfaces

    def set_state(self, state: str, interfaces: list[str] | None = None) -> None:
        self.state = state
        if interfaces is not None:
            self.selected_interfaces = interfaces
        if state == "capturing":
            self.interface_errors = {}

    def update_heartbeat(self, iface_stats: dict[str, dict]) -> None:
        self.last_heartbeat = time.time()
        self.interface_stats = iface_stats
        # Accumulate totals
        total_pkts = sum(s.get("packets", 0) for s in iface_stats.values())
        total_bytes = sum(s.get("bytes", 0) for s in iface_stats.values())
        self._packet_count = total_pkts
        self._byte_count = total_bytes

    def set_interface_error(self, interface: str, error: str) -> None:
        self.interface_errors[interface] = error

    def stats(self) -> dict:
        return {
            "name": self.name,
            "remote_ip": self.remote_ip,
            "connected_at": self.connected_at,
            "uptime": time.time() - self.connected_at,
            "packets": self._packet_count,
            "bytes": self._byte_count,
            "remote_interfaces": self.remote_interfaces,
            "selected_interfaces": self.selected_interfaces,
            "state": self.state,
            "interface_stats": self.interface_stats,
            "interface_errors": self.interface_errors,
            "last_heartbeat": self.last_heartbeat,
        }


class RemoteSensorManager:
    def __init__(self) -> None:
        self.sensors: dict[str, SensorSession] = {}

    def register(self, name: str, remote_ip: str) -> SensorSession:
        if name in self.sensors:
            raise ValueError(f"Sensor '{name}' already connected")
        session = SensorSession(name=name, remote_ip=remote_ip)
        self.sensors[name] = session
        return session

    def unregister(self, name: str) -> None:
        self.sensors.pop(name, None)

    def list_sensors(self) -> list[dict]:
        return [s.stats() for s in self.sensors.values()]

    def get_stale_sensors(self, timeout: float = 90) -> list[SensorSession]:
        """Return sensors whose last heartbeat is older than timeout seconds."""
        now = time.time()
        stale = []
        for s in self.sensors.values():
            if s.state == "capturing" and s.last_heartbeat is not None:
                if now - s.last_heartbeat > timeout:
                    stale.append(s)
        return stale

    def is_revoked(self, name: str, ca_dir) -> bool:
        from leetha.capture.remote.ca import list_certs
        try:
            certs = list_certs(ca_dir)
        except Exception:
            return True
        for c in certs:
            if c["name"] == name and not c["revoked"]:
                return False
        return True  # No valid cert found = rejected
