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
    _buffer: bytearray = field(default_factory=bytearray, repr=False)
    _packet_count: int = 0
    _byte_count: int = 0

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

    def stats(self) -> dict:
        return {
            "name": self.name,
            "remote_ip": self.remote_ip,
            "connected_at": self.connected_at,
            "uptime": time.time() - self.connected_at,
            "packets": self._packet_count,
            "bytes": self._byte_count,
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

    def is_revoked(self, name: str, ca_dir) -> bool:
        from leetha.capture.remote.ca import list_certs
        try:
            certs = list_certs(ca_dir)
        except Exception:
            return True
        for c in certs:
            if c["name"] == name:
                return c["revoked"]
        return True  # Unknown cert = rejected
