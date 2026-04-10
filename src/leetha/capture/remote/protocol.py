"""Binary wire protocol for remote sensor packet frames.

Frame layout (network byte order):
    4 bytes  — packet length (uint32)
    8 bytes  — timestamp in nanoseconds since Unix epoch (int64)
    4 bytes  — interface index (uint32)
    N bytes  — raw packet bytes (full L2 frame)

Total header: 16 bytes.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

FRAME_HEADER_FMT = "!IqI"  # uint32 + int64 + uint32
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FMT)  # 16


@dataclass(frozen=True, slots=True)
class RemotePacketFrame:
    length: int
    timestamp_ns: int
    interface_index: int
    packet: bytes


def serialize_frame(packet: bytes, timestamp_ns: int, interface_index: int) -> bytes:
    header = struct.pack(FRAME_HEADER_FMT, len(packet), timestamp_ns, interface_index)
    return header + packet


def deserialize_frame(data: bytes) -> RemotePacketFrame:
    if len(data) < FRAME_HEADER_SIZE:
        raise ValueError(
            f"incomplete frame header: got {len(data)} bytes, need {FRAME_HEADER_SIZE}"
        )
    length, ts_ns, iface_idx = struct.unpack_from(FRAME_HEADER_FMT, data)
    payload = data[FRAME_HEADER_SIZE:]
    if len(payload) < length:
        raise ValueError(
            f"incomplete frame payload: expected {length} bytes, got {len(payload)}"
        )
    return RemotePacketFrame(
        length=length,
        timestamp_ns=ts_ns,
        interface_index=iface_idx,
        packet=payload[:length],
    )
