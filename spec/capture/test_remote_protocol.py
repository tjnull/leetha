import struct
import time
import pytest
from leetha.capture.remote.protocol import (
    FRAME_HEADER_SIZE,
    serialize_frame,
    deserialize_frame,
    RemotePacketFrame,
)


def test_frame_header_size_is_16():
    assert FRAME_HEADER_SIZE == 16


def test_round_trip_simple_packet():
    raw = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00" + b"\x00" * 46
    ts_ns = int(time.time() * 1e9)
    iface_idx = 0

    data = serialize_frame(raw, ts_ns, iface_idx)
    frame = deserialize_frame(data)

    assert frame.packet == raw
    assert frame.timestamp_ns == ts_ns
    assert frame.interface_index == iface_idx
    assert frame.length == len(raw)


def test_deserialize_truncated_raises():
    with pytest.raises(ValueError, match="incomplete"):
        deserialize_frame(b"\x00" * 10)


def test_deserialize_length_mismatch_raises():
    # Header says 100 bytes but only 10 follow
    header = struct.pack("!IqI", 100, 0, 0)
    with pytest.raises(ValueError, match="expected 100"):
        deserialize_frame(header + b"\x00" * 10)


def test_multiple_frames_from_stream():
    raw1 = b"\xaa" * 60
    raw2 = b"\xbb" * 120
    ts1 = 1_000_000_000
    ts2 = 2_000_000_000

    stream = serialize_frame(raw1, ts1, 0) + serialize_frame(raw2, ts2, 1)

    frame1 = deserialize_frame(stream[:FRAME_HEADER_SIZE + 60])
    frame2 = deserialize_frame(stream[FRAME_HEADER_SIZE + 60:])

    assert frame1.packet == raw1
    assert frame1.interface_index == 0
    assert frame2.packet == raw2
    assert frame2.interface_index == 1
