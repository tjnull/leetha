"""Integration tests for remote packet capture.

These tests verify the full flow from frame serialization
through the sensor manager and into the pipeline.
They do NOT require a real WebSocket connection — they test
the Python-side ingestion path directly.
"""
import pytest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from leetha.capture.remote.protocol import serialize_frame
from leetha.capture.remote.server import RemoteSensorManager


@pytest.fixture
def manager():
    return RemoteSensorManager()


def _make_arp_packet() -> bytes:
    """Create a minimal Ethernet frame."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / ARP()
    return bytes(pkt)


def test_sensor_receives_and_parses_frames(manager):
    session = manager.register("integration-test", "127.0.0.1")
    raw = _make_arp_packet()
    ts = 1_700_000_000_000_000_000

    frame_data = serialize_frame(raw, ts, 0)
    frames = session.feed(frame_data)

    assert len(frames) == 1
    # Verify the packet can be parsed by scapy
    pkt = Ether(frames[0].packet)
    assert pkt.src == "00:11:22:33:44:55"


def test_multiple_packets_streamed(manager):
    session = manager.register("multi-test", "127.0.0.1")
    packets = []
    stream = bytearray()

    for i in range(10):
        src_mac = f"00:11:22:33:44:{i:02x}"
        raw = bytes(Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / IP() / UDP())
        stream.extend(serialize_frame(raw, i * 1_000_000_000, 0))
        packets.append(src_mac)

    frames = session.feed(bytes(stream))
    assert len(frames) == 10

    for i, frame in enumerate(frames):
        pkt = Ether(frame.packet)
        assert pkt.src == packets[i]

    stats = session.stats()
    assert stats["packets"] == 10


def test_chunked_delivery(manager):
    """Simulate network fragmentation — data arrives in small chunks."""
    session = manager.register("chunk-test", "127.0.0.1")
    raw = _make_arp_packet()
    frame_data = serialize_frame(raw, 999, 0)

    all_frames = []
    chunk_size = 7  # Deliberately misaligned with header size
    for i in range(0, len(frame_data), chunk_size):
        chunk = frame_data[i : i + chunk_size]
        all_frames.extend(session.feed(chunk))

    assert len(all_frames) == 1
    pkt = Ether(all_frames[0].packet)
    assert pkt.src == "00:11:22:33:44:55"


def test_sensor_lifecycle(manager):
    """Register, stream, unregister, re-register."""
    session1 = manager.register("lifecycle", "10.0.0.1")
    raw = _make_arp_packet()
    session1.feed(serialize_frame(raw, 1000, 0))
    assert session1.stats()["packets"] == 1

    manager.unregister("lifecycle")
    assert "lifecycle" not in manager.sensors

    # Re-register — fresh session, counter reset
    session2 = manager.register("lifecycle", "10.0.0.2")
    assert session2.stats()["packets"] == 0
