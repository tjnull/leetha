import asyncio
import struct
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from leetha.capture.remote.server import RemoteSensorManager, SensorSession
from leetha.capture.remote.protocol import serialize_frame


@pytest.fixture
def manager():
    return RemoteSensorManager()


async def test_register_sensor(manager):
    session = manager.register("pi-sensor", "192.168.1.50")
    assert session.name == "pi-sensor"
    assert session.remote_ip == "192.168.1.50"
    assert "pi-sensor" in manager.sensors


async def test_duplicate_sensor_rejected(manager):
    manager.register("pi-sensor", "192.168.1.50")
    with pytest.raises(ValueError, match="already connected"):
        manager.register("pi-sensor", "192.168.1.51")


async def test_unregister_sensor(manager):
    manager.register("pi-sensor", "192.168.1.50")
    manager.unregister("pi-sensor")
    assert "pi-sensor" not in manager.sensors


async def test_parse_frames_from_data(manager):
    session = manager.register("test", "10.0.0.1")
    raw_pkt = b"\xff" * 60
    ts = 1_000_000_000_000
    frame_data = serialize_frame(raw_pkt, ts, 0)

    frames = session.feed(frame_data)
    assert len(frames) == 1
    assert frames[0].packet == raw_pkt
    assert frames[0].timestamp_ns == ts


async def test_partial_frame_buffered(manager):
    session = manager.register("test", "10.0.0.1")
    raw_pkt = b"\xaa" * 100
    frame_data = serialize_frame(raw_pkt, 999, 0)

    # Feed first half
    frames1 = session.feed(frame_data[:30])
    assert len(frames1) == 0

    # Feed second half
    frames2 = session.feed(frame_data[30:])
    assert len(frames2) == 1
    assert frames2[0].packet == raw_pkt


async def test_sensor_stats(manager):
    session = manager.register("test", "10.0.0.1")
    raw_pkt = b"\xbb" * 60
    session.feed(serialize_frame(raw_pkt, 1000, 0))

    stats = session.stats()
    assert stats["packets"] == 1
    assert stats["bytes"] > 0
    assert stats["name"] == "test"


async def test_list_sensors(manager):
    manager.register("sensor-a", "10.0.0.1")
    manager.register("sensor-b", "10.0.0.2")
    names = [s["name"] for s in manager.list_sensors()]
    assert "sensor-a" in names
    assert "sensor-b" in names


def test_session_starts_idle():
    s = SensorSession(name="test", remote_ip="1.2.3.4")
    stats = s.stats()
    assert stats["state"] == "idle"
    assert stats["selected_interfaces"] == []
    assert stats["interface_stats"] == {}
    assert stats["interface_errors"] == {}


def test_session_set_capturing():
    s = SensorSession(name="test", remote_ip="1.2.3.4")
    s.set_state("capturing", ["eth0", "wlan0"])
    stats = s.stats()
    assert stats["state"] == "capturing"
    assert stats["selected_interfaces"] == ["eth0", "wlan0"]


def test_session_heartbeat_updates():
    s = SensorSession(name="test", remote_ip="1.2.3.4")
    s.update_heartbeat({"eth0": {"packets": 100, "bytes": 50000}})
    stats = s.stats()
    assert stats["interface_stats"]["eth0"]["packets"] == 100
    assert stats["last_heartbeat"] is not None


def test_session_capture_error():
    s = SensorSession(name="test", remote_ip="1.2.3.4")
    s.set_interface_error("wlan0", "permission denied")
    stats = s.stats()
    assert stats["interface_errors"]["wlan0"] == "permission denied"


def test_session_clear_errors_on_new_capture():
    s = SensorSession(name="test", remote_ip="1.2.3.4")
    s.set_interface_error("wlan0", "permission denied")
    s.set_state("capturing", ["eth0"])
    assert s.stats()["interface_errors"] == {}


def test_manager_heartbeat_stale():
    import time
    m = RemoteSensorManager()
    s = m.register("test", "1.2.3.4")
    s.set_state("capturing", ["eth0"])
    s.last_heartbeat = time.time() - 120
    stale = m.get_stale_sensors(timeout=90)
    assert len(stale) == 1
    assert stale[0].name == "test"
