"""Tests for sensor config persistence."""
import pytest
from pathlib import Path
from leetha.capture.remote.config import SensorConfigStore


@pytest.fixture
def store(tmp_path):
    return SensorConfigStore(tmp_path / "sensor_config.json")


def test_save_and_load(store):
    store.save_interfaces("test-sensor", ["eth0", "wlan0"])
    result = store.load_interfaces("test-sensor")
    assert result == ["eth0", "wlan0"]


def test_load_unknown_sensor(store):
    result = store.load_interfaces("unknown")
    assert result is None


def test_overwrite_existing(store):
    store.save_interfaces("test-sensor", ["eth0"])
    store.save_interfaces("test-sensor", ["wlan0"])
    assert store.load_interfaces("test-sensor") == ["wlan0"]


def test_delete(store):
    store.save_interfaces("test-sensor", ["eth0"])
    store.delete("test-sensor")
    assert store.load_interfaces("test-sensor") is None


def test_multiple_sensors(store):
    store.save_interfaces("sensor-a", ["eth0"])
    store.save_interfaces("sensor-b", ["wlan0"])
    assert store.load_interfaces("sensor-a") == ["eth0"]
    assert store.load_interfaces("sensor-b") == ["wlan0"]
