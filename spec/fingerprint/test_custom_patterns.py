"""Tests for custom pattern data model extensions."""
import json
import pytest
from pathlib import Path
from leetha.fingerprint.lookup import load_custom_patterns, save_custom_patterns


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path


def test_new_pattern_gets_hits_and_created_at(data_dir):
    patterns = {"hostname": [
        {"pattern": "*test*", "device_type": "Test", "manufacturer": "", "confidence": 80}
    ]}
    save_custom_patterns(data_dir, patterns)
    loaded = load_custom_patterns(data_dir)
    entry = loaded["hostname"][0]
    assert "hits" in entry
    assert entry["hits"] == 0
    assert "created_at" in entry


def test_existing_pattern_preserves_hits(data_dir):
    patterns = {"hostname": [
        {"pattern": "*test*", "device_type": "Test", "hits": 42, "created_at": "2026-01-01T00:00:00"}
    ]}
    save_custom_patterns(data_dir, patterns)
    loaded = load_custom_patterns(data_dir)
    assert loaded["hostname"][0]["hits"] == 42


def test_load_empty_returns_empty(data_dir):
    loaded = load_custom_patterns(data_dir)
    assert loaded == {}
