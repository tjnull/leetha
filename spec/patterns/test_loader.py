"""Tests for pattern data loader."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch
from leetha.patterns.loader import load, load_compiled, clear_cache, available_patterns, _DATA_DIR


@pytest.fixture(autouse=True)
def reset_cache():
    """Clear loader cache before each test."""
    clear_cache()
    yield
    clear_cache()


class TestLoad:
    def test_load_returns_data(self):
        """Loading a valid pattern file returns data."""
        # Only test if data files exist (Phase 3a creates them)
        if not (_DATA_DIR / "hostname.json").exists():
            pytest.skip("hostname.json not yet created")
        data = load("hostname")
        assert isinstance(data, list)
        assert len(data) > 0

    def test_load_caches_result(self):
        if not (_DATA_DIR / "hostname.json").exists():
            pytest.skip("hostname.json not yet created")
        data1 = load("hostname")
        data2 = load("hostname")
        assert data1 is data2  # same object from cache

    def test_load_missing_file_returns_empty(self):
        result = load("nonexistent_pattern_xyz")
        assert result == []

    def test_missing_required_dataset_reports_bundle_error(self, tmp_path):
        with patch("leetha.patterns.loader._DATA_DIR", tmp_path):
            with pytest.raises(FileNotFoundError, match="rebuild the executable"):
                load("mdns")

    def test_load_banners_returns_dict(self):
        if not (_DATA_DIR / "banners.json").exists():
            pytest.skip("banners.json not yet created")
        data = load("banners")
        assert isinstance(data, dict)

    def test_load_validates_structure(self, tmp_path):
        """Invalid data raises ValueError."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('"just a string"')
        with patch("leetha.patterns.loader._DATA_DIR", tmp_path):
            with pytest.raises(ValueError):
                load("bad")


class TestLoadCompiled:
    def test_compiled_patterns_have_regex(self):
        if not (_DATA_DIR / "hostname.json").exists():
            pytest.skip("hostname.json not yet created")
        compiled = load_compiled("hostname")
        assert len(compiled) > 0
        import re
        for pattern, metadata in compiled:
            assert isinstance(pattern, re.Pattern)
            assert isinstance(metadata, dict)

    def test_compiled_caches(self):
        if not (_DATA_DIR / "hostname.json").exists():
            pytest.skip("hostname.json not yet created")
        c1 = load_compiled("hostname")
        c2 = load_compiled("hostname")
        assert c1 is c2


class TestAvailablePatterns:
    def test_lists_json_files(self):
        patterns = available_patterns()
        assert isinstance(patterns, list)
        # At minimum, some patterns should exist after Phase 3a
        # If not yet created, this just returns what's available


class TestClearCache:
    def test_clear_forces_reload(self):
        if not (_DATA_DIR / "hostname.json").exists():
            pytest.skip("hostname.json not yet created")
        d1 = load("hostname")
        clear_cache()
        d2 = load("hostname")
        assert d1 is not d2  # different objects after cache clear
        assert d1 == d2      # but same data
