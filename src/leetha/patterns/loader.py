"""Pattern data loader with validation and caching.

Loads fingerprint patterns from JSON data files, validates their structure,
pre-compiles regex patterns, and caches results for fast repeated access.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from threading import Lock

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_cache: dict[str, list | dict] = {}
_compiled_patterns: dict[str, list[tuple[re.Pattern, dict]]] = {}
_lock = Lock()
_REQUIRED_DATASETS = frozenset({
    "banners", "dhcp_opt55", "dhcp_opt60", "dhcpv6",
    "hostname", "icmpv6", "mdns", "ssdp",
})


def load(name: str) -> list | dict:
    """Load a pattern dataset by name, with caching.

    Args:
        name: Pattern file name without extension (e.g. "hostname", "banners")

    Returns:
        Parsed JSON data (list or dict depending on the pattern type)
    """
    with _lock:
        if name in _cache:
            return _cache[name]

    path = _DATA_DIR / f"{name}.json"
    if not path.exists():
        if name in _REQUIRED_DATASETS:
            raise FileNotFoundError(
                f"Required Leetha pattern data is missing: {path}. "
                "Reinstall Leetha or rebuild the executable with package data."
            )
        logger.warning("Pattern file not found: %s", path)
        return [] if name != "banners" else {}

    data = json.loads(path.read_text(encoding="utf-8"))
    _validate(name, data)

    with _lock:
        _cache[name] = data

    return data


def load_compiled(name: str) -> list[tuple[re.Pattern, dict]]:
    """Load patterns with pre-compiled regexes.

    Returns list of (compiled_regex, metadata_dict) tuples for fast matching.
    """
    with _lock:
        if name in _compiled_patterns:
            return _compiled_patterns[name]

    raw = load(name)
    compiled = []

    entries = raw if isinstance(raw, list) else []
    for entry in entries:
        match_str = entry.get("match", "")
        if match_str:
            try:
                pattern = re.compile(match_str, re.IGNORECASE)
                compiled.append((pattern, entry))
            except re.error:
                logger.warning("Invalid regex in %s: %s", name, match_str)

    with _lock:
        _compiled_patterns[name] = compiled

    return compiled


def clear_cache() -> None:
    """Clear all cached data (useful for testing and reloading)."""
    with _lock:
        _cache.clear()
        _compiled_patterns.clear()


def available_patterns() -> list[str]:
    """List all available pattern datasets."""
    if not _DATA_DIR.exists():
        return []
    return sorted(p.stem for p in _DATA_DIR.glob("*.json"))


def _validate(name: str, data: list | dict) -> None:
    """Basic structural validation of loaded pattern data."""
    if isinstance(data, list):
        for i, entry in enumerate(data):
            if not isinstance(entry, dict):
                raise ValueError(f"{name}[{i}]: expected dict, got {type(entry).__name__}")
            if "match" not in entry and "key" not in entry and "pattern" not in entry:
                # Some patterns use "key" instead of "match" (e.g. DHCP opt55)
                pass  # Not all entries need a match field
    elif isinstance(data, dict):
        pass  # Dict-based patterns (banners, mdns services) are valid
    else:
        raise ValueError(f"{name}: expected list or dict, got {type(data).__name__}")
