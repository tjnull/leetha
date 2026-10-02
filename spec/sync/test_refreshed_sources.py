"""Exercise refreshed feed data through parsers and the actual matcher."""

import json
from types import SimpleNamespace

import pytest

from leetha.sync.parsers import (
    ingest_apple_devices, ingest_huginn_combinations,
    ingest_huginn_dhcp_vendor, ingest_oui,
)
from leetha.fingerprint.lookup import SignatureMatcher
from leetha.patterns.vendors import load_oui_data
from leetha.fingerprint.mac_intel import is_randomized_mac
from leetha.analysis.validator import _matching_oui
from leetha.sync import sync_source_with_progress


def _cache(path, name, entries):
    (path / f"{name}.json").write_text(json.dumps({"source": name, "entries": entries}))


def test_refreshed_oui_metadata_reaches_mac_matcher(tmp_path):
    csv = ("oui,manufacturer,short_name,device_type,registry,sources,"
           "registrant_raw,status,deregistered_date,registrant_history\n"
           "A036BC,Canonical Vendor,,router,MA-L,IEEE,Old Vendor,current,,Old Vendor\n")
    entries = ingest_oui(csv)
    assert entries["A0:36:BC"]["registrant_raw"] == "Old Vendor"
    _cache(tmp_path, "ieee_oui", entries)
    assert load_oui_data(tmp_path)["A0:36:BC"]["manufacturer"] == "Canonical Vendor"
    match = SignatureMatcher(tmp_path).match_mac("a0:36:bc:12:34:56")[0]
    assert match.manufacturer == "Canonical Vendor"
    assert match.raw_data["registration_status"] == "current"


def test_bridge_uses_match_quality_without_lean_signature(tmp_path):
    entries = ingest_huginn_combinations(json.dumps([
        {"dhcp_option55": "1,3,6", "satori_name": "Long April fallback name",
         "device_vendor": "Wrong", "device_match": "april-map"},
        {"dhcp_option55": "1,3,6", "satori_name": "Exact device",
         "device_vendor": "Correct", "device_match": "exact-name"},
    ]))
    _cache(tmp_path, "huginn_combinations", entries)
    matcher = SignatureMatcher(tmp_path)
    match = matcher._resolve_huginn_combo("1,3,6")
    assert match.manufacturer == "Correct"
    assert match.raw_data["device_match"] == "exact-name"
    assert all(hit.source != "huginn_dhcp" for hit in matcher.match_dhcp(opt55="1,3,6"))


def test_ignored_vendor_classes_are_not_indexed():
    rows = ingest_huginn_dhcp_vendor(json.dumps([
        {"id": 1, "value": "MSFT 5.0", "ignored": 0},
        {"id": 2, "value": "BadValue", "ignored": 1},
    ]))
    assert "1" in rows
    assert "2" not in rows


def test_dhcp_vendor_exact_index_keeps_best_duplicate(tmp_path):
    _cache(tmp_path, "huginn_dhcp_vendor", {
        "1": {"value": "MSFT 5.0"},
        "2": {"value": "MSFT 5.0", "vendor_hint": "Microsoft"},
    })
    matcher = SignatureMatcher(tmp_path)
    hit = matcher._resolve_huginn_dhcp_vendor("MSFT 5.0")
    assert hit.manufacturer == "Microsoft"
    assert len(matcher._dhcp_vendor_candidates()) == 1


def test_apple_feed_resolves_private_mac_model(tmp_path):
    entries = ingest_apple_devices(json.dumps([
        {"identifiers": ["iPhone15,2"], "name": "iPhone 14 Pro", "soc": "A16"}
    ]))
    _cache(tmp_path, "apple_devices", entries)
    hits = SignatureMatcher(tmp_path).match_mdns_service(
        "_device-info._tcp", packet_data={"apple_model": "iPhone15,2"})
    apple = next(hit for hit in hits if hit.model == "iPhone 14 Pro")
    assert apple.manufacturer == "Apple"
    assert apple.raw_data["soc"] == "A16"


def test_randomized_mac_checks_separator_variants():
    assert is_randomized_mac("da:5e:7d:bb:28:1b")
    assert is_randomized_mac("da-5e-7d-bb-28-1b")
    assert is_randomized_mac("da5e.7dbb.281b")
    assert not is_randomized_mac("invalid")


def test_validation_uses_most_specific_oui_block():
    table = {"A036BC": {"vendor": "Broad"},
             "A036BC123": {"vendor": "Specific"}}
    assert _matching_oui("a0:36:bc:12:34:56", table)[1]["vendor"] == "Specific"


@pytest.mark.asyncio
async def test_empty_refresh_keeps_previous_cache(tmp_path, monkeypatch):
    import leetha.config
    import leetha.sync.downloader

    old = '{"source":"apple_devices","entries":{"iPhone15,2":{"name":"iPhone"}}}'
    cache = tmp_path / "apple_devices.json"
    cache.write_text(old)
    monkeypatch.setattr(leetha.config, "get_config",
                        lambda: SimpleNamespace(cache_dir=tmp_path))

    async def empty_download(*args, **kwargs):
        kwargs["dest_file"].write(b"[]")
        yield {"stage": "done", "downloaded": 2}

    monkeypatch.setattr(leetha.sync.downloader, "download_with_progress", empty_download)
    events = [event async for event in sync_source_with_progress("apple_devices")]
    assert events[-1]["event"] == "error"
    assert cache.read_text() == old
