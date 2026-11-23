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
    csv = ("\ufeffmanufacturer,oui,short_name,device_type,registry,sources,"
           "registrant_raw,status,deregistered_date,registrant_history\n"
           "Canonical Vendor,A036BC,,Access Point,MA-L,IEEE,Old Vendor,current,,Old Vendor\n"
           "Historical Vendor,A036BC123,,,MA-S,Nmap,Historical Vendor,legacy,,\n")
    entries = ingest_oui(csv)
    assert entries["A0:36:BC"]["registrant_raw"] == "Old Vendor"
    _cache(tmp_path, "ieee_oui", entries)
    assert load_oui_data(tmp_path)["A0:36:BC"]["manufacturer"] == "Canonical Vendor"
    match = SignatureMatcher(tmp_path).match_mac("a0:36:bc:12:34:56")[0]
    assert match.manufacturer == "Historical Vendor"
    assert match.raw_data["registration_status"] == "legacy"
    assert match.confidence < .95
    match = SignatureMatcher(tmp_path).match_mac("a036.bc45.6789")[0]
    assert (match.manufacturer, match.device_type) == ("Canonical Vendor", "access_point")
    assert match.raw_data["registration_status"] == "current"
    assert match.raw_data["registrant_history"] == "Old Vendor"
    assert match.raw_data["registry"] == "MA-L"
    assert match.raw_data["sources"] == "IEEE"


async def test_registry_placeholder_preserves_match_and_yields_to_behavior(tmp_path):
    from leetha.capture.packets import CapturedPacket
    from leetha.core.pipeline import Pipeline
    from leetha.evidence.models import Evidence
    from leetha.fingerprint.evidence import FingerprintMatch, aggregate_evidence
    from leetha.store.store import Store

    _cache(tmp_path, "ieee_oui", ingest_oui(
        "oui,manufacturer,registry,device_type,status\n"
        "8C:1F:64,IEEE Registration Authority,MA-L,Router,current\n"
        "8C:1F:64:00:5,H Nu Pty Ltd,MA-S,,current\n"
    ))
    matcher = SignatureMatcher(tmp_path)
    mac = "8c:1f:64:ff:ff:ff"
    match = matcher.match_mac(mac)[0]
    assert match.manufacturer is None and match.device_type is None
    assert match.raw_data["registry_only"] is True
    assert match.raw_data["registrant_raw"] == "IEEE Registration Authority"
    assert matcher.match_mac("8c:1f:64:00:50:00")[0].manufacturer == "H Nu Pty Ltd"

    behavior = FingerprintMatch(source="ssdp", match_type="exact", confidence=.8,
                                manufacturer="Acme", device_type="camera")
    assert aggregate_evidence([match])["confidence"] == 0
    assert aggregate_evidence([match, behavior])["confidence"] == aggregate_evidence([behavior])["confidence"]

    store = Store(tmp_path / "test.db")
    await store.initialize()
    try:
        pipeline = Pipeline(store, lookup=matcher)
        packet = CapturedPacket(protocol="arp", hw_addr=mac, ip_addr="192.168.1.10")
        await pipeline.process(packet)
        verdict = await store.verdicts.find_by_addr(mac)
        assert not verdict.is_classified
        assert verdict.certainty == 0
        assert verdict.evidence_chain[0].raw["registry_only"]
        assert mac not in pipeline._gateway_macs
        assert mac not in pipeline._oui_vendors

        pipeline._processor_instances["arp"] = SimpleNamespace(analyze=lambda packet: [
            Evidence(source="ssdp", method="exact", certainty=.8, vendor="Acme", category="camera")
        ])
        await pipeline.process(packet)
        verdict = await store.verdicts.find_by_addr(mac)
        assert (verdict.vendor, verdict.category) == ("Acme", "camera")
        assert any(ev.raw.get("registry_only") for ev in verdict.evidence_chain)
    finally:
        await store.close()


async def test_store_repairs_saved_placeholder_verdicts_on_upgrade(tmp_path):
    from leetha.evidence.models import Evidence, Verdict
    from leetha.store.store import Store

    path = tmp_path / "test.db"
    mac = "8c:1f:64:ff:ff:ff"
    placeholder = "IEEE Registration Authority"
    store = Store(path)
    await store.initialize()
    try:
        await store.connection.execute(
            "DELETE FROM leetha_migrations WHERE name = 'oui_registry_placeholders_v1'",
        )
        await store.verdicts.upsert(Verdict(
            mac, category="router", vendor=placeholder, certainty=85, evidence_chain=[
                Evidence("oui", "exact", .95, category="router", vendor=placeholder,
                         raw={"registry": "MA-L"}),
                Evidence("ssdp", "exact", .8, category="camera", vendor="Acme"),
            ],
        ))
        identity = await store.identities.find_or_create(mac)
        identity.manufacturer = placeholder
        await store.identities.update(identity)
    finally:
        await store.close()

    store = Store(path)
    await store.initialize()
    try:
        verdict = await store.verdicts.find_by_addr(mac)
        assert (verdict.vendor, verdict.category) == ("Acme", "camera")
        oui = next(ev for ev in verdict.evidence_chain if ev.source == "oui")
        assert oui.vendor is None and oui.category is None
        assert oui.raw == {"registry": "MA-L", "registry_only": True, "registrant_raw": placeholder}
        assert (await store.identities.find_by_mac(mac)).manufacturer == "Acme"
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_oui_sync_refreshes_pipeline_and_preserves_cache_on_bad_csv(tmp_path, monkeypatch):
    import leetha.config
    import leetha.sync.downloader
    from leetha.capture.packets import CapturedPacket
    from leetha.core.pipeline import Pipeline
    from leetha.store.store import Store
    from leetha.ui.web.app import api_sync_sources

    monkeypatch.setattr(leetha.config, "get_config", lambda: SimpleNamespace(cache_dir=tmp_path))
    csv = b"oui,manufacturer,device_type,registry,status\n00:35:A9,Current Vendor,Access Point,MA-L,current\n"

    async def download(*args, **kwargs):
        kwargs["dest_file"].write(csv)
        yield {"stage": "done", "downloaded": len(csv), "etag": '"snapshot-1"'}

    monkeypatch.setattr(leetha.sync.downloader, "download_with_progress", download)
    store = Store(tmp_path / "test.db")
    await store.initialize()
    try:
        matcher = SignatureMatcher(tmp_path)
        pipeline = Pipeline(store, lookup=matcher)
        mac = "00:35:a9:00:00:01"
        pkt = CapturedPacket(protocol="tcp_syn", hw_addr=mac, ip_addr="8.8.8.8",
                             network="192.168.1.0/24", fields={"ttl": 43})
        await pipeline.process(pkt)
        assert mac not in pipeline._gateway_macs

        events = [event async for event in sync_source_with_progress("ieee_oui")]
        assert events[-1]["event"] == "complete"
        cache = tmp_path / "ieee_oui.json"
        freshness = json.loads(cache.read_text())["sync"]
        assert freshness["entry_count"] == 1
        assert freshness["upstream_etag"] == '"snapshot-1"'
        sources = (await api_sync_sources())["sources"]
        assert next(s for s in sources if s["name"] == "ieee_oui")["freshness"] == freshness
        matcher._next_oui_check = 0
        await pipeline.process(pkt)
        verdict = await store.verdicts.find_by_addr(mac)
        assert mac in pipeline._gateway_macs
        assert verdict.category == "access_point"
        assert verdict.vendor == "Current Vendor"
        assert verdict.evidence_chain[0].raw["registry"] == "MA-L"

        previous = cache.read_bytes()
        csv += b'02:42:00,"unterminated'
        events = [event async for event in sync_source_with_progress("ieee_oui")]
        assert events[-1]["event"] == "error"
        assert cache.read_bytes() == previous

        csv = b"oui,manufacturer,device_type,registry,status\n00:35:A9,Historical Vendor,Router,MA-L,deregistered\n"
        events = [event async for event in sync_source_with_progress("ieee_oui")]
        assert events[-1]["event"] == "complete"
        matcher._next_oui_check = 0
        await pipeline.process(pkt)
        verdict = await store.verdicts.find_by_addr(mac)
        assert mac not in pipeline._gateway_macs
        assert mac not in pipeline._oui_vendors
        assert [e.vendor for e in verdict.evidence_chain if e.source == "oui"] == ["Historical Vendor"]
    finally:
        await store.close()


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
    assert _matching_oui("a0:36:bc", table) is None
    assert _matching_oui("11:22:33:44:55:66", {"112233": {"vendor": "Group"}}) is None


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
