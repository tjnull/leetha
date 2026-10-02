"""Memory limits on capture data retained after ingestion."""

from leetha.capture.engine import PacketRingBuffer
from leetha.fingerprint.lookup import SignatureMatcher
from leetha.core.pipeline import Pipeline


def test_pcap_history_bounded_by_bytes_and_count():
    ring = PacketRingBuffer(max_packets=3, max_bytes=10)
    ring.append(b"aaaa")
    ring.append(b"bbbb")
    ring.append(b"cccc")
    assert list(ring) == [b"bbbb", b"cccc"]
    assert ring.bytes_used == 8
    ring.append(b"x" * 11)
    assert list(ring) == [b"bbbb", b"cccc"]


def test_huginn_compaction_preserves_useful_vendor_rows():
    data = {"entries": {
        "1": {"value": "MSFT", "vendor_hint": "Microsoft"},
        "2": {"value": "msft", "vendor_hint": "Microsoft", "model": "Windows"},
        "3": {"value": "unknown"},
    }}
    compact = SignatureMatcher._compact_cache("huginn_dhcp_vendor", data)
    assert len(compact["entries"]) == 1
    assert next(iter(compact["entries"].values()))["model"] == "Windows"


def test_huginn_devices_only_keep_referenced_profiles():
    data = {"entries": {
        "1": {"hierarchy": ["router"], "hierarchy_str": "router", "name": "x"},
        "2": {"hierarchy": ["printer"], "hierarchy_str": "printer"},
    }}
    compact = SignatureMatcher._compact_cache("huginn_devices", data, {"2"})
    assert compact == {"entries": {"2": {"hierarchy": ["printer"], "hierarchy_str": "printer"}}}


def test_lookup_signature_does_not_retain_wire_sized_strings():
    first = Pipeline._lookup_signature("service_banner", {"raw_banner": "a" * 20_000})
    second = Pipeline._lookup_signature("service_banner", {"raw_banner": "b" * 20_000})
    assert first != second
    assert max(len(part) for part in first) <= 256

    txt = Pipeline._lookup_signature("mdns", {"txt_records": {"blob": "x" * 20_000}})
    assert max(len(part) for part in txt) <= 256
