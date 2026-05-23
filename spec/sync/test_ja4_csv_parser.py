"""JA4 feed parsing.

The original feed (ja4db.com/api/read/) went offline — the host stopped
accepting TCP connections, so sync hung until timeout and failed. We
switched to FoxIO's official GitHub mirror ``ja4plus-mapping.csv``,
which is a CSV with columns:

    Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes

``ingest_ja4_csv`` must produce the SAME lookup structure the old JSON
parser did, so the consumer (`FingerprintLookup.match_ja4`, which reads
``entries[fp] -> {os_family, app, description}``) keeps working:

    {fingerprint_value: {"app", "os_family", "fp_type", "description", "user_agent"}}
"""

from leetha.sync.parsers import ingest_ja4_csv


SAMPLE_CSV = (
    "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes\n"
    # Library-only row, ja4 populated
    ",Python,,,t13i181000_85036bcba153_d41ae481755e,,,,,,\n"
    # Application + ja4
    "Chromium Browser,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,Chrome on desktop\n"
    # ja4s (server) fingerprint row
    ",,,,,t130200_1301_234ea6891581,,,,,TLS 1.3 server\n"
    # Device-only label, ja4h
    ",,SomeIoT,Linux,,,ge11nn060000_8daaf6152771,,,,IoT device\n"
    # Blank/garbage row (no fingerprints) — must be skipped, not crash
    ",,,,,,,,,,\n"
)


def test_ja4_csv_maps_each_fingerprint_column():
    table = ingest_ja4_csv(SAMPLE_CSV)
    # 4 distinct fingerprints across ja4/ja4s/ja4h columns
    assert "t13i181000_85036bcba153_d41ae481755e" in table
    assert "t13d1516h2_8daaf6152771_02713d6af862" in table
    assert "t130200_1301_234ea6891581" in table
    assert "ge11nn060000_8daaf6152771" in table
    assert len(table) == 4


def test_ja4_csv_record_shape_matches_consumer():
    table = ingest_ja4_csv(SAMPLE_CSV)
    rec = table["t13d1516h2_8daaf6152771_02713d6af862"]
    # keys the consumer relies on
    assert rec["app"] == "Chromium Browser"
    assert rec["fp_type"] == "ja4"
    assert rec["description"] == "Chrome on desktop"
    assert "os_family" in rec


def test_ja4_csv_label_fallback_library_then_device():
    table = ingest_ja4_csv(SAMPLE_CSV)
    # Library used when Application empty
    assert table["t13i181000_85036bcba153_d41ae481755e"]["app"] == "Python"
    # Device used when Application and Library empty; OS captured
    dev = table["ge11nn060000_8daaf6152771"]
    assert dev["app"] == "SomeIoT"
    assert dev["os_family"] == "Linux"
    assert dev["fp_type"] == "ja4h"


def test_ja4_csv_fp_type_from_column():
    table = ingest_ja4_csv(SAMPLE_CSV)
    assert table["t130200_1301_234ea6891581"]["fp_type"] == "ja4s"


def test_ja4_csv_empty_or_garbage_is_safe():
    assert ingest_ja4_csv("") == {}
    assert ingest_ja4_csv("not,a,real,header\n1,2,3,4\n") == {}
    # header only, no rows
    assert ingest_ja4_csv(
        "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes\n"
    ) == {}
