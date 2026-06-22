"""Rapid7 Recog sync source: XML parsing + banner matching."""

import json
import pytest

from leetha.sync.parsers import ingest_recog
from leetha.sync import MULTIFILE_MANIFESTS, PARSER_MAP
from leetha.sync.registry import FeedCatalog
from leetha.fingerprint.lookup import SignatureMatcher

_SAMPLE = """<?xml version='1.0' encoding='UTF-8'?>
<fingerprints matches="ssh.banner" protocol="ssh">
  <fingerprint pattern="^RomSShell_([\\d.]+)$">
    <description>Allegro RomSShell SSH</description>
    <param pos="0" name="service.vendor" value="Allegro Software"/>
    <param pos="0" name="service.product" value="RomSShell"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
"""


def test_recog_feed_registered_with_manifest():
    cat = FeedCatalog()
    feed = cat.lookup("recog")
    assert feed is not None and feed.kind == "git_multifile"
    assert feed.endpoint.endswith("/")            # multifile base dir
    assert PARSER_MAP["recog"] == "parse_recog"
    assert MULTIFILE_MANIFESTS["recog"]           # non-empty manifest
    assert all(f.endswith(".xml") for f in MULTIFILE_MANIFESTS["recog"])


def test_ingest_recog_parses_fingerprints():
    out = ingest_recog(_SAMPLE)
    assert "ssh.banner" in out
    fps = out["ssh.banner"]
    assert len(fps) == 1
    assert fps[0]["pattern"].startswith("^RomSShell")
    names = {p["name"] for p in fps[0]["params"]}
    assert {"service.vendor", "service.product", "service.version"} <= names


def test_ingest_recog_bad_xml_is_safe():
    assert ingest_recog("<not valid xml") == {}


def _matcher_with_cache(tmp_path):
    (tmp_path / "recog.json").write_text(json.dumps({"source": "recog", "entries": {
        "ssh.banner": [{
            "pattern": r"^RomSShell_([\d.]+)$", "description": "Allegro",
            "params": [
                {"pos": 0, "name": "service.vendor", "value": "Allegro Software"},
                {"pos": 1, "name": "service.version", "value": None},
            ],
        }],
        "http_header.server": [{
            "pattern": r"^Microsoft-IIS/([\d.]+)$", "description": "IIS on Windows",
            "params": [
                {"pos": 0, "name": "service.vendor", "value": "Microsoft"},
                {"pos": 0, "name": "os.product", "value": "Windows"},
            ],
        }],
    }}), encoding="utf-8")
    return SignatureMatcher(tmp_path)


def test_match_recog_extracts_vendor_and_capture_group(tmp_path):
    m = _matcher_with_cache(tmp_path)
    r = m.match_recog("ssh", "RomSShell_4.62")
    assert r is not None
    assert r.source == "recog"
    assert r.manufacturer == "Allegro Software"
    assert (r.raw_data or {}).get("version") == "4.62"  # from capture group


def test_match_recog_http_server_maps_os(tmp_path):
    m = _matcher_with_cache(tmp_path)
    r = m.match_recog("http", "Microsoft-IIS/10.0")
    assert r is not None
    assert r.manufacturer == "Microsoft"
    assert r.os_family == "Windows"


def test_match_recog_misses_and_unknown_kind(tmp_path):
    m = _matcher_with_cache(tmp_path)
    assert m.match_recog("ssh", "something-not-matching") is None
    assert m.match_recog("nonexistent-kind", "x") is None
    assert m.match_recog("ssh", "") is None
