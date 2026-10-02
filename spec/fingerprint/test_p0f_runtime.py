"""p0f's native signatures must match fields emitted by TCP capture."""

import json

from leetha.fingerprint.lookup import SignatureMatcher


def _fields(**updates):
    fields = {
        "tcp_flags": "S", "tcp_flags_int": 2,
        "ttl": 64, "ip_options_len": 0, "ip_id": 1, "df": 1,
        "mss": 1460, "window_size": 29200, "window_scale": 10,
        "p0f_options": "mss,sok,ts,nop,ws", "tcp_payload_len": 0,
        "tcp_seq": 123, "tcp_ack": 0, "tcp_urgptr": 0,
        "tcp_timestamps": (123, 0),
    }
    fields.update(updates)
    return fields


def test_native_p0f_request_match_and_quirk_guard(tmp_path):
    signature = "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0"
    (tmp_path / "p0f.json").write_text(json.dumps({"entries": [
        {"signature": signature, "class": "tcp:request",
         "os_family": "Linux", "os_version": "3.11 and newer"},
    ]}))
    matcher = SignatureMatcher(tmp_path)
    hit = matcher.match_p0f_packet(_fields())
    assert hit is not None and hit.os_family == "Linux"
    assert matcher.match_p0f_packet(_fields(df=0)) is None
    assert matcher.match_p0f_packet(_fields(tcp_flags="SA", tcp_flags_int=18)) is None


def test_ambiguous_p0f_os_is_not_attributed(tmp_path):
    signature = "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0"
    (tmp_path / "p0f.json").write_text(json.dumps({"entries": [
        {"signature": signature, "class": "tcp:request", "os_family": "Linux"},
        {"signature": signature, "class": "tcp:request", "os_family": "FreeBSD"},
    ]}))
    assert SignatureMatcher(tmp_path).match_p0f_packet(_fields()) is None
