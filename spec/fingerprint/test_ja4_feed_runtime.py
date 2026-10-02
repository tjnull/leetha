"""JA4 generated from captured TLS fields must match FoxIO feed keys."""

import json

from leetha.capture.tls_parser import parse_client_hello
from leetha.fingerprint.lookup import SignatureMatcher
from leetha.patterns.tls import compute_ja4


def test_foxio_published_ja4_example_matches_feed_key(tmp_path):
    # https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
    digest = compute_ja4(
        tls_version=0x0303,
        supported_versions=[0x0304, 0x0303],
        ciphers=[0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
        extensions=[0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017,
                    0x002D, 0x000D, 0x0005, 0x0023, 0x0012, 0x002B,
                    0xFF01, 0x000B, 0x000A, 0x0015],
        signature_algorithms=[0x0403, 0x0804, 0x0401, 0x0503,
                              0x0805, 0x0501, 0x0806, 0x0601],
        sni="example.com", alpn="h2",
    )
    assert digest == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    (tmp_path / "ja4.json").write_text(json.dumps({"entries": {
        digest: {"app": "Example Client", "os_family": "Linux"},
    }}))
    match = SignatureMatcher(tmp_path).match_ja4(digest)
    assert match is not None and match.os_family == "Linux"


def test_client_hello_exposes_ja4_version_and_signature_algorithms():
    def ext(kind, body):
        return kind.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    sni_name = b"example.com"
    sni = (len(sni_name) + 3).to_bytes(2, "big") + b"\x00" + len(sni_name).to_bytes(2, "big") + sni_name
    extensions = b"".join((
        ext(0, sni),
        ext(16, b"\x00\x03\x02h2"),
        ext(43, b"\x04\x03\x04\x03\x03"),
        ext(13, b"\x00\x04\x04\x03\x08\x04"),
    ))
    hello = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
             + b"\x01\x00" + len(extensions).to_bytes(2, "big") + extensions)
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    packet = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    parsed = parse_client_hello(packet)
    assert parsed is not None
    assert parsed.tls_version == 0x0303
    assert parsed.supported_versions == [0x0304, 0x0303]
    assert parsed.signature_algorithms == [0x0403, 0x0804]
    assert parsed.sni == "example.com"
    assert parsed.alpn == "h2"
