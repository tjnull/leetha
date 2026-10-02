"""Regressions for defects found during the source/pipeline audit.

Each test pins behaviour that was silently wrong before: parsers being
skipped on PCAP import, enterprise IDs resolving to the wrong vendor,
Recog patterns never matching framed banners, and OT banner extraction
reading a field the passive path never sets.
"""
from __future__ import annotations

import json
import os

import pytest

from leetha.capture.packets import CapturedPacket
from leetha.fingerprint.lookup import SignatureMatcher
from leetha.import_pcap import _classify_frame
from leetha.processors.banner import BannerProcessor


# ---------------------------------------------------------------------------
# PCAP import: an empty list means "no match", not "matched nothing"
# ---------------------------------------------------------------------------

def test_classify_frame_skips_parsers_returning_empty_list(monkeypatch):
    """A list-returning parser that yields [] must not stop the chain.

    parse_dns_answer returns [] for every non-DNS-answer packet. It sits
    16th of 38 in PARSER_CHAIN, so treating [] as a result made the 22
    parsers after it (mDNS, SSDP, all OT/ICS, service banners,
    ip_observed) unreachable for PCAP import.
    """
    sentinel = CapturedPacket(protocol="mdns", hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="10.0.0.9")

    def empty_list_parser(_frame):
        return []

    def real_parser(_frame):
        return sentinel

    monkeypatch.setattr(
        "leetha.import_pcap.PARSER_CHAIN", [empty_list_parser, real_parser]
    )

    result = _classify_frame(object(), "pcap:test.pcap")
    assert result is sentinel
    assert result.interface == "pcap:test.pcap"


def test_classify_frame_returns_none_when_nothing_matches(monkeypatch):
    monkeypatch.setattr(
        "leetha.import_pcap.PARSER_CHAIN", [lambda _f: [], lambda _f: None]
    )
    assert _classify_frame(object(), "pcap:test.pcap") is None


def test_classify_frame_keeps_non_empty_lists(monkeypatch):
    pkts = [
        CapturedPacket(protocol="dns", hw_addr="aa:bb:cc:dd:ee:01", ip_addr="10.0.0.1"),
        CapturedPacket(protocol="dns", hw_addr="aa:bb:cc:dd:ee:02", ip_addr="10.0.0.2"),
    ]
    monkeypatch.setattr("leetha.import_pcap.PARSER_CHAIN", [lambda _f: pkts])

    result = _classify_frame(object(), "pcap:x.pcap")
    assert result == pkts
    assert all(p.interface == "pcap:x.pcap" for p in result)


# ---------------------------------------------------------------------------
# DHCPv6 enterprise IDs
# ---------------------------------------------------------------------------

@pytest.fixture
def enterprise_cache(tmp_path):
    """The official IANA feed maps enterprise numbers directly to names."""
    (tmp_path / "iana_enterprise.json").write_text(json.dumps({
        "source": "iana_enterprise",
        # parse_iana_enterprise emits plain strings, not dicts
        "entries": {"9": "ciscoSystems", "311": "Microsoft"},
    }))
    return tmp_path


def test_dhcpv6_enterprise_resolves_from_iana(enterprise_cache):
    """The official registry supplies the device's manufacturer."""
    matcher = SignatureMatcher(enterprise_cache)
    hits = matcher.match_dhcpv6(enterprise_id=311)
    assert any(hit.source == "iana_enterprise" and hit.manufacturer == "Microsoft"
               for hit in hits)


def test_dhcpv6_enterprise_misses_unknown_number(enterprise_cache):
    matcher = SignatureMatcher(enterprise_cache)
    assert not any(hit.source == "iana_enterprise"
                   for hit in matcher.match_dhcpv6(enterprise_id=999999))


def test_iana_enterprise_accepts_plain_string_entries(enterprise_cache):
    """The IANA feed maps id -> name; calling .get() on it used to raise."""
    matcher = SignatureMatcher(enterprise_cache)
    hit = matcher._resolve_iana_enterprise(9)
    assert hit is not None
    assert hit.manufacturer == "ciscoSystems"


def test_iana_lookup_failure_does_not_discard_other_dhcpv6_evidence(enterprise_cache):
    """A crash in the IANA fallback used to drop every hit collected so far."""
    matcher = SignatureMatcher(enterprise_cache)
    hits = matcher.match_dhcpv6(oro="23,24,17,39", enterprise_id=999999)
    # Must not raise, and the ORO evidence must survive.
    assert any(h.source == "dhcpv6" for h in hits)


# ---------------------------------------------------------------------------
# Recog banner framing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind,raw,expected", [
    ("ssh", "SSH-2.0-OpenSSH_8.4p1 Debian-5", "OpenSSH_8.4p1 Debian-5"),
    ("ftp", "220 ProFTPD 1.3.5 Server", "ProFTPD 1.3.5 Server"),
    ("smtp", "220 mail.example.com ESMTP Postfix", "mail.example.com ESMTP Postfix"),
    ("pop3", "+OK Dovecot ready.", "Dovecot ready."),
    ("imap", "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "Dovecot ready."),
    ("http", "Apache/2.4.41 (Ubuntu)", "Apache/2.4.41 (Ubuntu)"),
])
def test_strip_banner_framing(kind, raw, expected):
    assert SignatureMatcher._strip_banner_framing(kind, raw) == expected


def test_strip_banner_framing_drops_trailing_crlf():
    got = SignatureMatcher._strip_banner_framing("ssh", "SSH-2.0-OpenSSH_9.2p1\r\n")
    assert got == "OpenSSH_9.2p1"


def test_recog_matches_framed_banner(tmp_path):
    """Recog anchors on the stripped payload, so the raw banner must be cleaned."""
    (tmp_path / "recog.json").write_text(json.dumps({
        "source": "recog",
        "entries": {
            "ssh.banner": [{
                "pattern": r"^OpenSSH_([\d.]+p\d+) Debian-(\d+)$",
                "params": [
                    {"pos": 0, "name": "service.vendor", "value": "OpenBSD"},
                    {"pos": 0, "name": "service.product", "value": "OpenSSH"},
                    {"pos": 1, "name": "service.version", "value": None},
                ],
                "description": "OpenSSH on Debian",
            }],
        },
    }))
    matcher = SignatureMatcher(tmp_path)

    hit = matcher.match_recog("ssh", "SSH-2.0-OpenSSH_8.4p1 Debian-5")
    assert hit is not None
    assert hit.manufacturer == "OpenBSD"
    assert hit.model == "OpenSSH"
    assert hit.raw_data["version"] == "8.4p1"

    # An already-stripped banner must keep working.
    assert matcher.match_recog("ssh", "OpenSSH_8.4p1 Debian-5") is not None


# ---------------------------------------------------------------------------
# Passive banner OT extraction
# ---------------------------------------------------------------------------

def test_ot_identity_extracted_from_raw_banner():
    """The passive path sets raw_banner; reading only "banner" found nothing."""
    packet = CapturedPacket(
        protocol="service_banner",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="10.0.0.5",
        fields={
            "service": "telnet",
            "software": "",
            "version": None,
            "server_port": 23,
            "raw_banner": "SEL-351-7 FID=SEL-351-7-R107-V0-Z002002-D20130514",
        },
    )
    evidence = BannerProcessor().analyze(packet)
    assert any(e.category == "ics_device" and e.vendor == "SEL" for e in evidence)


def test_ot_identity_still_read_from_banner_field():
    """The active-probe path uses "banner" -- keep supporting it."""
    packet = CapturedPacket(
        protocol="service_banner",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="10.0.0.5",
        fields={"service": "telnet", "banner": "SEL-351-7 FID=SEL-351-7-R107"},
    )
    evidence = BannerProcessor().analyze(packet)
    assert any(e.category == "ics_device" for e in evidence)


# ---------------------------------------------------------------------------
# DHCP vendor-class matching
# ---------------------------------------------------------------------------

def test_dhcp_vendor_longest_match_wins_and_is_memoised(tmp_path):
    (tmp_path / "huginn_dhcp_vendor.json").write_text(json.dumps({
        "source": "huginn_dhcp_vendor",
        "entries": {
            "1": {"value": "MSFT", "vendor_hint": "Microsoft"},
            "2": {"value": "MSFT 5.0", "vendor_hint": "Microsoft Windows"},
            "3": {"value": "", "vendor_hint": "junk"},
            "4": "not-a-dict",
        },
    }))
    matcher = SignatureMatcher(tmp_path)

    hit = matcher._resolve_huginn_dhcp_vendor("MSFT 5.0")
    assert hit is not None
    assert hit.manufacturer == "Microsoft Windows"

    # Second call is served from the memo and must agree.
    again = matcher._resolve_huginn_dhcp_vendor("MSFT 5.0")
    assert again is not None
    assert again.manufacturer == "Microsoft Windows"

    # A miss is memoised as a miss, not retried into a false positive.
    assert matcher._resolve_huginn_dhcp_vendor("android-dhcp-13") is None
    assert matcher._resolve_huginn_dhcp_vendor("android-dhcp-13") is None


# ---------------------------------------------------------------------------
# DHCPv6 DUID decoding
# ---------------------------------------------------------------------------

def _duid_packet(duid_bytes: bytes):
    from scapy.layers.l2 import Ether
    from scapy.layers.inet6 import IPv6
    from scapy.layers.inet import UDP
    from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6OptClientId, DHCP6OptOptReq
    return (
        Ether(src="00:50:56:11:22:33", dst="33:33:00:01:00:02")
        / IPv6(src="fe80::1", dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / DHCP6_Solicit(trid=1)
        / DHCP6OptClientId(duid=duid_bytes)
        / DHCP6OptOptReq(reqopts=[23, 24])
    )


def test_duid_en_yields_enterprise_number():
    """DUID-EN carries the vendor's IANA enterprise number."""
    from leetha.capture.protocols.dhcp import parse_dhcpv6
    fields = parse_dhcpv6(_duid_packet(b"\x00\x02" + (311).to_bytes(4, "big") + b"abcd")).fields
    assert fields["duid_type"] == "EN"
    assert fields["enterprise_id"] == 311
    assert fields["enterprise_id_source"] == "duid_en"


def test_duid_llt_yields_embedded_mac():
    """DUID-LLT embeds the link-layer address behind IPv6 privacy addressing."""
    from leetha.capture.protocols.dhcp import parse_dhcpv6
    duid = b"\x00\x01\x00\x01\x2b\xc5\x1f\x00" + bytes.fromhex("b827eb010203")
    fields = parse_dhcpv6(_duid_packet(duid)).fields
    assert fields["duid_type"] == "LLT"
    assert fields["duid_mac"] == "b8:27:eb:01:02:03"


def test_duid_ll_yields_embedded_mac():
    from leetha.capture.protocols.dhcp import parse_dhcpv6
    duid = b"\x00\x03\x00\x01" + bytes.fromhex("3c22fbaabbcc")
    fields = parse_dhcpv6(_duid_packet(duid)).fields
    assert fields["duid_type"] == "LL"
    assert fields["duid_mac"] == "3c:22:fb:aa:bb:cc"


def test_duid_uuid_and_truncated_are_safe():
    from leetha.capture.protocols.dhcp import parse_dhcpv6
    uuid_fields = parse_dhcpv6(_duid_packet(b"\x00\x04" + bytes(16))).fields
    assert uuid_fields["duid_type"] == "UUID"
    assert uuid_fields["duid_mac"] is None
    assert uuid_fields["enterprise_id"] is None

    short = parse_dhcpv6(_duid_packet(b"\x00")).fields
    assert short["duid_type"] is None
    assert short["enterprise_id"] is None


def test_vendor_class_option_outranks_duid_en():
    """Option 16 states the enterprise; a DUID-EN only implies it."""
    from scapy.layers.dhcp6 import DHCP6OptVendorClass
    from leetha.capture.protocols.dhcp import parse_dhcpv6
    pkt = _duid_packet(b"\x00\x02" + (311).to_bytes(4, "big") + b"abcd")
    pkt = pkt / DHCP6OptVendorClass(enterprisenum=43793, vcdata=[])
    fields = parse_dhcpv6(pkt).fields
    assert fields["enterprise_id"] == 43793
    assert fields["enterprise_id_source"] == "vendor_class"


# ---------------------------------------------------------------------------
# Satori TCP: SYN-ACK capture and flag isolation
# ---------------------------------------------------------------------------

def _handshake(flags, window, ttl, options):
    from scapy.compat import raw
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    pkt = (
        Ether(src="00:00:bc:11:22:33", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="10.0.0.50", dst="10.0.0.9", ttl=ttl, flags=0)
        / TCP(sport=44818, dport=51000, flags=flags, window=window, options=options)
    )
    return Ether(raw(pkt))  # force length/checksum computation


def test_syn_ack_is_captured_with_satori_signature():
    """A PLC is a server, so its stack only shows up in the SYN-ACK."""
    from leetha.capture.protocols.tcp_syn import parse_tcp_syn
    pkt = _handshake(
        "SA", 2048, 128,
        [("MSS", 16384), ("NOP", None), ("NOP", None), ("SAckOK", b"")],
    )
    fields = parse_tcp_syn(pkt).fields
    assert fields["tcp_flags"] == "SA"
    assert fields["satori_sig"] == "2048:128:0:48:M16384,N,N,S:."


def test_client_syn_signature_carries_option_values():
    from leetha.capture.protocols.tcp_syn import parse_tcp_syn
    pkt = _handshake(
        "S", 65535, 64,
        [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 9)],
    )
    fields = parse_tcp_syn(pkt).fields
    assert fields["tcp_flags"] == "S"
    assert fields["satori_sig"] == "65535:64:0:60:M1460,S,T,N,W9:."


def test_midstream_traffic_still_rejected():
    from leetha.capture.protocols.tcp_syn import parse_tcp_syn
    assert parse_tcp_syn(_handshake("A", 100, 64, [])) is None


def test_satori_tcp_keeps_syn_and_synack_separate(tmp_path):
    """The same signature means different devices per direction."""
    (tmp_path / "satori_tcp.json").write_text(json.dumps({
        "source": "satori_tcp",
        "entries": [{
            "name": "1763 MicroLogix 1100 PLC",
            "os_class": "ICS device",
            "device_vendor": "Allen-Bradley",
            "tests": [{
                "weight": "5", "matchtype": "exact",
                "tcpflag": "SA", "tcpsig": "2048:128:0:48:M16384,N,N,S:.",
            }],
        }],
    }))
    matcher = SignatureMatcher(tmp_path)
    sig = "2048:128:0:48:M16384,N,N,S:."

    hit = matcher.match_satori_tcp(sig, "SA")
    assert hit is not None
    assert hit.manufacturer == "Allen-Bradley"
    assert hit.os_family == "ICS device"

    # Same signature seen as a client SYN must not match the PLC.
    assert matcher.match_satori_tcp(sig, "S") is None


# ---------------------------------------------------------------------------
# SMB Native OS extraction
# ---------------------------------------------------------------------------

def _smb1_session_setup(native_os, native_lanman, unicode_strings=True, extended=True):
    flags2 = 0x8000 if unicode_strings else 0x0000
    # 4 magic + 1 command + 4 status + 1 flags + 2 flags2 + 20 trailing
    # (PIDHigh, signature, reserved, TID, PID, UID, MID) = 32 bytes.
    header = (
        b"\xffSMB" + bytes([0x73]) + b"\x00" * 4 + b"\x88"
        + flags2.to_bytes(2, "little") + b"\x00" * 20
    )
    assert len(header) == 32
    if unicode_strings:
        def enc(s):
            return s.encode("utf-16-le") + b"\x00\x00"
    else:
        def enc(s):
            return s.encode("latin-1") + b"\x00"

    if extended:
        blob = b"\xa1\x82" + b"BLOB" * 3
        params = b"\xff\x00" + (0).to_bytes(2, "little") + (1).to_bytes(2, "little") \
            + len(blob).to_bytes(2, "little")
        word_count, data = 4, blob + enc(native_os) + enc(native_lanman)
    else:
        params = b"\xff\x00" + (0).to_bytes(2, "little") + (1).to_bytes(2, "little")
        word_count, data = 3, enc(native_os) + enc(native_lanman)

    body = bytes([word_count]) + params + len(data).to_bytes(2, "little") + data
    smb = header + body
    return b"\x00\x00" + len(smb).to_bytes(2, "big") + smb


@pytest.mark.parametrize("unicode_strings,extended", [
    (True, True), (True, False), (False, True), (False, False),
])
def test_smb_native_os_extracted(unicode_strings, extended):
    from leetha.capture.banner.matchers import _match_smb
    payload = _smb1_session_setup(
        "Windows 10 Pro 19041", "Windows 10 Pro 6.3", unicode_strings, extended
    )
    result = _match_smb(payload)
    assert result["native_os"] == "Windows 10 Pro 19041"
    assert result["native_lanman"] == "Windows 10 Pro 6.3"


def test_smb2_has_no_native_fields():
    from leetha.capture.banner.matchers import _match_smb
    result = _match_smb(b"\x00\x00\x00\x40" + b"\xfeSMB" + b"\x00" * 60)
    assert result["smb_version"] == "2"
    assert "native_os" not in result


def test_smb_truncated_payload_does_not_raise():
    from leetha.capture.banner.matchers import _match_smb
    result = _match_smb(b"\x00\x00\x00\x05" + b"\xffSMB" + bytes([0x73]))
    assert result["smb_version"] == "1"
    assert result.get("native_os") is None


def test_satori_smb_matches_either_native_field(tmp_path):
    (tmp_path / "satori_smb.json").write_text(json.dumps({
        "source": "satori_smb",
        "entries": [{
            "name": "Dell Printer", "device_type": "Printer", "device_vendor": "Dell",
            "tests": [
                {"weight": "5", "matchtype": "exact", "smbnativename": "FXNIC 0.01"},
                {"weight": "5", "matchtype": "exact", "smbnativelanman": "FXNIC0.01"},
            ],
        }],
    }))
    matcher = SignatureMatcher(tmp_path)
    # Indexes for the two fields must not collide in the cache.
    assert matcher.match_satori_smb("FXNIC 0.01").manufacturer == "Dell"
    assert matcher.match_satori_smb("FXNIC0.01").manufacturer == "Dell"


# ---------------------------------------------------------------------------
# Self-describing DHCP vendor classes
# ---------------------------------------------------------------------------

def test_structured_vendor_class_gives_vendor_type_and_model():
    from leetha.sync.parsers import _parse_vendor_class_fields
    parsed = _parse_vendor_class_fields(
        "Mfg=Hewlett Packard;Typ=Printer;Mod=HP LaserJet 400 M401n;Ser=CN123"
    )
    assert parsed == {
        "vendor": "Hewlett Packard",
        "device_type": "Printer",
        "model": "HP LaserJet 400 M401n",
    }


def test_unstructured_vendor_class_returns_nothing():
    from leetha.sync.parsers import _parse_vendor_class_fields
    assert _parse_vendor_class_fields("MSFT 5.0") == {}
    assert _parse_vendor_class_fields("") == {}


def test_match_dhcp_reads_observed_structured_vendor_class(tmp_path):
    """Works for any printer, not just ones collected into Huginn."""
    matcher = SignatureMatcher(tmp_path)  # empty cache -- no table to lean on
    hits = matcher.match_dhcp(opt60="Mfg=Lexmark;Typ=MFP;Mod=Lexmark MX611de;Ser=99")
    structured = [h for h in hits if h.source == "dhcp_vendor_class"]
    assert len(structured) == 1
    assert structured[0].manufacturer == "Lexmark"
    assert structured[0].device_type == "mfp"
    assert structured[0].model == "Lexmark MX611de"


def test_vendor_class_match_without_identity_is_dropped(tmp_path):
    """A 0.75-confidence hit carrying no vendor/type/model is just noise."""
    (tmp_path / "huginn_dhcp_vendor.json").write_text(json.dumps({
        "source": "huginn_dhcp_vendor",
        "entries": {"1": {"value": "somerandomclass"}},  # no vendor_hint
    }))
    matcher = SignatureMatcher(tmp_path)
    assert matcher._resolve_huginn_dhcp_vendor("somerandomclass") is None


# ---------------------------------------------------------------------------
# Feed catalogue
# ---------------------------------------------------------------------------

def test_satori_ntp_feed_removed():
    """Its key encodes Satori-internal timestamp heuristics; unmatchable."""
    from leetha.sync import PARSER_MAP
    from leetha.sync.registry import SourceRegistry
    assert "satori_ntp" not in SourceRegistry()
    assert "satori_ntp" not in PARSER_MAP


def test_every_feed_has_a_parser_and_vice_versa():
    from leetha.sync import PARSER_MAP
    from leetha.sync.registry import SourceRegistry
    registry = SourceRegistry()
    assert {s.name for s in registry.list_sources()} == set(PARSER_MAP)


# ---------------------------------------------------------------------------
# Router Advertisement fingerprinting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hop_limit,managed,other,expect_vendor", [
    (255, 0, 0, "Cisco"),
    (64, 0, 1, "Juniper"),
    (64, 1, 1, "MikroTik"),
    (128, 0, 0, "Microsoft"),
])
def test_router_advertisement_identifies_vendor(hop_limit, managed, other, expect_vendor):
    """RA hop limit + M/O flags fingerprint the router's stack."""
    matcher = SignatureMatcher("/nonexistent")  # pattern tables, not cache files
    hit = matcher.match_icmpv6("router_advertisement", hop_limit, managed, other, {})
    assert hit is not None
    assert hit.manufacturer == expect_vendor


def test_router_advertisement_lookup_is_wired_into_the_pipeline():
    """It was defined but never called, so router vendor was never learned."""
    import inspect
    from leetha.core.pipeline import Pipeline
    source = inspect.getsource(Pipeline._fingerprint_lookup)
    assert "match_icmpv6" in source


def test_ra_parser_supplies_every_field_the_matcher_needs():
    from scapy.compat import raw
    from scapy.layers.l2 import Ether
    from scapy.layers.inet6 import IPv6, ICMPv6ND_RA
    from leetha.capture.protocols.icmpv6 import parse_icmpv6
    pkt = Ether(raw(
        Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01")
        / IPv6(src="fe80::1", dst="ff02::1")
        / ICMPv6ND_RA(chlim=255, M=0, O=0)
    ))
    fields = parse_icmpv6(pkt).fields
    assert fields["icmpv6_type"] == "router_advertisement"
    assert fields["hop_limit"] == 255
    assert fields["managed"] == 0
    assert fields["other"] == 0


# ---------------------------------------------------------------------------
# Public parser names must resolve to the parsers PARSER_CHAIN runs
# ---------------------------------------------------------------------------

def test_public_parser_names_are_not_the_legacy_copies():
    """The plain names used to resolve to stale _legacy duplicates."""
    from leetha.capture import protocols
    from leetha.capture.protocols import PARSER_CHAIN
    for name in ("parse_dhcpv6", "parse_tcp_syn", "parse_icmpv6", "parse_arp"):
        fn = getattr(protocols, name)
        assert not fn.__module__.endswith("_legacy"), name
        assert fn in PARSER_CHAIN, name


def test_legacy_module_still_importable_directly():
    """Kept for anything that genuinely wants the old ParsedPacket type."""
    from leetha.capture.protocols._legacy import parse_dhcpv6 as legacy
    assert legacy.__module__.endswith("_legacy")


def test_shadowed_protocols_module_is_gone():
    """A stray protocols.py sat next to the package, permanently dead."""
    from pathlib import Path
    import leetha.capture
    pkg_dir = Path(leetha.capture.__file__).parent
    assert not (pkg_dir / "protocols.py").exists()


# ---------------------------------------------------------------------------
# Recog: match-less files, telnet framing, template interpolation
# ---------------------------------------------------------------------------

def test_recog_files_without_matches_use_a_fallback_key():
    """Two match-less files used to collapse onto "unknown" and clobber."""
    from leetha.sync.parsers import ingest_recog
    xml = ('<?xml version="1.0"?><fingerprints protocol="telnet">'
           '<fingerprint pattern="^Cisco"><description>C</description>'
           '<param pos="0" name="service.vendor" value="Cisco"/>'
           '</fingerprint></fingerprints>')
    assert list(ingest_recog(xml, fallback_key="telnet_banners")) == ["telnet_banners"]
    assert list(ingest_recog(xml)) == ["unknown"]


def test_telnet_banner_framing_keeps_all_lines():
    """Recog anchors whole multi-line login screens; first-line-only broke it."""
    banner = "User Access Verification\r\n\r\nUsername:"
    assert SignatureMatcher._strip_banner_framing("telnet", banner) == banner
    # Line-oriented greetings still collapse to their first line.
    assert SignatureMatcher._strip_banner_framing(
        "ssh", "SSH-2.0-OpenSSH_9.2p1\r\nextra"
    ) == "OpenSSH_9.2p1"


def test_recog_resolves_param_templates(tmp_path):
    """"{hw.product} Firmware" was surfaced as a literal model string."""
    (tmp_path / "recog.json").write_text(json.dumps({
        "source": "recog",
        "entries": {
            "sip_header.user_agent": [{
                "pattern": r"^Grandstream (\S+) ",
                "params": [
                    {"pos": 0, "name": "hw.vendor", "value": "Grandstream"},
                    {"pos": 1, "name": "hw.product", "value": None},
                    {"pos": 0, "name": "os.product", "value": "{hw.product} Firmware"},
                ],
                "description": "Grandstream phone",
            }],
        },
    }))
    matcher = SignatureMatcher(tmp_path)
    hit = matcher.match_recog("sip_user_agent", "Grandstream GXP2140 1.0.7.25")
    assert hit is not None
    assert hit.model == "GXP2140"
    assert hit.os_family == "GXP2140 Firmware"
    assert "{" not in hit.os_family


# ---------------------------------------------------------------------------
# Telnet / LDAP banner extraction
# ---------------------------------------------------------------------------

def test_telnet_banner_preserves_case_and_strips_negotiation():
    """It used to lowercase the banner, corrupting it for every consumer."""
    from leetha.capture.banner.matchers import _match_telnet
    payload = b"\xff\xfd\x18\xff\xfb\x01User Access Verification\r\n\r\nUsername: "
    result = _match_telnet(payload)
    assert result["service"] == "telnet"
    assert "User Access Verification" in result["raw_banner"]
    assert "\xff" not in result["raw_banner"]


def test_telnet_banner_without_login_prompt_is_still_captured():
    from leetha.capture.banner.matchers import _match_telnet
    result = _match_telnet(b"\xff\xfb\x01DD-WRT v24-sp2 std\r\n")
    assert result is not None
    assert "DD-WRT v24-sp2 std" in result["raw_banner"]


def test_ldap_exposes_decoded_response_for_matching():
    """Recog matches the response bytes; a 16-byte hex prefix never could."""
    from leetha.capture.banner.matchers import _match_ldap
    payload = b"\x30\x84\x00\x00\x00\x10\x65" + b"vendorName1\x04\x05Samba"
    result = _match_ldap(payload)
    assert result["service"] == "ldap"
    assert "Samba" in result["ldap_response"]
    # The displayed banner stays hex.
    assert result["raw_banner"] == payload[:16].hex()


def test_recog_manifest_covers_the_added_protocols():
    from leetha.sync import MULTIFILE_MANIFESTS
    manifest = MULTIFILE_MANIFESTS["recog"]
    for name in ("telnet_banners.xml", "mdns_device-info_txt.xml",
                 "dhcp_vendor_class.xml", "sip_user_agents.xml",
                 "ldap_searchresult.xml", "rtsp_servers.xml"):
        assert name in manifest


# ---------------------------------------------------------------------------
# JA3 sourcing: JSON-lines feed, OS inference, threat classification
# ---------------------------------------------------------------------------

def test_ja3_parses_json_lines():
    """The Trisul feed is newline-delimited JSON, which json.loads rejects."""
    from leetha.sync.parsers import ingest_ja3
    content = (
        '{"desc":"Adium 1.5.10","ja3_hash":"aaa","ja3_str":"769,4-5,0,0,0"}\n'
        '{"desc":"AirCanada Android App","ja3_hash":"bbb","ja3_str":"769,6,0,0,0"}\n'
    )
    table = ingest_ja3(content)
    assert set(table) == {"aaa", "bbb"}
    assert table["aaa"]["app"] == "Adium 1.5.10"
    assert table["bbb"]["ja3_str"] == "769,6,0,0,0"


def test_ja3_still_parses_a_json_array():
    from leetha.sync.parsers import ingest_ja3
    table = ingest_ja3('[{"desc":"X","ja3_hash":"h1"}]')
    assert table["h1"]["app"] == "X"


def test_ja3_still_parses_csv():
    from leetha.sync.parsers import ingest_ja3
    digest = "b386946a5a44d1ddcc843bc75336dfce"  # CSV path requires an MD5
    table = ingest_ja3(f"{digest},Some Client\n")
    assert table[digest]["app"] == "Some Client"


@pytest.mark.parametrize("desc,expected_os", [
    ("AirCanada Android App", "Android"),
    ("Apple Spotlight Search (OSX)", "macOS"),
    ("Microsoft Updater (Windows 7SP1)", "Windows"),
    ("Chrome/56.0.2924.87 Linux", "Linux"),
    ("iPhone Mail", "iOS"),
    ("Google Chrome", None),
])
def test_ja3_infers_os_from_description(desc, expected_os):
    """Trisul carries no os field, so every hit used to have no identity."""
    from leetha.sync.parsers import _classify_ja3_description
    assert _classify_ja3_description(desc).get("os_family") == expected_os


def test_ja3_mobile_app_implies_a_handset():
    from leetha.sync.parsers import _classify_ja3_description
    assert _classify_ja3_description("AirCanada Android App")["device_type"] == "mobile"
    assert "device_type" not in _classify_ja3_description("Google Chrome")


def test_ja3_drops_malware_and_scanner_records():
    """leetha identifies devices and operating systems, not malware.

    These records carry no vendor, OS, or device type, so keeping them
    would only put malware labels in the host inventory.
    """
    from leetha.sync.parsers import _classify_ja3_description, ingest_ja3
    assert _classify_ja3_description("Malware: Gootkit") == {"skip": True}
    assert _classify_ja3_description(
        "SCANNER: wordpress wp-login Firefox/40.1"
    ) == {"skip": True}

    content = (
        '{"desc":"Malware: Gootkit","ja3_hash":"bad1"}\n'
        '{"desc":"AirCanada Android App","ja3_hash":"good1"}\n'
    )
    table = ingest_ja3(content)
    assert "bad1" not in table
    assert "good1" in table


def test_ja3_keeps_records_that_merely_mention_malware():
    """A hash shared by Chrome and an exploit kit still identifies Chrome."""
    from leetha.sync.parsers import _classify_ja3_description
    result = _classify_ja3_description(
        "Chrome 11 - 18, Chrome 11.0.696.16, Malware Test FP: angler-ek"
    )
    assert not result.get("skip")


def test_ja3_server_side_entries_are_marked():
    """JA3S fingerprints a ServerHello and can never match a ClientHello."""
    from leetha.sync.parsers import _classify_ja3_description
    assert _classify_ja3_description("JA3S: GitHub.com")["direction"] == "server"


def test_ja3_match_surfaces_os_and_device_type(tmp_path):
    (tmp_path / "ja3.json").write_text(json.dumps({
        "source": "ja3_fingerprints",
        "entries": {
            "abc123": {
                "app": "AirCanada Android App",
                "os_family": "Android",
                "device_type": "mobile",
                "description": "AirCanada Android App",
            },
        },
    }))
    matcher = SignatureMatcher(tmp_path)
    hit = matcher.match_ja3("abc123")
    assert hit is not None
    assert hit.os_family == "Android"
    assert hit.device_type == "mobile"


def test_ja3_feed_points_at_a_maintained_source():
    """salesforce/ja3 is archived; its 157 hashes are a subset of Trisul's."""
    from leetha.sync.registry import SourceRegistry
    feed = SourceRegistry().get_source("ja3_fingerprints")
    assert "salesforce" not in feed.endpoint
    assert feed.source_type == "json"


# ---------------------------------------------------------------------------
# Retired feed caches
# ---------------------------------------------------------------------------

def test_prune_removes_only_retired_feed_caches(tmp_path):
    """A retired feed used to leave its cache on disk forever.

    Harmless for satori_ntp (12 KB) but the dropped huginn_mac_vendors
    export was over 700 MB.
    """
    from leetha.sync import prune_retired_caches
    from leetha.sync.registry import SourceRegistry

    for name in ("ieee_oui", "ja3", "ja4", "recog", "p0f",
                 "satori_ntp", "huginn_mac_vendors"):
        (tmp_path / f"{name}.json").write_text("{}")
    (tmp_path / "notes.txt").write_text("not a cache file")

    removed = prune_retired_caches(tmp_path, SourceRegistry())

    assert set(removed) == {"satori_ntp.json", "huginn_mac_vendors.json"}
    survivors = {p.name for p in tmp_path.iterdir()}
    # ja3/ja4 are CACHE_NAMES aliases, not feed keys -- they must survive.
    assert {"ja3.json", "ja4.json", "ieee_oui.json", "recog.json"} <= survivors
    # Anything that is not a feed cache is left alone.
    assert "notes.txt" in survivors


def test_prune_tolerates_a_missing_cache_dir(tmp_path):
    from leetha.sync import prune_retired_caches
    from leetha.sync.registry import SourceRegistry
    assert prune_retired_caches(tmp_path / "nope", SourceRegistry()) == []


# ---------------------------------------------------------------------------
# Admin token location and hardened-service survivability
# ---------------------------------------------------------------------------

def test_admin_token_follows_the_data_directory(tmp_path, monkeypatch):
    """A service pointing LEETHA_DATA_DIR at /var/lib must keep its token there."""
    import leetha.config as cfg

    monkeypatch.setenv("LEETHA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LEETHA_CACHE_DIR", str(tmp_path / "cache"))
    # get_config() memoises into a module global, so the singleton has to be
    # dropped for the patched environment to take effect.
    monkeypatch.setattr(cfg, "_config", None, raising=False)

    from leetha.auth.tokens import _token_dir, save_admin_token, generate_token
    assert _token_dir() == tmp_path

    token = generate_token()
    written = save_admin_token(token)
    assert written.parent == tmp_path
    if os.name != "nt":
        # Windows has no Unix permission bits; chmod is a no-op there.
        assert oct(written.stat().st_mode)[-3:] == "600"


@pytest.mark.skipif(
    os.name == "nt", reason="Unix file-permission bits do not apply on Windows"
)
def test_token_read_survives_an_unreadable_directory(tmp_path):
    """ProtectHome= makes the service user's home unreadable.

    Path.exists() raises PermissionError there instead of returning False,
    and letting it escape killed the whole backend event loop -- packet
    capture died while the web server kept serving.
    """
    from leetha.auth.tokens import _read_token_file

    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "admin-token").write_text("ltk_secret")
    os.chmod(blocked, 0o000)
    try:
        assert _read_token_file(blocked / "admin-token") is None
    finally:
        os.chmod(blocked, 0o700)


def test_token_read_handles_a_missing_file(tmp_path):
    from leetha.auth.tokens import _read_token_file
    assert _read_token_file(tmp_path / "nope") is None


# ---------------------------------------------------------------------------
# leetha interfaces add/remove/show
# ---------------------------------------------------------------------------

def test_interface_subcommands_are_implemented():
    """add/remove/show were declared but the dispatcher only handled list,
    so a headless service had no way to configure its capture interfaces."""
    import inspect
    from leetha import cli
    source = inspect.getsource(cli.main)
    for action in ('action == "add"', 'action == "remove"', 'action == "show"'):
        assert action in source, action


def test_interface_add_persists_and_is_idempotent(tmp_path):
    from leetha.capture.interfaces import (
        AdapterConfig, load_interface_config, save_interface_config,
    )
    save_interface_config(tmp_path, [AdapterConfig(name="eth0", type="local")])
    saved = load_interface_config(tmp_path)
    assert [s.name for s in saved] == ["eth0"]
    assert (tmp_path / "interfaces.json").is_file()

    # Removing leaves an empty, still-valid config.
    save_interface_config(tmp_path, [s for s in saved if s.name != "eth0"])
    assert load_interface_config(tmp_path) == []
