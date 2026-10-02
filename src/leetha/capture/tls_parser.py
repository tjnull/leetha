"""
Dissector for TLS ClientHello handshake messages.

Reads raw TCP payload bytes and extracts the version, cipher suites,
extension IDs, supported groups (elliptic curves), EC point formats,
SNI hostname, and ALPN protocol from a TLS 1.x ClientHello record.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Handshake constants
# ---------------------------------------------------------------------------

_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_EXT_SNI = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_ALPN = 0x0010
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_RANDOM_BYTES_LEN = 32


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class TlsHandshakeData:
    """Holds the significant fields extracted from a TLS ClientHello."""
    tls_version: int
    ciphers: list[int]
    extensions: list[int]
    elliptic_curves: list[int]
    ec_point_formats: list[int]
    sni: str | None = None
    alpn: str | None = None
    supported_versions: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)


# Backward-compatible alias used by other modules
ClientHelloFields = TlsHandshakeData


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_uint16(buf: bytes, offset: int) -> int:
    """Unpack a big-endian unsigned 16-bit integer at *offset*."""
    return struct.unpack("!H", buf[offset:offset + 2])[0]


def _decode_cipher_list(raw: bytes, start: int, suite_block_len: int) -> list[int]:
    """Return the list of 16-bit cipher-suite IDs from the given span."""
    suites: list[int] = []
    cursor = start
    boundary = start + suite_block_len
    while cursor + 2 <= boundary:
        suites.append(_read_uint16(raw, cursor))
        cursor += 2
    return suites


def _extract_sni(ext_body: bytes) -> str | None:
    """Pull the hostname out of an SNI extension body, if present."""
    if len(ext_body) < 5:
        return None
    try:
        host_type = ext_body[2]
        if host_type != 0:
            return None
        host_len = _read_uint16(ext_body, 3)
        return ext_body[5:5 + host_len].decode("ascii", errors="ignore")
    except (struct.error, IndexError):
        return None


def _extract_supported_groups(ext_body: bytes) -> list[int]:
    """Decode the Supported Groups (elliptic curves) extension."""
    groups: list[int] = []
    if len(ext_body) < 2:
        return groups
    try:
        total = _read_uint16(ext_body, 0)
        idx = 2
        while idx + 2 <= 2 + total and idx + 2 <= len(ext_body):
            groups.append(_read_uint16(ext_body, idx))
            idx += 2
    except (struct.error, IndexError):
        pass
    return groups


def _extract_ec_formats(ext_body: bytes) -> list[int]:
    """Decode the EC Point Formats extension."""
    formats: list[int] = []
    if len(ext_body) < 1:
        return formats
    try:
        fmt_count = ext_body[0]
        for idx in range(1, 1 + fmt_count):
            if idx < len(ext_body):
                formats.append(ext_body[idx])
    except IndexError:
        pass
    return formats


def _extract_alpn(ext_body: bytes) -> str | None:
    """Pull the first protocol name out of an ALPN extension body."""
    if len(ext_body) < 3:
        return None
    try:
        proto_len = ext_body[2]
        return ext_body[3:3 + proto_len].decode("ascii", errors="ignore")
    except (struct.error, IndexError):
        return None


def _extract_uint16_list(ext_body: bytes, length_size: int) -> list[int]:
    """Decode a length-prefixed list of two-byte TLS identifiers."""
    if len(ext_body) < length_size:
        return []
    count = ext_body[0] if length_size == 1 else _read_uint16(ext_body, 0)
    end = min(len(ext_body), length_size + count)
    return [_read_uint16(ext_body, pos)
            for pos in range(length_size, end - 1, 2)]


def _walk_extensions(
    raw: bytes,
    cursor: int,
) -> tuple[list[int], list[int], list[int], str | None, str | None,
           list[int], list[int]]:
    """Iterate through the extensions block, collecting IDs and known fields.

    Returns extension IDs, JA3 groups/formats, SNI/ALPN, supported versions,
    and signature algorithms.
    """
    ext_ids: list[int] = []
    groups: list[int] = []
    ec_fmts: list[int] = []
    sni_hostname: str | None = None
    alpn_proto: str | None = None
    supported_versions: list[int] = []
    signature_algorithms: list[int] = []

    if cursor + 2 > len(raw):
        return (ext_ids, groups, ec_fmts, sni_hostname, alpn_proto,
                supported_versions, signature_algorithms)

    block_len = _read_uint16(raw, cursor)
    cursor += 2
    block_end = min(len(raw), cursor + block_len)

    while cursor + 4 <= block_end:
        eid = _read_uint16(raw, cursor)
        elen = _read_uint16(raw, cursor + 2)
        body = raw[cursor + 4:cursor + 4 + elen]
        ext_ids.append(eid)

        if eid == _EXT_SNI:
            sni_hostname = _extract_sni(body)
        elif eid == _EXT_SUPPORTED_GROUPS:
            groups = _extract_supported_groups(body)
        elif eid == _EXT_EC_POINT_FORMATS:
            ec_fmts = _extract_ec_formats(body)
        elif eid == _EXT_ALPN:
            alpn_proto = _extract_alpn(body)
        elif eid == _EXT_SUPPORTED_VERSIONS:
            supported_versions = _extract_uint16_list(body, 1)
        elif eid == _EXT_SIGNATURE_ALGORITHMS:
            signature_algorithms = _extract_uint16_list(body, 2)

        cursor += 4 + elen

    return (ext_ids, groups, ec_fmts, sni_hostname, alpn_proto,
            supported_versions, signature_algorithms)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_client_hello(raw_payload: bytes) -> TlsHandshakeData | None:
    """Dissect a TLS ClientHello from a raw TCP segment.

    Walks the TLS record header, handshake header, and the variable-length
    fields (session ID, cipher suites, compression, extensions) to populate
    a ``TlsHandshakeData`` instance.

    Args:
        raw_payload: The raw bytes of the TCP payload (starting at the TLS
            record header).

    Returns:
        A ``TlsHandshakeData`` with the parsed fields, or ``None`` when the
        payload is not a valid ClientHello.
    """
    buf = raw_payload

    # -- TLS record header: ContentType(1) + Version(2) + Length(2) ---------
    if len(buf) < 6:
        return None
    if buf[0] != _CONTENT_TYPE_HANDSHAKE:
        return None

    # -- Handshake header: Type(1) + Length(3) ------------------------------
    if len(buf) < 9:
        return None
    if buf[5] != _HANDSHAKE_CLIENT_HELLO:
        return None

    cursor = 9

    # -- Client version (2 bytes) -------------------------------------------
    if len(buf) < cursor + 2:
        return None
    version = _read_uint16(buf, cursor)
    cursor += 2

    # -- Random (32 bytes) --------------------------------------------------
    cursor += _RANDOM_BYTES_LEN
    if cursor >= len(buf):
        return None

    # -- Session ID (variable) ----------------------------------------------
    sid_len = buf[cursor]
    cursor += 1 + sid_len

    # -- Cipher suites (variable) -------------------------------------------
    if cursor + 2 > len(buf):
        return None
    suite_block_len = _read_uint16(buf, cursor)
    cursor += 2
    cipher_list = _decode_cipher_list(buf, cursor, suite_block_len)
    cursor += suite_block_len

    # -- Compression methods (variable) -------------------------------------
    if cursor >= len(buf):
        return None
    comp_count = buf[cursor]
    cursor += 1 + comp_count

    # -- Extensions (variable) ----------------------------------------------
    (ext_ids, groups, ec_fmts, sni_hostname, alpn_proto,
     supported_versions, signature_algorithms) = _walk_extensions(
        buf, cursor,
    )

    return TlsHandshakeData(
        tls_version=version,
        ciphers=cipher_list,
        extensions=ext_ids,
        elliptic_curves=groups,
        ec_point_formats=ec_fmts,
        sni=sni_hostname,
        alpn=alpn_proto,
        supported_versions=supported_versions,
        signature_algorithms=signature_algorithms,
    )


# Backward-compatible alias -- imported by protocols.py, tests, etc.
parse_client_hello = extract_client_hello
