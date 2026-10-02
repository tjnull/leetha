"""Leetha TLS fingerprint computation and matching.

Implements JA3 and JA4 fingerprint algorithms for identifying TLS client
applications from their ClientHello parameters. GREASE values are filtered
per the JA3/JA4 specifications to ensure consistent hashing.

JA3: https://github.com/salesforce/ja3
JA4: https://github.com/FoxIO-LLC/ja4
"""

import hashlib
from typing import Dict, List, Optional, Tuple


# RFC 8701 GREASE Values

# Generate Randomized Extensions And Sustain Extensibility (GREASE)
# These values are injected by TLS clients to test server tolerance
# and must be filtered before fingerprint computation.
GREASE_VALUES: set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


# Known JA3 Hashes

# Well-known JA3 hashes mapped to application/OS identification.
# Each entry: ja3_hash -> {app, os_family (optional), confidence}
KNOWN_JA3: Dict[str, dict] = {
    # Chrome on Windows
    "e7d705a3286e19ea42f587b344ee6865": {
        "app": "Chrome",
        "os_family": "Windows",
        "confidence": 70,
    },
    # Firefox (cross-platform)
    "769baa87ef9078cf6b3a85d12e0d3f40": {
        "app": "Firefox",
        "confidence": 65,
    },
    # Safari on macOS
    "b32309a26951912be7dba376398abc3b": {
        "app": "Safari",
        "os_family": "macOS",
        "confidence": 70,
    },
    # curl (cross-platform)
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "app": "curl",
        "confidence": 60,
    },
    # Python requests library (cross-platform)
    "cd08e31494f9531f560d64c695473da9": {
        "app": "Python requests",
        "confidence": 60,
    },
}


# JA4 Version and ALPN Mappings

_JA4_VERSION_MAP: Dict[int, str] = {
    0x0300: "s3",  # SSL 3.0
    0x0301: "10",  # TLS 1.0
    0x0302: "11",  # TLS 1.1
    0x0303: "12",  # TLS 1.2
    0x0304: "13",  # TLS 1.3
}


# Helper Functions

def _filter_grease(values: List[int]) -> List[int]:
    """Remove RFC 8701 GREASE values from a list of TLS parameters.

    Args:
        values: List of integer TLS parameter values (cipher suites,
                extensions, elliptic curves, etc.).

    Returns:
        New list with all GREASE values removed.
    """
    return [v for v in values if v not in GREASE_VALUES]


# JA3 Computation

def compute_ja3(
    tls_version: int,
    ciphers: List[int],
    extensions: List[int],
    elliptic_curves: List[int],
    ec_point_formats: List[int],
) -> Tuple[str, str]:
    """Compute a JA3 fingerprint hash from TLS ClientHello parameters.

    The JA3 full string is built by joining five comma-separated sections
    with commas, where each section's values are dash-separated:
        TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats

    GREASE values are filtered from ciphers, extensions, and elliptic_curves
    before hashing.

    Args:
        tls_version: TLS version as integer (e.g. 0x0303 for TLS 1.2).
        ciphers: List of cipher suite values from ClientHello.
        extensions: List of extension type values from ClientHello.
        elliptic_curves: List of supported elliptic curve/group values.
        ec_point_formats: List of EC point format values.

    Returns:
        Tuple of (md5_hash, full_string) where md5_hash is the 32-char
        lowercase hex MD5 digest and full_string is the raw JA3 string.
    """
    filtered_ciphers = _filter_grease(ciphers)
    filtered_extensions = _filter_grease(extensions)
    filtered_curves = _filter_grease(elliptic_curves)

    parts = [
        str(tls_version),
        "-".join(str(c) for c in filtered_ciphers),
        "-".join(str(e) for e in filtered_extensions),
        "-".join(str(g) for g in filtered_curves),
        "-".join(str(p) for p in ec_point_formats),
    ]

    full_string = ",".join(parts)
    md5_hash = hashlib.md5(full_string.encode("ascii")).hexdigest()

    return md5_hash, full_string


# JA4 Computation

def compute_ja4(
    tls_version: int,
    ciphers: List[int],
    extensions: List[int],
    sni: Optional[str] = None,
    alpn: Optional[str] = None,
    supported_versions: Optional[List[int]] = None,
    signature_algorithms: Optional[List[int]] = None,
    sni_present: Optional[bool] = None,
) -> str:
    """Compute a FoxIO-compatible JA4 fingerprint for a TLS ClientHello."""
    filtered_ciphers = _filter_grease(ciphers)
    filtered_extensions = _filter_grease(extensions)
    versions = _filter_grease(supported_versions or [])
    version = _JA4_VERSION_MAP.get(max(versions) if versions else tls_version, "00")
    sni_flag = "d" if (bool(sni) if sni_present is None else sni_present) else "i"
    cipher_count = f"{min(len(filtered_ciphers), 99):02d}"
    ext_count = f"{min(len(filtered_extensions), 99):02d}"
    if not alpn:
        alpn_code = "00"
    elif alpn[0].isascii() and alpn[0].isalnum() and alpn[-1].isascii() and alpn[-1].isalnum():
        alpn_code = alpn[0] + alpn[-1]
    else:
        alpn_hex = alpn.encode("utf-8").hex()
        alpn_code = alpn_hex[0] + alpn_hex[-1]

    cipher_str = ",".join(f"{value:04x}" for value in sorted(filtered_ciphers))
    cipher_hash = (hashlib.sha256(cipher_str.encode("ascii")).hexdigest()[:12]
                   if cipher_str else "000000000000")

    # SNI and ALPN are represented in section A, so they are excluded here.
    ext_str = ",".join(f"{value:04x}" for value in sorted(
        value for value in filtered_extensions if value not in (0, 16)))
    if ext_str and signature_algorithms:
        sigalgs = ",".join(f"{value:04x}" for value in _filter_grease(signature_algorithms))
        if sigalgs:
            ext_str += "_" + sigalgs
    ext_hash = (hashlib.sha256(ext_str.encode("ascii")).hexdigest()[:12]
                if ext_str else "000000000000")

    section_a = f"t{version}{sni_flag}{cipher_count}{ext_count}{alpn_code}"
    return f"{section_a}_{cipher_hash}_{ext_hash}"


# Lookup

def lookup_ja3(ja3_hash: str) -> Optional[dict]:
    """Look up a JA3 hash in the known fingerprint database.

    Args:
        ja3_hash: 32-character lowercase hex MD5 JA3 hash string.

    Returns:
        Dictionary with identification info (app, os_family, confidence)
        if the hash is known, or None if not found.
    """
    return KNOWN_JA3.get(ja3_hash)
