"""
DHCP field integrity checker -- validates option payloads per RFC 2132.

Executes off the main packet path so capture throughput is unaffected.
Detected irregularities are persisted to {data_dir}/dhcp_anomalies.jsonl.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path

_log = logging.getLogger(__name__)

ANOMALY_LOG_CEILING = 10 * 1024 * 1024  # 10 MB rotation threshold

# ---------------------------------------------------------------------------
# Primitive value testers
# ---------------------------------------------------------------------------

_IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_ipv4(val) -> bool:
    """Return True when *val* resembles a syntactically valid IPv4 address."""
    text = val if isinstance(val, str) else str(val)
    if not _IPV4_PATTERN.match(text):
        return False
    return all(0 <= int(part) <= 255 for part in text.split("."))


def _text_is_clean(val) -> bool:
    """Return True when *val* contains only printable characters (tabs allowed)."""
    if isinstance(val, bytes):
        try:
            decoded = val.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
    else:
        decoded = str(val)
    return all(ch.isprintable() or ch == "\t" for ch in decoded)


# ---------------------------------------------------------------------------
# Per-option validators -- each returns a failure reason or None
# ---------------------------------------------------------------------------

def _check_single_ip(val) -> str | None:
    """Ensure value is one valid IPv4 address."""
    if not _looks_like_ipv4(val):
        return f"invalid IP address: {_clamp_repr(val)}"
    return None


def _check_ip_collection(val) -> str | None:
    """Ensure value is an IPv4 address or a sequence of them."""
    if isinstance(val, (list, tuple)):
        for element in val:
            if not _looks_like_ipv4(element):
                return f"invalid IP in list: {_clamp_repr(element)}"
    elif not _looks_like_ipv4(val):
        return f"invalid IP address: {_clamp_repr(val)}"
    return None


def _check_printable_text(val) -> str | None:
    """Ensure value consists of printable characters."""
    if not _text_is_clean(val):
        return f"non-printable bytes in value: {_clamp_repr(val)}"
    return None


def _check_msg_type(val) -> str | None:
    """DHCP message-type must be an integer in 1..8 (RFC 2132 sec 9.6)."""
    try:
        numeric = int(val)
    except (TypeError, ValueError):
        return f"non-integer message type: {_clamp_repr(val)}"
    if not 1 <= numeric <= 8:
        return f"message type {numeric} outside RFC range 1-8"
    return None


def _check_param_request(val) -> str | None:
    """Parameter request list entries must each be in 1..254."""
    if isinstance(val, (list, tuple, bytes)):
        for item in val:
            code = int(item)
            if not 1 <= code <= 254:
                return f"option number {code} outside valid range 1-254"
    return None


def _check_duration(val) -> str | None:
    """Lease / renewal / rebinding times are 32-bit unsigned, nonzero."""
    try:
        numeric = int(val)
    except (TypeError, ValueError):
        return f"non-integer lease time: {_clamp_repr(val)}"
    if numeric <= 0 or numeric > 0xFFFFFFFF:
        return f"lease time {numeric} outside valid range 1-4294967295"
    return None


def _check_max_msg_size(val) -> str | None:
    """Maximum DHCP message size must be >= 576 (RFC 2132 sec 9.10)."""
    try:
        numeric = int(val)
    except (TypeError, ValueError):
        return f"non-integer max DHCP size: {_clamp_repr(val)}"
    if numeric < 576 or numeric > 65535:
        return f"max DHCP size {numeric} outside valid range 576-65535"
    return None


def _check_nonempty(val) -> str | None:
    """Value must be present and non-empty."""
    if val is None or (isinstance(val, (bytes, str)) and len(val) == 0):
        return "empty value"
    return None


# ---------------------------------------------------------------------------
# Option registry -- maps scapy option names to (type label, checker)
# ---------------------------------------------------------------------------

FIELD_RULES: dict[str, tuple[str, callable]] = {
    # Address fields
    "subnet_mask":          ("ipv4_address",        _check_single_ip),
    "requested_addr":       ("ipv4_address",        _check_single_ip),
    "server_id":            ("ipv4_address",        _check_single_ip),
    "broadcast_address":    ("ipv4_address",        _check_single_ip),
    # Address-list fields
    "router":               ("ipv4_address_list",   _check_ip_collection),
    "name_server":          ("ipv4_address_list",   _check_ip_collection),
    "NIS_server":           ("ipv4_address_list",   _check_ip_collection),
    "NTP_server":           ("ipv4_address_list",   _check_ip_collection),
    # Text fields
    "domain":               ("printable_string",    _check_printable_text),
    "hostname":             ("printable_string",    _check_printable_text),
    "vendor_class_id":      ("printable_string",    _check_printable_text),
    "NIS_domain":           ("printable_string",    _check_printable_text),
    "TFTP_server_name":     ("printable_string",    _check_printable_text),
    "boot-file-name":       ("printable_string",    _check_printable_text),
    # Numeric / byte fields
    "param_req_list":       ("byte_sequence_1_254", _check_param_request),
    "lease_time":           ("uint32_positive",     _check_duration),
    "renewal_time":         ("uint32_positive",     _check_duration),
    "rebinding_time":       ("uint32_positive",     _check_duration),
    "message-type":         ("uint8_1_8",           _check_msg_type),
    "max_dhcp_size":        ("uint16_gte_576",      _check_max_msg_size),
    "client_id":            ("nonempty_bytes",       _check_nonempty),
}

# Keep the old constant name available for anything that referenced it
RFC_OPTION_REGISTRY = FIELD_RULES

# Server-only options should not appear in client requests
SERVER_ONLY_OPTIONS = frozenset({
    "server_id", "lease_time", "renewal_time", "rebinding_time",
    "subnet_mask", "router", "name_server",
})

# Relay-agent options are suspicious when sent by an endpoint
RELAY_AGENT_OPTIONS = frozenset({
    "relay_agent_Information",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clamp_repr(val) -> str:
    """Produce a length-limited string representation safe for log output."""
    if isinstance(val, bytes):
        return val[:64].hex() + ("..." if len(val) > 64 else "")
    text = str(val)
    return text[:128] + ("..." if len(text) > 128 else "")

# Legacy name
_safe_repr = _clamp_repr


def _persist_anomalies(records: list[dict], target_dir: Path) -> None:
    """Append anomaly records to the JSONL log, rotating when it grows too large."""
    dest = target_dir / "dhcp_anomalies.jsonl"
    try:
        if dest.exists() and dest.stat().st_size > ANOMALY_LOG_CEILING:
            archive = target_dir / "dhcp_anomalies.1.jsonl"
            if archive.exists():
                archive.unlink()
            dest.rename(archive)

        with open(dest, "a") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
    except OSError as exc:
        _log.warning("Failed to write DHCP anomaly log: %s", exc)

# Legacy name
_write_anomalies = _persist_anomalies


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def inspect_dhcp_fields(
    raw_options: dict,
    src_mac: str,
    src_ip: str,
    data_dir: Path,
) -> list[dict]:
    """Scan DHCP option values for RFC 2132 violations and log any findings.

    Parameters
    ----------
    raw_options : dict
        Option name -> value mapping extracted from the DHCP packet.
    src_mac : str
        Sender hardware address.
    src_ip : str
        Sender protocol address.
    data_dir : Path
        Directory where the anomaly JSONL file is written.

    Returns
    -------
    list[dict]
        Each dict describes one detected anomaly (also persisted to disk).
    """
    irregularities: list[dict] = []
    ts = datetime.now().isoformat()

    # Classify packet direction
    pkt_msg_type = raw_options.get("message-type")
    from_client = pkt_msg_type in (1, 3, 4, 7, 8) if pkt_msg_type else False

    # --- Pass 1: relay-agent option in a client packet ---
    for opt_name, opt_val in raw_options.items():
        if opt_name in RELAY_AGENT_OPTIONS and from_client:
            irregularities.append({
                "timestamp": ts,
                "src_mac": src_mac,
                "src_ip": src_ip,
                "option": opt_name,
                "expected_type": "relay_only",
                "actual_value": _clamp_repr(opt_val),
                "reason": "relay agent option in client packet",
            })

    # --- Pass 2: RFC field-level validation ---
    for opt_name, opt_val in raw_options.items():
        rule = FIELD_RULES.get(opt_name)
        if rule is None:
            continue
        type_label, checker = rule
        failure = checker(opt_val)
        if failure:
            irregularities.append({
                "timestamp": ts,
                "src_mac": src_mac,
                "src_ip": src_ip,
                "option": opt_name,
                "expected_type": type_label,
                "actual_value": _clamp_repr(opt_val),
                "reason": failure,
            })

    # Flush to disk
    if irregularities:
        _persist_anomalies(irregularities, data_dir)

    return irregularities


# Backward-compatibility alias
analyze_dhcp_options = inspect_dhcp_fields
