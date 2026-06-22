"""Ingestion routines for upstream fingerprint data feeds.

Each ``ingest_*`` function accepts raw text content from a downloaded feed
and returns a structured dict (or list) ready for caching and lookup.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
from io import StringIO

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex for the IEEE OUI hex-format text file (used as fallback)
# ---------------------------------------------------------------------------
_OUI_HEX_RE = re.compile(
    r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Well-known vendor shorthands (OUI normalisation)
# ---------------------------------------------------------------------------
_VENDOR_SHORTHANDS: dict[str, str] = {
    "Cisco Systems, Inc": "Cisco",
    "Apple, Inc.": "Apple",
    "Dell Inc.": "Dell",
    "Hewlett Packard": "HP",
    "Intel Corporate": "Intel",
    "Microsoft Corporation": "Microsoft",
    "Samsung Electronics Co.,Ltd": "Samsung",
    "VMware, Inc.": "VMware",
    "Ubiquiti Inc": "Ubiquiti",
    "TP-LINK TECHNOLOGIES CO.,LTD.": "TP-Link",
    "Raspberry Pi Foundation": "Raspberry Pi",
}

# ---------------------------------------------------------------------------
# DHCP vendor-class keyword map
# ---------------------------------------------------------------------------
_VENDOR_CLASS_KEYWORDS: dict[str, str] = {
    "msft": "Microsoft", "cisco": "Cisco", "apple": "Apple",
    "android": "Android", "linux": "Linux", "ubuntu": "Ubuntu",
    "debian": "Debian", "redhat": "Red Hat", "centos": "CentOS",
    "fedora": "Fedora", "vmware": "VMware", "dell": "Dell",
    "hp": "HP", "lenovo": "Lenovo", "xerox": "Xerox",
    "canon": "Canon", "epson": "Epson", "brother": "Brother",
    "samsung": "Samsung", "lg": "LG", "sony": "Sony",
    "philips": "Philips", "panasonic": "Panasonic",
    "honeywell": "Honeywell", "juniper": "Juniper",
    "fortinet": "Fortinet", "paloalto": "Palo Alto",
    "aruba": "Aruba", "ubiquiti": "Ubiquiti", "meraki": "Meraki",
    "synology": "Synology", "qnap": "QNAP", "netgear": "Netgear",
    "asus": "ASUS", "linksys": "Linksys", "tp-link": "TP-Link",
    "dlink": "D-Link", "zyxel": "ZyXEL", "mikrotik": "MikroTik",
    "ruckus": "Ruckus", "cambium": "Cambium",
}


# ===================================================================
# Internal helpers
# ===================================================================

def _shorten_vendor(full_name: str) -> str:
    """Return a short vendor label, using known shorthands or truncating."""
    lowered = full_name.lower()
    for long_form, short_form in _VENDOR_SHORTHANDS.items():
        if long_form.lower() in lowered:
            return short_form
    return full_name[:27] + "..." if len(full_name) > 30 else full_name


def _fingerprint_dhcp_opts(raw_options: str) -> str:
    """Produce a stable MD5 digest of a comma-separated DHCP options string."""
    cleaned = sorted(tok.strip() for tok in raw_options.split(",") if tok.strip())
    return hashlib.md5(",".join(cleaned).encode()).hexdigest()


def _guess_vendor_from_class(vc_string: str) -> str | None:
    """Match a DHCP vendor-class string against known keywords."""
    if not vc_string:
        return None
    lower = vc_string.lower()
    for kw, vendor_name in _VENDOR_CLASS_KEYWORDS.items():
        if kw in lower:
            return vendor_name
    return None


def _normalise_oui(raw: str) -> str:
    """Normalise an OUI string to upper-case colon-separated form."""
    oui = raw.upper().replace("-", ":").replace(".", ":")
    if len(oui) == 6:
        oui = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"
    return oui


# ===================================================================
# Public ingestion functions
# ===================================================================

def ingest_oui(content: str) -> dict:
    """Ingest OUI data (CSV or IEEE hex-text) into ``{prefix: info}``."""
    if content.startswith("oui,manufacturer"):
        return _ingest_oui_csv(content)
    return _ingest_oui_hex_text(content)


def _ingest_oui_csv(content: str) -> dict:
    """Handle OUI-Master-Database CSV rows."""
    result: dict[str, dict] = {}
    try:
        rdr = csv.DictReader(StringIO(content))
        for row in rdr:
            raw_oui = row.get("oui", "").strip()
            if not raw_oui:
                continue
            prefix = _normalise_oui(raw_oui)
            mfr = row.get("manufacturer", "").strip()
            short = row.get("short_name", "").strip()
            dev_type = row.get("device_type", "").strip()
            reg = row.get("registry", "").strip()
            src = row.get("sources", "").strip()

            rec: dict[str, str] = {
                "vendor": mfr,
                "vendor_short": short if short else _shorten_vendor(mfr),
            }
            if dev_type:
                rec["device_type"] = dev_type
            if reg:
                rec["registry"] = reg
            if src:
                rec["sources"] = src
            result[prefix] = rec
        log.info("Ingested %d OUI entries from CSV", len(result))
    except Exception as exc:
        log.error("OUI CSV ingestion failed: %s", exc)
    return result


def _ingest_oui_hex_text(content: str) -> dict:
    """Handle legacy IEEE hex-format OUI text."""
    result: dict[str, dict] = {}
    for m in _OUI_HEX_RE.finditer(content):
        prefix = m.group(1).replace("-", ":").upper()
        vendor = m.group(2).strip()
        result[prefix] = {
            "vendor": vendor,
            "vendor_short": _shorten_vendor(vendor),
        }
    log.info("Ingested %d OUI entries from hex text", len(result))
    return result


def ingest_p0f(content: str) -> list[dict]:
    """Ingest a p0f.fp file into a list of signature records."""
    sigs: list[dict] = []
    active_class: str | None = None
    active_label: str | None = None

    for raw_line in content.split("\n"):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(";"):
            continue

        # Section header
        if stripped.startswith("[") and stripped.endswith("]"):
            active_class = stripped[1:-1]
            continue

        # Label assignment
        if stripped.startswith("label"):
            _, _, rhs = stripped.partition("=")
            if rhs:
                active_label = rhs.strip()
            continue

        # Signature assignment
        if stripped.startswith("sig"):
            _, _, rhs = stripped.partition("=")
            if rhs:
                rec = _decode_p0f_sig(rhs.strip(), active_class, active_label)
                if rec is not None:
                    sigs.append(rec)

    log.info("Ingested %d p0f signatures", len(sigs))
    return sigs


def _decode_p0f_sig(
    sig_str: str,
    sig_class: str | None,
    label_str: str | None,
) -> dict | None:
    """Decode a single p0f signature line.

    Expected format: ``ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass``
    """
    fields = sig_str.split(":")
    if len(fields) < 6:
        return None
    try:
        # Initial TTL
        ttl_val: int | None = None
        raw_ttl = fields[1]
        if raw_ttl != "*":
            cleaned_ttl = raw_ttl.lstrip("s")
            if cleaned_ttl.isdigit():
                ttl_val = int(cleaned_ttl)

        # MSS
        mss_val: int | None = None
        if fields[3] != "*" and fields[3].isdigit():
            mss_val = int(fields[3])

        # Window size
        win_part = fields[4].split(",")[0]
        win_val: int | None = None
        if win_part != "*" and win_part.isdigit():
            win_val = int(win_part)

        # Extract OS info from label
        os_fam: str | None = None
        os_ver: str | None = None
        if label_str:
            label_parts = label_str.split(":")
            if len(label_parts) >= 3:
                os_fam = label_parts[2]
                os_ver = ":".join(label_parts[3:]) if len(label_parts) > 3 else None
            elif len(label_parts) == 2:
                os_fam = label_parts[1]
            else:
                os_fam = label_str

        return {
            "signature": sig_str,
            "class": sig_class,
            "label": label_str or "Unknown",
            "ttl": ttl_val,
            "window_size": win_val,
            "mss": mss_val,
            "options": fields[5] if len(fields) > 5 else None,
            "quirks": fields[6] if len(fields) > 6 else None,
            "os_family": os_fam,
            "os_version": os_ver,
            "confidence": 80,
        }
    except Exception as exc:
        log.debug("p0f signature decode error for %r: %s", sig_str, exc)
        return None


def ingest_huginn_devices(content: str) -> dict:
    """Ingest Huginn-Muninn device.json into ``{device_id: profile}``."""
    profiles: dict[str, dict] = {}
    name_by_id: dict[str, str] = {}
    parent_of: dict[str, str | None] = {}

    try:
        records = json.loads(content)

        # First sweep: index names and parent pointers
        for rec in records:
            did = str(rec.get("id", ""))
            nm = rec.get("name", "")
            pid = rec.get("parent_id")
            if did and nm:
                name_by_id[did] = nm
                parent_of[did] = str(pid) if pid else None

        # Second sweep: build full entries with hierarchy chains
        for rec in records:
            did = str(rec.get("id", ""))
            if not did:
                continue
            nm = rec.get("name", "")
            pid = rec.get("parent_id")
            pid_str = str(pid) if pid else None

            chain = [nm]
            walker = pid_str
            guard = 0
            while walker and walker in name_by_id and guard < 10:
                chain.insert(0, name_by_id[walker])
                walker = parent_of.get(walker)
                guard += 1

            profile: dict = {
                "name": nm,
                "parent_id": pid_str,
                "hierarchy": chain,
                "hierarchy_str": " > ".join(chain),
                "mobile": bool(rec.get("mobile", 0)),
                "tablet": bool(rec.get("tablet", 0)),
            }
            if rec.get("simplified_name"):
                profile["simplified_name"] = rec["simplified_name"]
            if rec.get("inherit"):
                profile["inherit"] = bool(rec.get("inherit", 0))

            profiles[did] = profile

        log.info("Ingested %d Huginn-Muninn device profiles", len(profiles))
    except Exception as exc:
        log.error("Huginn-Muninn devices ingestion failed: %s", exc)

    return profiles


def ingest_huginn_dhcp(content: str) -> dict:
    """Ingest Huginn-Muninn DHCP signature JSON into a lookup table."""
    table: dict[str, dict] = {}
    try:
        records = json.loads(content)
        for rec in records:
            rid = str(rec.get("id", ""))
            if not rid or rec.get("ignored", 0):
                continue
            val = rec.get("value", "")
            opts = [o.strip() for o in val.split(",") if o.strip()] if val else []
            table[rid] = {
                "value": val,
                "options": opts,
                "options_hash": _fingerprint_dhcp_opts(val),
            }
        log.info("Ingested %d Huginn-Muninn DHCP signatures", len(table))
    except Exception as exc:
        log.error("Huginn-Muninn DHCP ingestion failed: %s", exc)
    return table


def ingest_huginn_dhcp_vendor(content: str) -> dict:
    """Ingest Huginn-Muninn DHCP vendor-class JSON."""
    table: dict[str, dict] = {}
    try:
        records = json.loads(content)
        for rec in records:
            vid = str(rec.get("id", ""))
            if not vid:
                continue
            val = rec.get("value", "")
            row: dict[str, str] = {"value": val}
            guessed = _guess_vendor_from_class(val)
            if guessed:
                row["vendor_hint"] = guessed
            table[vid] = row
        log.info("Ingested %d Huginn-Muninn DHCP vendor entries", len(table))
    except Exception as exc:
        log.error("Huginn-Muninn DHCP vendor ingestion failed: %s", exc)
    return table


def ingest_huginn_combinations(content: str) -> dict:
    """Ingest Huginn-Muninn DHCP combinations JSON.

    Returns a dict keyed by DHCP Option 55 value, each mapping to a list
    of matching device descriptors.
    """
    opt55_map: dict[str, list[dict]] = {}
    try:
        records = json.loads(content)
        for rec in records:
            o55 = rec.get("dhcp_option55", "")
            if not o55:
                continue
            descriptor = {
                "dhcp_fingerprint_id": rec.get("dhcp_fingerprint_id"),
                "device_id": rec.get("device_id"),
                "satori_name": rec.get("satori_name", ""),
                "device_type": rec.get("device_type", ""),
                "device_vendor": rec.get("device_vendor", ""),
            }
            opt55_map.setdefault(o55, []).append(descriptor)

        total_combos = sum(len(v) for v in opt55_map.values())
        log.info(
            "Ingested %d Huginn-Muninn DHCP combinations across %d fingerprints",
            total_combos, len(opt55_map),
        )
    except Exception as exc:
        log.error("Huginn-Muninn combinations ingestion failed: %s", exc)
    return opt55_map


def ingest_huginn_dhcpv6(content: str) -> dict:
    """Ingest Huginn-Muninn DHCPv6 signature JSON."""
    table: dict[str, dict] = {}
    try:
        records = json.loads(content)
        for rec in records:
            rid = str(rec.get("id", ""))
            if not rid:
                continue
            val = rec.get("value", "")
            opts = [o.strip() for o in val.split(",") if o.strip()] if val else []
            table[rid] = {
                "value": val,
                "options": opts,
                "options_hash": _fingerprint_dhcp_opts(val),
            }
        log.info("Ingested %d Huginn-Muninn DHCPv6 signatures", len(table))
    except Exception as exc:
        log.error("Huginn-Muninn DHCPv6 ingestion failed: %s", exc)
    return table


def ingest_huginn_dhcpv6_enterprise(content: str) -> dict:
    """Ingest Huginn-Muninn DHCPv6 enterprise IDs JSON."""
    table: dict[str, dict] = {}
    try:
        records = json.loads(content)
        for rec in records:
            eid = str(rec.get("id", ""))
            if not eid:
                continue
            table[eid] = {
                "value": rec.get("value", ""),
                "organization": rec.get("organization", ""),
            }
        log.info("Ingested %d Huginn-Muninn DHCPv6 enterprise entries", len(table))
    except Exception as exc:
        log.error("Huginn-Muninn DHCPv6 enterprise ingestion failed: %s", exc)
    return table


def ingest_iana_enterprise(content: str) -> dict:
    """Ingest the IANA enterprise-numbers text file.

    The file uses a four-line record format::

        <decimal_id>
          <organisation>
            <contact>
              <email>

    Returns ``{enterprise_id: vendor_name}``.
    """
    mapping: dict[str, str] = {}
    try:
        all_lines = content.split("\n")
        pos = 0
        while pos < len(all_lines):
            cur = all_lines[pos].rstrip()
            if cur and cur.strip().isdigit():
                eid = cur.strip()
                if pos + 1 < len(all_lines):
                    org = all_lines[pos + 1].strip()
                    if org:
                        mapping[eid] = org
                pos += 4
            else:
                pos += 1
        log.info("Ingested %d IANA enterprise entries", len(mapping))
    except Exception as exc:
        log.error("IANA enterprise ingestion failed: %s", exc)
    return mapping


def ingest_ja3(content: str) -> dict:
    """Ingest Salesforce JA3 fingerprint data (auto-detects JSON vs CSV).

    Returns ``{ja3_hash: {app, os_family, description}}``.
    """
    trimmed = content.lstrip()
    if trimmed.startswith("[") or trimmed.startswith("{"):
        return _ingest_ja3_json(content)
    return _ingest_ja3_csv(content)


def _ingest_ja3_json(content: str) -> dict:
    """Handle JA3 data in JSON format."""
    table: dict[str, dict] = {}
    try:
        blob = json.loads(content)
        if isinstance(blob, list):
            for item in blob:
                h = item.get("ja3_hash") or item.get("md5")
                if h:
                    table[h] = {
                        "app": item.get("User-Agent") or item.get("desc", ""),
                        "os_family": item.get("os"),
                        "description": item.get("desc", ""),
                    }
        log.info("Ingested %d JA3 fingerprints from JSON", len(table))
    except Exception as exc:
        log.error("JA3 JSON ingestion failed: %s", exc)
    return table


def _ingest_ja3_csv(content: str) -> dict:
    """Handle JA3 data in CSV format (no header row)."""
    table: dict[str, dict] = {}
    try:
        for raw in content.splitlines():
            ln = raw.strip()
            if not ln or ln.startswith("#"):
                continue
            sep = ln.find(",")
            if sep == -1:
                continue
            digest = ln[:sep].strip()
            apps_str = ln[sep + 1:].strip().strip('"')
            if digest and len(digest) == 32:
                table[digest] = {
                    "app": apps_str,
                    "os_family": None,
                    "description": apps_str,
                }
        log.info("Ingested %d JA3 fingerprints from CSV", len(table))
    except Exception as exc:
        log.error("JA3 CSV ingestion failed: %s", exc)
    return table


def ingest_ja4(content: str) -> dict:
    """Ingest JA4+ fingerprint database from ja4db.com.

    Handles multiple fingerprint subtypes per entry (ja4, ja4s, ja4h, etc.).
    Returns ``{fingerprint_value: {app, os_family, fp_type, ...}}``.
    """
    table: dict[str, dict] = {}
    subtype_fields = [
        "ja4_fingerprint", "ja4s_fingerprint", "ja4h_fingerprint",
        "ja4x_fingerprint", "ja4t_fingerprint", "ja4ts_fingerprint",
        "ja4tscan_fingerprint",
    ]
    try:
        blob = json.loads(content)
        items = blob if isinstance(blob, list) else blob.get("data", [])
        for item in items:
            app_label = (
                item.get("application")
                or item.get("library")
                or item.get("desc")
                or ""
            )
            os_info = item.get("os")
            for sf in subtype_fields:
                fp_val = item.get(sf)
                if fp_val:
                    st = sf.replace("_fingerprint", "")
                    table[fp_val] = {
                        "app": app_label,
                        "os_family": os_info,
                        "fp_type": st,
                        "description": item.get("notes") or app_label,
                        "user_agent": item.get("user_agent_string"),
                    }
        log.info("Ingested %d JA4+ fingerprints", len(table))
    except Exception as exc:
        log.error("JA4 ingestion failed: %s", exc)
    return table


# Fingerprint columns in FoxIO's ja4plus-mapping.csv. The column name is
# used directly as the fp_type.
_JA4_CSV_FP_COLUMNS = ("ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan")


def ingest_ja4_csv(content: str) -> dict:
    """Ingest the FoxIO JA4+ database from ``ja4plus-mapping.csv``.

    The canonical ja4db.com JSON API went offline, so we read FoxIO's
    GitHub-hosted CSV mirror instead. Columns:

        Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes

    Each non-empty fingerprint column becomes its own table entry, keyed
    by the fingerprint value. Output matches :func:`ingest_ja4` so the
    lookup consumer is unchanged:
    ``{fp_value: {app, os_family, fp_type, description, user_agent}}``.
    """
    table: dict[str, dict] = {}
    try:
        reader = csv.DictReader(StringIO(content))
        # Bail cleanly if this isn't the expected mapping CSV.
        if not reader.fieldnames or "ja4" not in reader.fieldnames:
            return table
        for row in reader:
            app_label = (
                (row.get("Application") or "").strip()
                or (row.get("Library") or "").strip()
                or (row.get("Device") or "").strip()
            )
            os_info = (row.get("OS") or "").strip() or None
            notes = (row.get("Notes") or "").strip()
            for col in _JA4_CSV_FP_COLUMNS:
                fp_val = (row.get(col) or "").strip()
                if not fp_val:
                    continue
                table[fp_val] = {
                    "app": app_label,
                    "os_family": os_info,
                    "fp_type": col,
                    "description": notes or app_label,
                    "user_agent": None,
                }
        log.info("Ingested %d JA4+ fingerprints (CSV)", len(table))
    except Exception as exc:
        log.error("JA4 CSV ingestion failed: %s", exc)
    return table


# ===================================================================
# Backward-compatible aliases (parse_* -> ingest_*)
# ===================================================================
parse_oui_csv = ingest_oui
parse_p0f = ingest_p0f
parse_huginn_devices = ingest_huginn_devices
parse_huginn_dhcp = ingest_huginn_dhcp
parse_huginn_dhcp_vendor = ingest_huginn_dhcp_vendor
parse_huginn_combinations = ingest_huginn_combinations
parse_huginn_dhcpv6 = ingest_huginn_dhcpv6
parse_huginn_dhcpv6_enterprise = ingest_huginn_dhcpv6_enterprise
parse_iana_enterprise = ingest_iana_enterprise
parse_ja3_database = ingest_ja3
parse_ja4_database = ingest_ja4
parse_ja4_csv = ingest_ja4_csv


# ===================================================================
# Satori fingerprint parser (generic for all 13 Satori JSON files)
# ===================================================================

def ingest_satori(content: str) -> list[dict]:
    """Parse a Satori fingerprint JSON file.

    All Satori files share the same schema: a list of entries, each with
    device metadata (name, os_name, os_class, os_vendor, device_type,
    device_vendor) and a ``tests`` array of protocol-specific match rules.

    Returns the list as-is — indexing happens at load time in the matcher.
    """
    raw = json.loads(content)
    if not isinstance(raw, list):
        return []
    return raw


parse_satori = ingest_satori

# Also expose old private helper names in case anything references them
_abbreviate_vendor = _shorten_vendor
_hash_dhcp_options = _fingerprint_dhcp_opts
_extract_vendor_from_dhcp_class = _guess_vendor_from_class

# Keep old constant names accessible
OUI_PATTERN = _OUI_HEX_RE
_VENDOR_ABBREVIATIONS = _VENDOR_SHORTHANDS
_DHCP_VENDOR_PATTERNS = _VENDOR_CLASS_KEYWORDS
