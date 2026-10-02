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
    # High-frequency vendors that were previously falling through: between
    # them these account for tens of thousands of otherwise-unattributed
    # vendor-class strings in the Huginn table.
    "lexmark": "Lexmark", "huawei": "Huawei", "shelly": "Shelly",
    "shoretel": "ShoreTel", "axis": "Axis Communications",
    "tenda": "Tenda", "hewlett packard": "HP", "hewlett-packard": "HP",
    "kyocera": "Kyocera", "ricoh": "Ricoh", "sharp": "Sharp",
    "toshiba": "Toshiba", "zebra": "Zebra", "polycom": "Polycom",
    "yealink": "Yealink", "grandstream": "Grandstream",
    "hikvision": "Hikvision", "dahua": "Dahua", "amazon": "Amazon",
    "roku": "Roku", "sonos": "Sonos", "nest": "Nest", "ecobee": "ecobee",
    "tplink": "TP-Link", "technicolor": "Technicolor",
    "arris": "Arris", "sagemcom": "Sagemcom", "zte": "ZTE",
    "siemens": "Siemens", "schneider": "Schneider Electric",
    "rockwell": "Rockwell Automation", "moxa": "Moxa",
}

# Self-describing vendor classes used by most network printers and some
# appliances: "Mfg=Hewlett Packard;Typ=Printer;Mod=HP LaserJet 400;Ser=..."
# These carry vendor, device type, and model outright -- far better than a
# keyword guess -- and account for thousands of rows on their own.
_VC_STRUCTURED_RE = re.compile(
    r"\b(mfg|typ|mod)\s*=\s*([^;]+)", re.IGNORECASE
)


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


def _parse_vendor_class_fields(vc_string: str) -> dict[str, str]:
    """Extract Mfg / Typ / Mod fields from a structured vendor class.

    Returns ``{}`` when the string isn't in the structured form.
    """
    if not vc_string or "=" not in vc_string:
        return {}
    found = {
        key.lower(): val.strip()
        for key, val in _VC_STRUCTURED_RE.findall(vc_string)
        if val.strip()
    }
    if not found:
        return {}
    out: dict[str, str] = {}
    if found.get("mfg"):
        out["vendor"] = found["mfg"]
    if found.get("typ"):
        out["device_type"] = found["typ"]
    if found.get("mod"):
        out["model"] = found["mod"]
    return out


def _guess_vendor_from_class(vc_string: str) -> str | None:
    """Match a DHCP vendor-class string against known keywords.

    A structured ``Mfg=...`` field is authoritative and wins over the
    keyword table.
    """
    if not vc_string:
        return None
    structured = _parse_vendor_class_fields(vc_string)
    if structured.get("vendor"):
        return structured["vendor"]
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
    if content.lstrip("\ufeff \t\r\n").startswith("oui,manufacturer"):
        return _ingest_oui_csv(content)
    return _ingest_oui_hex_text(content)


def _ingest_oui_csv(content: str) -> dict:
    """Handle OUI-Master-Database CSV rows."""
    result: dict[str, dict] = {}
    try:
        rdr = csv.DictReader(StringIO(content.lstrip("\ufeff")))
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
            for field in ("registrant_raw", "status", "deregistered_date", "registrant_history",
                          "registered_date", "country", "address"):
                value = (row.get(field) or "").strip()
                if value:
                    rec[field] = value
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


def ingest_huginn_dhcp_vendor(content: str) -> dict:
    """Ingest Huginn-Muninn DHCP vendor-class JSON."""
    table: dict[str, dict] = {}
    try:
        records = json.loads(content)
        for rec in records:
            vid = str(rec.get("id", ""))
            if not vid or rec.get("ignored", 0):
                continue
            val = rec.get("value", "")
            row: dict[str, str] = {"value": val}
            structured = _parse_vendor_class_fields(val)
            guessed = _guess_vendor_from_class(val)
            if guessed:
                row["vendor_hint"] = guessed
            # A structured class also names the device type and model.
            if structured.get("device_type"):
                row["device_type"] = structured["device_type"]
            if structured.get("model"):
                row["model"] = structured["model"]
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
                "device_match": rec.get("device_match", ""),
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


def ingest_apple_devices(content: str) -> dict:
    """Index AppleDB records by advertised hardware model identifier."""
    result: dict[str, dict] = {}
    records = json.loads(content)
    if isinstance(records, dict):
        records = records.get("devices", records.get("entries", records))
    if isinstance(records, dict):
        records = [dict(rec, identifier=key) if isinstance(rec, dict) and not any(
            rec.get(field) for field in ("identifiers", "identifier", "model_identifier", "model_id")
        ) else rec for key, rec in records.items()]
    if not isinstance(records, list):
        return result
    for rec in records:
        if not isinstance(rec, dict):
            continue
        identifiers = (rec.get("identifiers") or rec.get("identifier")
                       or rec.get("model_identifiers") or rec.get("model_identifier")
                       or rec.get("model_id") or rec.get("model"))
        if isinstance(identifiers, str):
            identifiers = [identifiers]
        if not isinstance(identifiers, list):
            continue
        name = rec.get("name") or rec.get("marketing_name")
        if not name:
            continue
        for identifier in identifiers:
            if isinstance(identifier, str) and identifier.strip():
                result[identifier.strip()] = {
                    "name": name,
                    "soc": rec.get("soc") or rec.get("chip"),
                    "release": rec.get("release") or rec.get("release_date"),
                }
    return result



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


# Description keywords -> OS family. The Trisul feed carries no explicit
# "os" field, so without this every synced JA3 hit produced a match with no
# identity at all. Ordered: the first match wins, so put specific platforms
# ahead of the generic ones they contain.
_JA3_OS_HINTS: tuple[tuple[str, str], ...] = (
    ("android", "Android"),
    ("iphone", "iOS"), ("ipad", "iOS"), (" ios", "iOS"),
    ("osx", "macOS"), ("os x", "macOS"), ("macos", "macOS"),
    ("windows", "Windows"), ("win7", "Windows"), ("win10", "Windows"),
    ("linux", "Linux"), ("ubuntu", "Linux"), ("debian", "Linux"),
)

# Entries that describe malware or scanner traffic rather than a device.
# leetha is a device-discovery and OS-identification tool, not a threat
# feed, so these are dropped at ingest: they carry no vendor, OS, or device
# type, and surfacing them would put malware labels in the host inventory.
_JA3_NON_DEVICE_PREFIXES = ("malware:", "scanner:")


def _classify_ja3_description(label: str) -> dict:
    """Infer OS and device type from a JA3 description.

    Returns ``{"skip": True}`` for records that identify malware or scanner
    traffic instead of a device.
    """
    out: dict = {}
    if not label:
        return out
    lowered = label.lower()

    if lowered.startswith(_JA3_NON_DEVICE_PREFIXES):
        return {"skip": True}

    for needle, os_name in _JA3_OS_HINTS:
        if needle in lowered:
            out["os_family"] = os_name
            break

    # An Android/iOS app fingerprint means a handset, not a general host.
    if out.get("os_family") in ("Android", "iOS"):
        out["device_type"] = "mobile"

    # "JA3S:" entries fingerprint a *server* hello, so they can never match
    # a client hello -- flag them rather than letting them look like misses.
    if lowered.startswith("ja3s:"):
        out["direction"] = "server"

    return out


def _ja3_record(item: dict) -> tuple[str, dict] | None:
    """Normalise one JA3 record into ``(hash, info)``."""
    if not isinstance(item, dict):
        return None
    digest = item.get("ja3_hash") or item.get("md5")
    if not digest:
        return None
    label = item.get("User-Agent") or item.get("desc") or item.get("description") or ""
    derived = _classify_ja3_description(label)
    if derived.get("skip"):
        return None
    info = {
        "app": label,
        "os_family": item.get("os"),
        "description": label,
        # Trisul ships the raw JA3 string alongside the digest; keeping it
        # lets a future matcher fall back to string comparison.
        "ja3_str": item.get("ja3_str"),
    }
    if not info["os_family"]:
        info["os_family"] = derived.get("os_family")
    for key in ("device_type", "direction"):
        if key in derived:
            info[key] = derived[key]
    return str(digest).strip(), info


def _ingest_ja3_json(content: str) -> dict:
    """Handle JA3 data in JSON or JSON-lines format.

    The Trisul feed is newline-delimited JSON (one object per line), which
    ``json.loads`` on the whole document rejects, so fall back to parsing
    line by line.
    """
    table: dict[str, dict] = {}
    try:
        blob = json.loads(content)
        items = blob if isinstance(blob, list) else [blob]
    except json.JSONDecodeError:
        items = []
        for raw in content.splitlines():
            line = raw.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for item in items:
        rec = _ja3_record(item)
        if rec:
            table[rec[0]] = rec[1]

    log.info("Ingested %d JA3 fingerprints from JSON", len(table))
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
                rec = {
                    "app": apps_str,
                    "os_family": None,
                    "description": apps_str,
                }
                # Same enrichment the JSON path gets, so an alternate
                # CSV source still yields OS and device-type inference.
                derived = _classify_ja3_description(apps_str)
                if derived.pop("skip", False):
                    continue
                rec.update(derived)
                table[digest] = rec
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
parse_huginn_dhcp_vendor = ingest_huginn_dhcp_vendor
parse_huginn_combinations = ingest_huginn_combinations
parse_apple_devices = ingest_apple_devices
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


# ===================================================================
# Rapid7 Recog fingerprint parser (one XML file per banner/header type)
# ===================================================================

def ingest_recog(content: str, fallback_key: str | None = None) -> dict:
    """Parse one Rapid7 Recog XML fingerprint file.

    Returns ``{match_type: [fingerprint, ...]}`` keyed by the file's
    ``matches`` attribute (e.g. ``ssh.banner``, ``http_header.server``).
    Each fingerprint is ``{pattern, params, description}`` where ``params``
    are the ``<param pos name value>`` extractions (``value`` is None for
    capture-group extractions resolved at match time). The multifile sync
    merges files by their (distinct) match type.

    A few upstream files (telnet_banners.xml) omit ``matches`` entirely.
    Those fall back to *fallback_key* -- normally derived from the filename
    -- because keying them all as "unknown" made any two such files
    silently overwrite each other during the merge.
    """
    import xml.etree.ElementTree as ET

    out: dict[str, list] = {}
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        log.warning("Recog XML parse failed: %s", exc)
        return out

    match_type = root.get("matches") or fallback_key or "unknown"
    fps: list[dict] = []
    for fp in root.findall("fingerprint"):
        pattern = fp.get("pattern")
        if not pattern:
            continue
        params = []
        for p in fp.findall("param"):
            try:
                pos = int(p.get("pos", 0))
            except (TypeError, ValueError):
                pos = 0
            params.append({"pos": pos, "name": p.get("name", ""), "value": p.get("value")})
        desc_el = fp.find("description")
        desc = (desc_el.text or "").strip() if desc_el is not None and desc_el.text else ""
        fps.append({"pattern": pattern, "params": params, "description": desc})

    if fps:
        out[match_type] = fps
    log.info("Ingested %d Recog '%s' fingerprints", len(fps), match_type)
    return out


parse_recog = ingest_recog

# Also expose old private helper names in case anything references them
_abbreviate_vendor = _shorten_vendor
_hash_dhcp_options = _fingerprint_dhcp_opts
_extract_vendor_from_dhcp_class = _guess_vendor_from_class

# Keep old constant names accessible
OUI_PATTERN = _OUI_HEX_RE
_VENDOR_ABBREVIATIONS = _VENDOR_SHORTHANDS
_DHCP_VENDOR_PATTERNS = _VENDOR_CLASS_KEYWORDS
