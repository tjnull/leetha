"""SNMP (Simple Network Management Protocol) parser.

Extracts community strings (v1/v2c -- plaintext), version,
and PDU type from SNMP packets.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

# OID-to-field mapping for system MIB objects.
# OIDs may appear with or without the trailing .0 (scalar instance).
_SYSTEM_OIDS: dict[str, str] = {
    "1.3.6.1.2.1.1.1":   "sys_descr",
    "1.3.6.1.2.1.1.1.0": "sys_descr",
    "1.3.6.1.2.1.1.2":   "sys_object_id",
    "1.3.6.1.2.1.1.2.0": "sys_object_id",
    "1.3.6.1.2.1.1.4":   "sys_contact",
    "1.3.6.1.2.1.1.4.0": "sys_contact",
    "1.3.6.1.2.1.1.5":   "sys_name",
    "1.3.6.1.2.1.1.5.0": "sys_name",
    "1.3.6.1.2.1.1.6":   "sys_location",
    "1.3.6.1.2.1.1.6.0": "sys_location",
}


def _extract_varbinds(pdu, result: dict) -> None:
    """Extract known system-MIB fields from SNMP VarBinds."""
    try:
        varbindlist = getattr(pdu, "varbindlist", None)
        if not varbindlist:
            return
        for vb in varbindlist:
            oid = str(vb.oid.val)
            field_name = _SYSTEM_OIDS.get(oid)
            if field_name is None:
                continue
            # Decode value -- may be bytes or already a string/OID
            raw_val = vb.value.val if hasattr(vb.value, "val") else vb.value
            if isinstance(raw_val, bytes):
                value = raw_val.decode("utf-8", errors="replace")
            else:
                value = str(raw_val)
            if value:
                result[field_name] = value
    except Exception:
        logger.debug("Failed to extract SNMP VarBinds", exc_info=True)


def parse_snmp(packet) -> dict | None:
    """Parse SNMP packet and extract community string and version."""
    try:
        from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPset, SNMPtrapv1
    except ImportError:
        return None

    if not packet.haslayer(SNMP):
        return None

    snmp = packet[SNMP]
    result = {"protocol": "snmp"}

    try:
        # Version
        version = int(snmp.version)
        result["version"] = {0: "v1", 1: "v2c", 2: "v2c", 3: "v3"}.get(version, f"v{version}")

        # Community string (only in v1/v2c -- plaintext!)
        if hasattr(snmp, "community") and snmp.community:
            community = snmp.community
            if isinstance(community, bytes):
                community = community.decode("utf-8", errors="replace")
            result["community"] = str(community)

        # PDU type
        if snmp.haslayer(SNMPget):
            result["pdu_type"] = "get-request"
        elif snmp.haslayer(SNMPresponse):
            result["pdu_type"] = "get-response"
        elif snmp.haslayer(SNMPset):
            result["pdu_type"] = "set-request"
        elif snmp.haslayer(SNMPtrapv1):
            result["pdu_type"] = "trap"
        else:
            result["pdu_type"] = "unknown"

        # Extract variable bindings from GetResponse packets
        if snmp.haslayer(SNMPresponse):
            _extract_varbinds(snmp.PDU, result)

    except Exception:
        pass

    return result if len(result) > 1 else None
