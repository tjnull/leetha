"""IoT/SCADA protocol parsers -- Modbus TCP, BACnet/IP, CoAP, MQTT, EtherNet/IP.

Each parser extracts fields from raw payloads and returns a CapturedPacket
whose protocol name matches the processor registration in
``leetha.processors.iot_scada``.
"""
from __future__ import annotations

import struct

from leetha.capture.packets import CapturedPacket


# ---------------------------------------------------------------------------
# Modbus TCP (port 502)
# ---------------------------------------------------------------------------

def parse_modbus(packet) -> CapturedPacket | None:
    """Parse Modbus TCP packets on port 502.

    MBAP header (7 bytes):
      0-1  Transaction ID
      2-3  Protocol ID (must be 0x0000 for Modbus)
      4-5  Length
      6    Unit ID
    PDU byte 0 = function code.
    """
    from scapy.all import IP, TCP, UDP, Raw

    if not packet.haslayer(IP):
        return None

    sport = dport = None
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
    else:
        return None

    if sport != 502 and dport != 502:
        return None

    try:
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
        else:
            payload = bytes(packet[UDP].payload)
    except Exception:
        return None

    # MBAP header (7 bytes) + at least 1 byte function code
    if len(payload) < 8:
        return None

    # Protocol ID must be 0x0000
    proto_id = struct.unpack("!H", payload[2:4])[0]
    if proto_id != 0x0000:
        return None

    unit_id = payload[6]
    function_code = payload[7]

    return CapturedPacket(
        protocol="modbus",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "unit_id": unit_id,
            "function_code": function_code,
        },
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


# ---------------------------------------------------------------------------
# BACnet/IP (UDP port 47808)
# ---------------------------------------------------------------------------

def parse_bacnet(packet) -> CapturedPacket | None:
    """Parse BACnet/IP packets on UDP port 47808 (0xBAC0).

    BVLC header:
      Byte 0: Type (0x81 = BACnet/IP)
      Byte 1: Function
      Byte 2-3: Length
    """
    from scapy.all import IP, UDP

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    if udp.dport != 47808 and udp.sport != 47808:
        return None

    try:
        payload = bytes(udp.payload)
    except Exception:
        return None

    if len(payload) < 4:
        return None

    # BVLC type must be 0x81
    if payload[0] != 0x81:
        return None

    bvlc_function = payload[1]

    fields: dict = {
        "bvlc_function": bvlc_function,
    }

    # Attempt to extract vendor_id, object_name, model_name from deeper
    # APDU layers if present.  BACnet APDU parsing is complex; we do
    # best-effort extraction of common tagged values.
    _extract_bacnet_fields(payload[4:], fields)

    return CapturedPacket(
        protocol="bacnet",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _extract_bacnet_fields(data: bytes, fields: dict) -> None:
    """Best-effort extraction of BACnet APDU fields.

    Scans for common context-tagged values.  This is intentionally
    shallow -- full BACnet decoding is out of scope for passive
    fingerprinting.
    """
    # Look for vendor_id pattern (context tag 2, unsigned)
    # and character-string values that might be object_name / model_name.
    # For now we just note their absence; deeper parsing can be added later.
    fields.setdefault("vendor_id", None)
    fields.setdefault("object_name", None)
    fields.setdefault("model_name", None)


# ---------------------------------------------------------------------------
# CoAP (UDP port 5683)
# ---------------------------------------------------------------------------

def parse_coap(packet) -> CapturedPacket | None:
    """Parse CoAP packets on UDP port 5683.

    Header (4 bytes minimum):
      Byte 0: Ver (2 bits) | Type (2 bits) | Token Length (4 bits)
      Byte 1: Code (3-bit class . 5-bit detail)
      Byte 2-3: Message ID
    Options follow the header.
    """
    from scapy.all import IP, UDP

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    if udp.dport != 5683 and udp.sport != 5683:
        return None

    try:
        payload = bytes(udp.payload)
    except Exception:
        return None

    if len(payload) < 4:
        return None

    # Version must be 1 (bits 7-6)
    version = (payload[0] >> 6) & 0x03
    if version != 1:
        return None

    msg_type = (payload[0] >> 4) & 0x03
    token_len = payload[0] & 0x0F
    code_class = (payload[1] >> 5) & 0x07
    code_detail = payload[1] & 0x1F

    fields: dict = {
        "message_type": msg_type,
        "code": f"{code_class}.{code_detail:02d}",
        "uri_path": None,
        "content_format": None,
    }

    # Parse options starting after the token
    opt_offset = 4 + token_len
    _parse_coap_options(payload, opt_offset, fields)

    return CapturedPacket(
        protocol="coap",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _parse_coap_options(payload: bytes, offset: int, fields: dict) -> None:
    """Walk CoAP options and extract Uri-Path (11) and Content-Format (12)."""
    opt_number = 0
    uri_parts: list[str] = []

    while offset < len(payload):
        byte = payload[offset]
        if byte == 0xFF:  # payload marker
            break

        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        offset += 1

        if delta == 13:
            if offset >= len(payload):
                break
            delta = payload[offset] + 13
            offset += 1
        elif delta == 14:
            if offset + 1 >= len(payload):
                break
            delta = struct.unpack("!H", payload[offset : offset + 2])[0] + 269
            offset += 2
        elif delta == 15:
            break

        if length == 13:
            if offset >= len(payload):
                break
            length = payload[offset] + 13
            offset += 1
        elif length == 14:
            if offset + 1 >= len(payload):
                break
            length = struct.unpack("!H", payload[offset : offset + 2])[0] + 269
            offset += 2
        elif length == 15:
            break

        opt_number += delta
        opt_value = payload[offset : offset + length]
        offset += length

        if opt_number == 11:  # Uri-Path
            uri_parts.append(opt_value.decode("utf-8", errors="replace"))
        elif opt_number == 12:  # Content-Format
            if len(opt_value) == 1:
                fields["content_format"] = opt_value[0]
            elif len(opt_value) == 2:
                fields["content_format"] = struct.unpack("!H", opt_value)[0]

    if uri_parts:
        fields["uri_path"] = "/" + "/".join(uri_parts)


# ---------------------------------------------------------------------------
# MQTT (TCP port 1883 / 8883)
# ---------------------------------------------------------------------------

def parse_mqtt(packet) -> CapturedPacket | None:
    """Parse MQTT CONNECT and PUBLISH packets on TCP ports 1883/8883.

    Fixed header byte 0:
      Bits 7-4: Packet type (1=CONNECT, 3=PUBLISH)
      Bits 3-0: Flags
    """
    from scapy.all import IP, TCP

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    if tcp.dport not in (1883, 8883) and tcp.sport not in (1883, 8883):
        return None

    try:
        payload = bytes(tcp.payload)
    except Exception:
        return None

    if len(payload) < 2:
        return None

    pkt_type = (payload[0] >> 4) & 0x0F

    # Only handle CONNECT (1) and PUBLISH (3)
    if pkt_type not in (1, 3):
        return None

    # Decode remaining length (variable-length encoding)
    remaining_length, rl_bytes = _mqtt_decode_remaining_length(payload, 1)
    if remaining_length is None:
        return None

    body_start = 1 + rl_bytes
    body = payload[body_start:]

    fields: dict = {
        "message_type": "CONNECT" if pkt_type == 1 else "PUBLISH",
        "client_id": None,
        "topic": None,
    }

    if pkt_type == 1:
        _parse_mqtt_connect(body, fields)
    elif pkt_type == 3:
        _parse_mqtt_publish(body, fields)

    return CapturedPacket(
        protocol="mqtt",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _mqtt_decode_remaining_length(
    data: bytes, offset: int
) -> tuple[int | None, int]:
    """Decode MQTT variable-length integer. Returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    consumed = 0
    while offset < len(data):
        encoded_byte = data[offset]
        offset += 1
        consumed += 1
        value += (encoded_byte & 0x7F) * multiplier
        if (encoded_byte & 0x80) == 0:
            return value, consumed
        multiplier *= 128
        if consumed > 4:
            break
    return None, consumed


def _parse_mqtt_connect(body: bytes, fields: dict) -> None:
    """Extract client_id from an MQTT CONNECT variable header + payload."""
    # Variable header: Protocol Name (length-prefixed string) + Protocol Level
    # + Connect Flags + Keep Alive
    if len(body) < 10:
        return

    proto_name_len = struct.unpack("!H", body[0:2])[0]
    offset = 2 + proto_name_len  # skip protocol name
    if offset + 4 > len(body):
        return
    # Skip protocol level (1 byte), connect flags (1 byte), keep alive (2 bytes)
    offset += 4

    # Payload starts with Client ID (length-prefixed UTF-8 string)
    if offset + 2 > len(body):
        return
    client_id_len = struct.unpack("!H", body[offset : offset + 2])[0]
    offset += 2
    if offset + client_id_len > len(body):
        return
    fields["client_id"] = body[offset : offset + client_id_len].decode(
        "utf-8", errors="replace"
    )


def _parse_mqtt_publish(body: bytes, fields: dict) -> None:
    """Extract topic from an MQTT PUBLISH variable header."""
    if len(body) < 2:
        return
    topic_len = struct.unpack("!H", body[0:2])[0]
    if 2 + topic_len > len(body):
        return
    fields["topic"] = body[2 : 2 + topic_len].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# EtherNet/IP (TCP/UDP port 44818)
# ---------------------------------------------------------------------------

_ENIP_COMMANDS = {
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0065: "RegisterSession",
    0x0066: "UnRegisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
}


def parse_enip(packet) -> CapturedPacket | None:
    """Parse EtherNet/IP encapsulation header on port 44818.

    Header (24 bytes):
      0-1   Command
      2-3   Length of data portion
      4-7   Session Handle
      8-11  Status
      12-19 Sender Context
      20-23 Options
    """
    from scapy.all import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None

    sport = dport = None
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
    else:
        return None

    if sport != 44818 and dport != 44818:
        return None

    try:
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
        else:
            payload = bytes(packet[UDP].payload)
    except Exception:
        return None

    # Encapsulation header is 24 bytes minimum
    if len(payload) < 24:
        return None

    command = struct.unpack("<H", payload[0:2])[0]
    data_length = struct.unpack("<H", payload[2:4])[0]

    command_name = _ENIP_COMMANDS.get(command)
    if command_name is None:
        return None

    fields: dict = {
        "command": command_name,
        "product_name": None,
        "vendor_id": None,
        "device_type": None,
    }

    # For ListIdentity responses, try to extract identity info
    if command == 0x0063 and len(payload) > 24:
        _parse_enip_list_identity(payload[24:], fields)

    return CapturedPacket(
        protocol="enip",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _parse_enip_list_identity(data: bytes, fields: dict) -> None:
    """Extract identity fields from a ListIdentity response CPF.

    The response contains a count of items, each item having:
      Type ID (2), Length (2), then identity data.
    Identity data layout (after encapsulation version + socket addr):
      Vendor ID (2), Device Type (2), Product Code (2),
      Revision (2), Status (2), Serial (4),
      Product Name Length (1), Product Name (variable).
    """
    if len(data) < 2:
        return

    item_count = struct.unpack("<H", data[0:2])[0]
    if item_count < 1:
        return

    offset = 2
    if offset + 4 > len(data):
        return

    # type_id = struct.unpack("<H", data[offset : offset + 2])[0]
    item_length = struct.unpack("<H", data[offset + 2 : offset + 4])[0]
    offset += 4

    item_data = data[offset : offset + item_length]

    # Skip encapsulation protocol version (2) + socket address (16)
    id_offset = 18
    if id_offset + 14 > len(item_data):
        return

    fields["vendor_id"] = struct.unpack("<H", item_data[id_offset : id_offset + 2])[0]
    fields["device_type"] = struct.unpack(
        "<H", item_data[id_offset + 2 : id_offset + 4]
    )[0]

    # Skip product code (2), revision (2), status (2), serial (4)
    name_len_offset = id_offset + 14
    if name_len_offset >= len(item_data):
        return

    name_len = item_data[name_len_offset]
    name_start = name_len_offset + 1
    if name_start + name_len > len(item_data):
        return

    fields["product_name"] = item_data[name_start : name_start + name_len].decode(
        "utf-8", errors="replace"
    )
