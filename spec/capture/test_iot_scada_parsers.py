"""Tests for IoT/SCADA protocol parsers."""
from __future__ import annotations

import struct

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw

from leetha.capture.protocols.iot_scada import (
    parse_bacnet,
    parse_coap,
    parse_enip,
    parse_modbus,
    parse_mqtt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _udp_packet(sport: int, dport: int, payload: bytes) -> object:
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _tcp_packet(sport: int, dport: int, payload: bytes) -> object:
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=dport) / Raw(load=payload)


# ---------------------------------------------------------------------------
# Modbus TCP
# ---------------------------------------------------------------------------

class TestModbus:
    def _make_mbap(self, unit_id: int = 1, function_code: int = 3) -> bytes:
        """Build a minimal Modbus TCP frame: MBAP header + function code."""
        transaction_id = 0x0001
        protocol_id = 0x0000
        length = 2  # unit_id (1) + function_code (1)
        return struct.pack(
            "!HHHBB", transaction_id, protocol_id, length, unit_id, function_code
        )

    def test_valid_modbus_tcp(self):
        pkt = _tcp_packet(12345, 502, self._make_mbap(unit_id=5, function_code=6))
        result = parse_modbus(pkt)
        assert result is not None
        assert result.protocol == "modbus"
        assert result.fields["unit_id"] == 5
        assert result.fields["function_code"] == 6

    def test_valid_modbus_udp(self):
        pkt = _udp_packet(12345, 502, self._make_mbap(unit_id=10, function_code=1))
        result = parse_modbus(pkt)
        assert result is not None
        assert result.protocol == "modbus"
        assert result.fields["unit_id"] == 10

    def test_wrong_protocol_id_rejected(self):
        payload = struct.pack("!HHHBB", 1, 0x0001, 2, 1, 3)  # proto_id != 0
        pkt = _tcp_packet(12345, 502, payload)
        assert parse_modbus(pkt) is None

    def test_wrong_port_rejected(self):
        pkt = _tcp_packet(12345, 80, self._make_mbap())
        assert parse_modbus(pkt) is None

    def test_short_payload_rejected(self):
        pkt = _tcp_packet(12345, 502, b"\x00" * 5)
        assert parse_modbus(pkt) is None


# ---------------------------------------------------------------------------
# BACnet/IP
# ---------------------------------------------------------------------------

class TestBACnet:
    def _make_bvlc(self, bvlc_type: int = 0x81, function: int = 0x0A) -> bytes:
        length = 4
        return struct.pack("!BBH", bvlc_type, function, length)

    def test_valid_bacnet(self):
        pkt = _udp_packet(47808, 47808, self._make_bvlc())
        result = parse_bacnet(pkt)
        assert result is not None
        assert result.protocol == "bacnet"
        assert result.fields["bvlc_function"] == 0x0A

    def test_wrong_type_rejected(self):
        pkt = _udp_packet(47808, 47808, self._make_bvlc(bvlc_type=0x82))
        assert parse_bacnet(pkt) is None

    def test_wrong_port_rejected(self):
        pkt = _udp_packet(1234, 1234, self._make_bvlc())
        assert parse_bacnet(pkt) is None

    def test_short_payload_rejected(self):
        pkt = _udp_packet(47808, 47808, b"\x81")
        assert parse_bacnet(pkt) is None


# ---------------------------------------------------------------------------
# CoAP
# ---------------------------------------------------------------------------

class TestCoAP:
    def _make_coap(
        self, version: int = 1, msg_type: int = 0, code: int = 0x01,
        token: bytes = b"", options: bytes = b"",
    ) -> bytes:
        first_byte = ((version & 0x03) << 6) | ((msg_type & 0x03) << 4) | (len(token) & 0x0F)
        msg_id = 0x1234
        header = struct.pack("!BBH", first_byte, code, msg_id)
        return header + token + options

    def test_valid_coap(self):
        pkt = _udp_packet(12345, 5683, self._make_coap())
        result = parse_coap(pkt)
        assert result is not None
        assert result.protocol == "coap"
        assert result.fields["code"] == "0.01"

    def test_coap_with_uri_path(self):
        # Option: delta=11 (Uri-Path), length=4, value="test"
        opt = bytes([0xB4]) + b"test"
        pkt = _udp_packet(12345, 5683, self._make_coap(options=opt))
        result = parse_coap(pkt)
        assert result is not None
        assert result.fields["uri_path"] == "/test"

    def test_wrong_version_rejected(self):
        pkt = _udp_packet(12345, 5683, self._make_coap(version=0))
        assert parse_coap(pkt) is None

    def test_wrong_port_rejected(self):
        pkt = _udp_packet(12345, 80, self._make_coap())
        assert parse_coap(pkt) is None


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------

class TestMQTT:
    def _make_connect(self, client_id: str = "test-client") -> bytes:
        """Build a minimal MQTT CONNECT packet."""
        # Variable header
        proto_name = b"\x00\x04MQTT"
        proto_level = b"\x04"       # MQTT 3.1.1
        connect_flags = b"\x02"     # Clean Session
        keep_alive = b"\x00\x3C"    # 60 seconds

        # Payload: Client ID (length-prefixed)
        client_id_bytes = client_id.encode("utf-8")
        payload = struct.pack("!H", len(client_id_bytes)) + client_id_bytes

        var_header = proto_name + proto_level + connect_flags + keep_alive
        remaining = var_header + payload

        # Fixed header: type=1 (CONNECT), remaining length
        fixed = bytes([0x10, len(remaining)])
        return fixed + remaining

    def _make_publish(self, topic: str = "home/sensor") -> bytes:
        """Build a minimal MQTT PUBLISH packet."""
        topic_bytes = topic.encode("utf-8")
        var_header = struct.pack("!H", len(topic_bytes)) + topic_bytes
        payload = b"data"
        remaining = var_header + payload
        fixed = bytes([0x30, len(remaining)])
        return fixed + remaining

    def test_connect_extracts_client_id(self):
        pkt = _tcp_packet(12345, 1883, self._make_connect("my-iot-device"))
        result = parse_mqtt(pkt)
        assert result is not None
        assert result.protocol == "mqtt"
        assert result.fields["message_type"] == "CONNECT"
        assert result.fields["client_id"] == "my-iot-device"

    def test_publish_extracts_topic(self):
        pkt = _tcp_packet(12345, 1883, self._make_publish("sensors/temp"))
        result = parse_mqtt(pkt)
        assert result is not None
        assert result.fields["message_type"] == "PUBLISH"
        assert result.fields["topic"] == "sensors/temp"

    def test_port_8883(self):
        pkt = _tcp_packet(12345, 8883, self._make_connect())
        result = parse_mqtt(pkt)
        assert result is not None
        assert result.protocol == "mqtt"

    def test_wrong_port_rejected(self):
        pkt = _tcp_packet(12345, 80, self._make_connect())
        assert parse_mqtt(pkt) is None

    def test_unknown_type_rejected(self):
        # Type 0 is reserved
        payload = bytes([0x00, 0x00])
        pkt = _tcp_packet(12345, 1883, payload)
        assert parse_mqtt(pkt) is None


# ---------------------------------------------------------------------------
# EtherNet/IP
# ---------------------------------------------------------------------------

class TestEtherNetIP:
    def _make_enip_header(self, command: int = 0x0063, data: bytes = b"") -> bytes:
        """Build a 24-byte EtherNet/IP encapsulation header + data."""
        header = struct.pack(
            "<HHI I 8s I",
            command,
            len(data),       # length
            0,               # session handle
            0,               # status
            b"\x00" * 8,     # sender context
            0,               # options
        )
        return header + data

    def _make_list_identity_response(self) -> bytes:
        """Build a ListIdentity response with one identity item."""
        # Identity item data:
        # Encapsulation version (2) + socket address (16) = 18 bytes
        # Then: vendor_id(2) + device_type(2) + product_code(2) +
        #   revision(2) + status(2) + serial(4) + name_len(1) + name
        product_name = b"TestPLC"
        identity = (
            b"\x00" * 18                            # version + socket
            + struct.pack("<H", 42)                  # vendor_id
            + struct.pack("<H", 14)                  # device_type
            + struct.pack("<H", 1)                   # product_code
            + struct.pack("<H", 1)                   # revision
            + struct.pack("<H", 0)                   # status
            + struct.pack("<I", 12345)               # serial
            + bytes([len(product_name)])             # name_len
            + product_name
        )
        # CPF: item_count(2) + type_id(2) + item_length(2) + identity
        cpf = struct.pack("<HHH", 1, 0x000C, len(identity)) + identity
        return self._make_enip_header(command=0x0063, data=cpf)

    def test_list_identity_command(self):
        pkt = _tcp_packet(44818, 12345, self._make_enip_header(command=0x0063))
        result = parse_enip(pkt)
        assert result is not None
        assert result.protocol == "enip"
        assert result.fields["command"] == "ListIdentity"

    def test_list_identity_response_fields(self):
        pkt = _tcp_packet(44818, 12345, self._make_list_identity_response())
        result = parse_enip(pkt)
        assert result is not None
        assert result.fields["vendor_id"] == 42
        assert result.fields["device_type"] == 14
        assert result.fields["product_name"] == "TestPLC"

    def test_register_session(self):
        pkt = _tcp_packet(12345, 44818, self._make_enip_header(command=0x0065))
        result = parse_enip(pkt)
        assert result is not None
        assert result.fields["command"] == "RegisterSession"

    def test_udp_variant(self):
        pkt = _udp_packet(12345, 44818, self._make_enip_header(command=0x0063))
        result = parse_enip(pkt)
        assert result is not None

    def test_wrong_port_rejected(self):
        pkt = _tcp_packet(12345, 80, self._make_enip_header())
        assert parse_enip(pkt) is None

    def test_unknown_command_rejected(self):
        pkt = _tcp_packet(12345, 44818, self._make_enip_header(command=0xFFFF))
        assert parse_enip(pkt) is None

    def test_short_payload_rejected(self):
        pkt = _tcp_packet(12345, 44818, b"\x00" * 10)
        assert parse_enip(pkt) is None
