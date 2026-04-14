"""IoT/SCADA processor -- Modbus, BACnet, CoAP, MQTT, EtherNet/IP."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


_MQTT_CLIENT_PATTERNS: list[tuple[str, str | None, str]] = [
    ("tasmota", "Tasmota", "iot_device"),
    ("shelly", "Shelly", "iot_device"),
    ("sonoff", "Sonoff", "iot_device"),
    ("homebridge", "Homebridge", "smart_home"),
    ("zigbee2mqtt", None, "smart_home"),
    ("node-red", "Node-RED", "smart_home"),
    ("homeassistant", "Home Assistant", "smart_home"),
    ("hass", "Home Assistant", "smart_home"),
    ("esphome", "ESPHome", "iot_device"),
]


@register_processor("modbus", "bacnet", "coap", "mqtt", "enip", "dnp3", "s7comm", "opcua", "goose", "profinet", "umas")
class IotScadaProcessor(Processor):
    """Handles ICS/SCADA and IoT protocols.

    Passive observation of these protocols provides presence detection
    and basic device categorization.
    """

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "modbus":
            return self._analyze_modbus(packet)
        elif protocol == "bacnet":
            return self._analyze_bacnet(packet)
        elif protocol == "coap":
            return self._analyze_coap(packet)
        elif protocol == "mqtt":
            return self._analyze_mqtt(packet)
        elif protocol == "enip":
            return self._analyze_enip(packet)
        elif protocol == "dnp3":
            return self._analyze_dnp3(packet)
        elif protocol == "s7comm":
            return self._analyze_s7comm(packet)
        elif protocol == "opcua":
            return self._analyze_opcua(packet)
        elif protocol == "goose":
            return self._analyze_goose(packet)
        elif protocol == "profinet":
            return self._analyze_profinet(packet)
        elif protocol == "umas":
            return self._analyze_umas(packet)
        return []

    def _analyze_modbus(self, packet: CapturedPacket) -> list[Evidence]:
        unit_id = packet.get("unit_id")
        function_code = packet.get("function_code")
        return [Evidence(
            source="modbus", method="heuristic", certainty=0.60,
            category="ics_device",
            raw={"unit_id": unit_id, "function_code": function_code},
        )]

    def _analyze_bacnet(self, packet: CapturedPacket) -> list[Evidence]:
        vendor_id = packet.get("vendor_id")
        object_name = packet.get("object_name")
        model_name = packet.get("model_name")
        return [Evidence(
            source="bacnet", method="heuristic", certainty=0.65,
            category="building_automation",
            model=model_name,
            raw={"vendor_id": vendor_id, "object_name": object_name,
                 "model_name": model_name},
        )]

    def _analyze_coap(self, packet: CapturedPacket) -> list[Evidence]:
        uri_path = packet.get("uri_path")
        content_format = packet.get("content_format")
        return [Evidence(
            source="coap", method="heuristic", certainty=0.50,
            category="iot_device",
            raw={"uri_path": uri_path, "content_format": content_format},
        )]

    def _analyze_mqtt(self, packet: CapturedPacket) -> list[Evidence]:
        evidence: list[Evidence] = []
        client_id = packet.get("client_id", "")
        topic = packet.get("topic")

        # Baseline evidence for any MQTT traffic
        evidence.append(Evidence(
            source="mqtt", method="heuristic", certainty=0.55,
            category="iot_device",
            raw={"client_id": client_id, "topic": topic},
        ))

        # Pattern-match client_id to known IoT/smart-home prefixes
        if client_id:
            cid_lower = client_id.lower()
            for prefix, vendor, category in _MQTT_CLIENT_PATTERNS:
                if cid_lower.startswith(prefix):
                    evidence.append(Evidence(
                        source="mqtt",
                        method="pattern",
                        certainty=0.75,
                        vendor=vendor,
                        category=category,
                        raw={"client_id": client_id},
                    ))
                    break

        return evidence

    def _analyze_enip(self, packet: CapturedPacket) -> list[Evidence]:
        product_name = packet.get("product_name")
        vendor_id = packet.get("vendor_id")
        device_type = packet.get("device_type")
        return [Evidence(
            source="enip", method="heuristic", certainty=0.65,
            category="ics_device",
            model=product_name,
            raw={"product_name": product_name, "vendor_id": vendor_id,
                 "device_type": device_type},
        )]

    def _analyze_dnp3(self, packet: CapturedPacket) -> list[Evidence]:
        """DNP3 — SCADA RTU/outstation identification.

        is_server means "TCP listener" (the outstation/RTU in DNP3 terms).
        The DNP3 master (SCADA server) is the TCP client that initiates connections.
        So: is_server=True → RTU/outstation, is_server=False → SCADA master.
        """
        func_name = packet.get("func_name", "")
        is_server = packet.get("is_server", False)
        category = "rtu" if is_server else "scada_server"
        return [Evidence(
            source="dnp3", method="exact", certainty=0.75,
            category=category,
            raw={"func": func_name, "src_addr": packet.get("src_addr"),
                 "dst_addr": packet.get("dst_addr")},
        )]

    def _analyze_s7comm(self, packet: CapturedPacket) -> list[Evidence]:
        """S7comm — Siemens PLC identification."""
        s7_pdu_name = packet.get("s7_pdu_name")
        s7_function_name = packet.get("s7_function_name")
        is_server = packet.get("is_server", False)
        evidence = [Evidence(
            source="s7comm", method="exact", certainty=0.80,
            vendor="Siemens",
            category="plc" if is_server else "scada_server",
            raw={"pdu": s7_pdu_name, "function": s7_function_name},
        )]
        return evidence

    def _analyze_opcua(self, packet: CapturedPacket) -> list[Evidence]:
        """OPC UA — industrial server/client.

        Non-server OPC UA nodes could be HMIs, historians, engineering
        workstations, or MES systems. Use generic "opcua_client" at reduced
        certainty rather than assuming HMI.
        """
        msg_type = packet.get("msg_type", "")
        type_name = packet.get("type_name", "")
        is_server = packet.get("is_server", False)
        endpoint_url = packet.get("endpoint_url")
        if is_server:
            category = "scada_server"
            certainty = 0.75
        else:
            category = "opcua_client"
            certainty = 0.50
        evidence = [Evidence(
            source="opcua", method="exact", certainty=certainty,
            category=category,
            raw={"msg_type": msg_type, "type_name": type_name,
                 "endpoint_url": endpoint_url},
        )]
        return evidence

    def _analyze_goose(self, packet: CapturedPacket) -> list[Evidence]:
        """IEC 61850 GOOSE — substation automation device."""
        gocb_ref = packet.get("gocb_ref")
        go_id = packet.get("go_id")
        evidence = [Evidence(
            source="goose", method="exact", certainty=0.85,
            category="ics_device",
            raw={"gocb_ref": gocb_ref, "go_id": go_id,
                 "appid": packet.get("appid")},
        )]
        # Extract hostname from goID if present
        if go_id:
            evidence[0].hostname = go_id
        return evidence

    def _analyze_profinet(self, packet: CapturedPacket) -> list[Evidence]:
        """PROFINET — industrial Ethernet device."""
        frame_type = packet.get("frame_type", "")
        vendor_name = packet.get("vendor_name")
        station_name = packet.get("station_name")
        device_role = packet.get("device_role", [])

        category = "plc"
        if "io_controller" in device_role:
            category = "plc"
        elif "io_device" in device_role:
            category = "ics_device"
        elif "io_supervisor" in device_role:
            category = "hmi"

        evidence = [Evidence(
            source="profinet", method="exact", certainty=0.80,
            vendor=vendor_name,
            category=category,
            raw={"frame_type": frame_type, "station_name": station_name,
                 "device_role": device_role},
        )]
        if station_name:
            evidence[0].hostname = station_name
        return evidence

    def _analyze_umas(self, packet: CapturedPacket) -> list[Evidence]:
        """UMAS — Schneider Electric PLC identification."""
        umas_function = packet.get("umas_function", "")
        project_name = packet.get("project_name")
        is_server = packet.get("is_server", False)
        evidence = [Evidence(
            source="umas", method="exact", certainty=0.85,
            vendor="Schneider Electric",
            category="plc" if is_server else "scada_server",
            platform="Unity",
            raw={"function": umas_function, "project_name": project_name},
        )]
        if project_name:
            evidence[0].hostname = project_name
        return evidence
