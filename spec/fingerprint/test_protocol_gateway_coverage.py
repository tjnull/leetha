"""Classification coverage for LoRa / Zigbee / Thread / Z-Wave gateways.

These devices tunnel low-power RF protocols into IP networks; they show up
on the LAN as Ethernet/Wi-Fi endpoints but the vendor + model string
distinguishes them from generic IoT hubs. The fingerprint engine now
recognises them via dedicated banner patterns:

  * ``lora_gateway`` — LoRaWAN base stations (Dragino, RAK, MultiTech,
    Kerlink, Tektelic, Laird, TTIG, Heltec, Seeed, MikroTik KNOT).
  * ``iot_hub``      — Zigbee / Thread / Z-Wave / Matter coordinators
    (Aqara, Hue Bridge, ConBee/Phoscon, SkyConnect, IKEA Tradfri,
    Home Assistant Yellow, Aeotec Z-Wave, Zooz).
"""

import re
import pytest


# LoRaWAN gateways

@pytest.mark.parametrize("model_string, expected_type", [
    # Dragino (very common open-source LoRa gateway line)
    ("Dragino LPS8",        "lora_gateway"),
    ("Dragino LPS8-N",      "lora_gateway"),
    ("Dragino LG308",       "lora_gateway"),
    ("Dragino LG308N",      "lora_gateway"),
    ("Dragino OLG01",       "lora_gateway"),
    ("Dragino DLOS8",       "lora_gateway"),
    ("Dragino MS14",        "lora_gateway"),
    # RAK Wireless WisGate
    ("RAK7240",             "lora_gateway"),
    ("RAK7244",             "lora_gateway"),
    ("RAK7258",             "lora_gateway"),
    ("RAK7271",             "lora_gateway"),
    ("RAK7289",             "lora_gateway"),
    ("WisGate Edge",        "lora_gateway"),
    ("WisGate Developer",   "lora_gateway"),
    # The Things Industries
    ("The Things Indoor Gateway", "lora_gateway"),
    ("TTIG",                "lora_gateway"),
    # MultiTech Conduit
    ("MultiTech MTCDT",     "lora_gateway"),
    ("MTCDT-LAT3",          "lora_gateway"),
    ("Conduit AEP",         "lora_gateway"),
    # Kerlink
    ("Kerlink Wirnet iFemtoCell",  "lora_gateway"),
    ("Wirnet iStation",            "lora_gateway"),
    ("Wirnet iBTS",                "lora_gateway"),
    # Tektelic Kona
    ("Kona Micro Lite",     "lora_gateway"),
    ("Kona Mega",           "lora_gateway"),
    ("Kona Enterprise",     "lora_gateway"),
    ("Tektelic Kona",       "lora_gateway"),
    # Laird Sentrius
    ("Sentrius RG1xx",      "lora_gateway"),
    ("Sentrius RG191",      "lora_gateway"),
    # Heltec
    ("Heltec HT-M01",       "lora_gateway"),
    ("Heltec HT-M02",       "lora_gateway"),
    # Seeed LoRa
    ("Seeed SenseCAP M2",   "lora_gateway"),
    ("Seeedstudio LoRa Gateway", "lora_gateway"),
    # ResIOT / Pygate / Mikrotik KNOT (already routed — kept for coverage)
    ("Pygate",              "lora_gateway"),
])
def test_lora_gateway_classification(model_string, expected_type):
    from leetha.patterns.vendors import LORA_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in LORA_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


# Zigbee / Thread / Z-Wave / Matter coordinators

@pytest.mark.parametrize("model_string, expected_type", [
    # Aqara (Zigbee 3.0 hubs, some are Thread border routers too)
    ("Aqara Hub M1S",        "iot_hub"),
    ("Aqara Hub M2",         "iot_hub"),
    ("Aqara Hub E1",         "iot_hub"),
    ("Aqara G3 Camera Hub",  "iot_hub"),
    # ConBee II / RaspBee / Phoscon (Zigbee via Home Assistant deCONZ)
    ("ConBee II",            "iot_hub"),
    ("ConBee III",           "iot_hub"),
    ("RaspBee II",           "iot_hub"),
    ("Phoscon",              "iot_hub"),
    # Nabu Casa / Home Assistant Yellow + SkyConnect / Connect ZBT-1
    ("Home Assistant Yellow",  "iot_hub"),
    ("Home Assistant SkyConnect", "iot_hub"),
    ("SkyConnect",           "iot_hub"),
    ("Connect ZBT-1",        "iot_hub"),
    # IKEA Tradfri / Dirigera (Matter/Thread successor)
    ("IKEA Tradfri Gateway", "iot_hub"),
    ("Tradfri Gateway",      "iot_hub"),
    ("IKEA Dirigera",        "iot_hub"),
    ("Dirigera",             "iot_hub"),
    # Z-Wave controllers
    ("Aeotec Smart Home Hub",  "iot_hub"),
    ("Aeotec Z-Stick 7",       "iot_hub"),
    ("Zooz ZST10",             "iot_hub"),
    ("Zooz ZST39",             "iot_hub"),
    ("HomeSeer SmartStick+",   "iot_hub"),
    # Silicon Labs reference sticks commonly used by DIY hubs
    ("Silicon Labs UZB-7",     "iot_hub"),
])
def test_zigbee_thread_zwave_classification(model_string, expected_type):
    from leetha.patterns.vendors import IOT_HUB_BANNER_PATTERNS
    matched = None
    for pattern, _name, device_type, _os in IOT_HUB_BANNER_PATTERNS:
        if re.search(pattern, model_string, re.IGNORECASE):
            matched = device_type
            break
    assert matched == expected_type, (
        f"{model_string!r} classified as {matched!r}, expected {expected_type!r}"
    )


# Hostname-based classification for common LoRa/Zigbee gateways

@pytest.mark.parametrize("hostname, expected", [
    # LoRa gateway hostnames
    ("dragino-lps8-field1",  "lora_gateway"),
    ("rak7258-gw",           "lora_gateway"),
    ("ttig-office",          "lora_gateway"),
    ("lorawan-gw-01",        "lora_gateway"),
    ("kerlink-wirnet",       "lora_gateway"),
    # Zigbee/Thread hub hostnames
    ("aqara-hub-m2",         "iot_hub"),
    ("conbee2",              "iot_hub"),
    ("skyconnect-usb",       "iot_hub"),
    ("tradfri-gateway",      "iot_hub"),
    ("dirigera",             "iot_hub"),
    ("hassio-yellow",        "iot_hub"),
    # Z-Wave
    ("zwave-stick",          "iot_hub"),
    ("aeotec-hub",           "iot_hub"),
])
def test_protocol_gateway_hostname_classification(hostname, expected):
    from leetha.topology import _HOSTNAME_DEVICE_HINTS
    hn_lower = hostname.lower()
    inferred = None
    for pattern, kind in _HOSTNAME_DEVICE_HINTS:
        if pattern in hn_lower:
            inferred = kind
            break
    assert inferred == expected, (
        f"hostname {hostname!r} classified as {inferred!r}, expected {expected!r}"
    )
